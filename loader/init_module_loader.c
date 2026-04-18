#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#if defined(__linux__)
#include <elf.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <module.ko> [module_params]\n", prog);
}

static int read_file(const char *path, void **buf, size_t *len)
{
	int fd;
	struct stat st;
	ssize_t rd;
	size_t off = 0;
	char *mem;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return -1;
	}
	if (st.st_size <= 0) {
		close(fd);
		errno = EINVAL;
		return -1;
	}

	mem = malloc((size_t)st.st_size);
	if (!mem) {
		close(fd);
		errno = ENOMEM;
		return -1;
	}

	while (off < (size_t)st.st_size) {
		rd = read(fd, mem + off, (size_t)st.st_size - off);
		if (rd < 0) {
			if (errno == EINTR)
				continue;
			free(mem);
			close(fd);
			return -1;
		}
		if (rd == 0)
			break;
		off += (size_t)rd;
	}

	close(fd);
	*buf = mem;
	*len = off;
	return 0;
}

#if defined(__linux__)
struct ksym {
	char *name;
	unsigned long long addr;
};

struct ksym_table {
	struct ksym *items;
	size_t count;
	size_t nonzero_count;
};

static int ksym_cmp(const void *a, const void *b)
{
	const struct ksym *ka = a;
	const struct ksym *kb = b;
	return strcmp(ka->name, kb->name);
}

static void free_kallsyms(struct ksym_table *tbl)
{
	size_t i;

	if (!tbl || !tbl->items)
		return;
	for (i = 0; i < tbl->count; ++i)
		free(tbl->items[i].name);
	free(tbl->items);
	tbl->items = NULL;
	tbl->count = 0;
	tbl->nonzero_count = 0;
}

static int parse_kallsyms(struct ksym_table *tbl)
{
	FILE *fp;
	char *line = NULL;
	size_t line_cap = 0;
	struct ksym *items = NULL;
	size_t count = 0;
	size_t cap_items = 0;

	fp = fopen("/proc/kallsyms", "re");
	if (!fp)
		return -1;

	while (getline(&line, &line_cap, fp) > 0) {
		unsigned long long addr = 0;
		char type = '\0';
		char name[512];
		struct ksym *next;

		if (sscanf(line, "%llx %c %511s", &addr, &type, name) != 3)
			continue;

		if (count == cap_items) {
			size_t new_cap = cap_items ? cap_items * 2 : 4096;
			next = realloc(items, new_cap * sizeof(*items));
			if (!next) {
				errno = ENOMEM;
				free(line);
				fclose(fp);
				free_kallsyms(&(struct ksym_table){ .items = items, .count = count });
				return -1;
			}
			items = next;
			cap_items = new_cap;
		}

		items[count].name = strdup(name);
		if (!items[count].name) {
			errno = ENOMEM;
			free(line);
			fclose(fp);
			free_kallsyms(&(struct ksym_table){ .items = items, .count = count });
			return -1;
		}
		items[count].addr = addr;
		if (addr != 0)
			tbl->nonzero_count++;
		++count;
	}

	free(line);
	fclose(fp);

	if (count == 0) {
		free(items);
		errno = ENOENT;
		return -1;
	}

	qsort(items, count, sizeof(*items), ksym_cmp);
	tbl->items = items;
	tbl->count = count;
	return 0;
}

static int read_int_from_file(const char *path, int *out)
{
	FILE *fp;
	int v;

	fp = fopen(path, "re");
	if (!fp)
		return -1;

	if (fscanf(fp, "%d", &v) != 1) {
		fclose(fp);
		errno = EINVAL;
		return -1;
	}

	fclose(fp);
	*out = v;
	return 0;
}

static int write_int_to_file(const char *path, int value)
{
	FILE *fp;

	fp = fopen(path, "we");
	if (!fp)
		return -1;

	if (fprintf(fp, "%d\n", value) < 0) {
		fclose(fp);
		return -1;
	}

	if (fclose(fp) != 0)
		return -1;
	return 0;
}

static int lookup_kallsyms(const struct ksym_table *tbl, const char *symbol,
			   unsigned long long *addr_out)
{
	size_t lo = 0;
	size_t hi = tbl->count;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		int c = strcmp(symbol, tbl->items[mid].name);

		if (c == 0) {
			*addr_out = tbl->items[mid].addr;
			return 0;
		}
		if (c < 0)
			hi = mid;
		else
			lo = mid + 1;
	}

	errno = ENOENT;
	return -1;
}

static int valid_range(size_t off, size_t sz, size_t total)
{
	if (off > total)
		return 0;
	if (sz > total - off)
		return 0;
	return 1;
}

static int patch_elf64(void *buf, size_t len, const struct ksym_table *tbl,
		       size_t *patched, size_t *missing)
{
	Elf64_Ehdr *eh = buf;
	size_t i;

	if (!valid_range(eh->e_shoff, (size_t)eh->e_shnum * eh->e_shentsize, len))
		return -1;
	if (eh->e_shentsize != sizeof(Elf64_Shdr))
		return -1;

	Elf64_Shdr *shdrs = (Elf64_Shdr *)((char *)buf + eh->e_shoff);

	for (i = 0; i < eh->e_shnum; ++i) {
		size_t n;
		Elf64_Shdr *symtab = &shdrs[i];
		Elf64_Shdr *strtab;
		Elf64_Sym *syms;
		const char *strs;

		if (symtab->sh_type != SHT_SYMTAB)
			continue;
		if (symtab->sh_entsize != sizeof(Elf64_Sym) || symtab->sh_entsize == 0)
			continue;
		if (symtab->sh_link >= eh->e_shnum)
			continue;
		if (!valid_range(symtab->sh_offset, symtab->sh_size, len))
			continue;

		strtab = &shdrs[symtab->sh_link];
		if (!valid_range(strtab->sh_offset, strtab->sh_size, len))
			continue;

		syms = (Elf64_Sym *)((char *)buf + symtab->sh_offset);
		strs = (const char *)buf + strtab->sh_offset;
		n = symtab->sh_size / symtab->sh_entsize;

		for (size_t idx = 1; idx < n; ++idx) {
			unsigned long long addr = 0;
			const char *name;

			if (syms[idx].st_shndx != SHN_UNDEF)
				continue;
			if (syms[idx].st_name >= strtab->sh_size)
				continue;
			name = strs + syms[idx].st_name;
			if (*name == '\0')
				continue;

			if (lookup_kallsyms(tbl, name, &addr) < 0 || addr == 0) {
				++(*missing);
				fprintf(stderr, "warn: cannot find symbol: %s\n", name);
				continue;
			}

			syms[idx].st_shndx = SHN_ABS;
			syms[idx].st_value = addr;
			++(*patched);
		}
	}
	return 0;
}

static int patch_elf32(void *buf, size_t len, const struct ksym_table *tbl,
		       size_t *patched, size_t *missing)
{
	Elf32_Ehdr *eh = buf;
	size_t i;

	if (!valid_range(eh->e_shoff, (size_t)eh->e_shnum * eh->e_shentsize, len))
		return -1;
	if (eh->e_shentsize != sizeof(Elf32_Shdr))
		return -1;

	Elf32_Shdr *shdrs = (Elf32_Shdr *)((char *)buf + eh->e_shoff);

	for (i = 0; i < eh->e_shnum; ++i) {
		size_t n;
		Elf32_Shdr *symtab = &shdrs[i];
		Elf32_Shdr *strtab;
		Elf32_Sym *syms;
		const char *strs;

		if (symtab->sh_type != SHT_SYMTAB)
			continue;
		if (symtab->sh_entsize != sizeof(Elf32_Sym) || symtab->sh_entsize == 0)
			continue;
		if (symtab->sh_link >= eh->e_shnum)
			continue;
		if (!valid_range(symtab->sh_offset, symtab->sh_size, len))
			continue;

		strtab = &shdrs[symtab->sh_link];
		if (!valid_range(strtab->sh_offset, strtab->sh_size, len))
			continue;

		syms = (Elf32_Sym *)((char *)buf + symtab->sh_offset);
		strs = (const char *)buf + strtab->sh_offset;
		n = symtab->sh_size / symtab->sh_entsize;

		for (size_t idx = 1; idx < n; ++idx) {
			unsigned long long addr = 0;
			const char *name;

			if (syms[idx].st_shndx != SHN_UNDEF)
				continue;
			if (syms[idx].st_name >= strtab->sh_size)
				continue;
			name = strs + syms[idx].st_name;
			if (*name == '\0')
				continue;

			if (lookup_kallsyms(tbl, name, &addr) < 0 || addr == 0) {
				++(*missing);
				fprintf(stderr, "warn: cannot find symbol: %s\n", name);
				continue;
			}

			syms[idx].st_shndx = SHN_ABS;
			syms[idx].st_value = (Elf32_Addr)addr;
			++(*patched);
		}
	}
	return 0;
}

static int relocate_undef_symbols(void *buf, size_t len, const struct ksym_table *tbl,
				  size_t *patched, size_t *missing)
{
	unsigned char *ident = buf;

	if (!valid_range(0, EI_NIDENT, len))
		return -1;
	if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 ||
	    ident[EI_MAG2] != ELFMAG2 || ident[EI_MAG3] != ELFMAG3)
		return -1;
	if (ident[EI_DATA] != ELFDATA2LSB)
		return -1;

	if (ident[EI_CLASS] == ELFCLASS64)
		return patch_elf64(buf, len, tbl, patched, missing);
	if (ident[EI_CLASS] == ELFCLASS32)
		return patch_elf32(buf, len, tbl, patched, missing);

	errno = ENOTSUP;
	return -1;
}

static char *build_module_params(const char *user_params)
{
	const char *allow = "allow_shell=1";
	int has_allow = (access("/ksu_allow_shell", F_OK) == 0);
	size_t user_len = user_params ? strlen(user_params) : 0;
	size_t need = 1;
	char *out;

	if (has_allow)
		need += strlen(allow);
	if (user_len)
		need += user_len + (has_allow ? 1 : 0);

	out = malloc(need);
	if (!out)
		return NULL;

	out[0] = '\0';
	if (has_allow)
		strcat(out, allow);
	if (user_len) {
		if (has_allow)
			strcat(out, " ");
		strcat(out, user_params);
	}
	return out;
}
#endif

int main(int argc, char **argv)
{
	const char *ko_path;
	const char *params_raw = "";
	void *image = NULL;
	size_t image_len = 0;
#if defined(__linux__)
	struct ksym_table table = {0};
	size_t patched = 0;
	size_t missing = 0;
	char *params = NULL;
#endif

	if (argc < 2 || argc > 3) {
		usage(argv[0]);
		return 2;
	}

	ko_path = argv[1];
	if (argc == 3)
		params_raw = argv[2];

	if (read_file(ko_path, &image, &image_len) < 0) {
		fprintf(stderr, "read %s failed: %s\n", ko_path, strerror(errno));
		return 1;
	}

#if defined(__linux__)
	if (write_int_to_file("/proc/sys/kernel/kptr_restrict", 1) < 0) {
		fprintf(stderr, "note: set /proc/sys/kernel/kptr_restrict=1 failed: %s\n",
			strerror(errno));
	}

	if (parse_kallsyms(&table) < 0) {
		fprintf(stderr, "parse /proc/kallsyms failed: %s\n", strerror(errno));
		free(image);
		return 1;
	}

	{
		int kptr_restrict = -1;
		if (read_int_from_file("/proc/sys/kernel/kptr_restrict", &kptr_restrict) == 0 &&
		    kptr_restrict > 0) {
			fprintf(stderr,
				"note: /proc/sys/kernel/kptr_restrict=%d, kallsyms may hide addresses\n",
				kptr_restrict);
		}
	}

	if (table.nonzero_count == 0) {
		fprintf(stderr, "kallsyms addresses are all zero, skip relocation and load module directly\n");
	} else {
		if (relocate_undef_symbols(image, image_len, &table, &patched, &missing) < 0) {
			fprintf(stderr, "relocate undefined symbols failed: %s\n", strerror(errno));
			free(image);
			free_kallsyms(&table);
			return 1;
		}
		fprintf(stderr, "relocation done: patched=%zu missing=%zu\n", patched, missing);
	}

	params = build_module_params(params_raw);
	if (!params) {
		fprintf(stderr, "alloc module params failed: %s\n", strerror(errno));
		free(image);
		free_kallsyms(&table);
		return 1;
	}

#ifndef __NR_init_module
#ifdef SYS_init_module
#define __NR_init_module SYS_init_module
#endif
#endif
#ifndef __NR_init_module
	fprintf(stderr, "init_module syscall number is unavailable on this libc/arch\n");
	free(image);
	free(params);
	free_kallsyms(&table);
	return 1;
#endif
	long ret = syscall(__NR_init_module, image, image_len, params);
	if (ret < 0) {
		fprintf(stderr, "init_module(%s) failed: %s\n", ko_path, strerror(errno));
		free(image);
		free(params);
		free_kallsyms(&table);
		return 1;
	}
	printf("init_module loaded: %s (size=%zu, params=\"%s\")\n", ko_path, image_len, params);
	free(params);
	free_kallsyms(&table);
#else
	(void)params_raw;
	fprintf(stderr, "init_module loader only works on Linux\n");
	free(image);
	return 1;
#endif

	free(image);
	return 0;
}
