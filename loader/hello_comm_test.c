#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MAGIC_KEY 0x53454c58UL

#define PR_WXSHADOW_SET_BP       0x57580001UL
#define PR_WXSHADOW_SET_REG      0x57580002UL
#define PR_WXSHADOW_DEL_BP       0x57580003UL
#define PR_WXSHADOW_SET_TLB_MODE 0x57580004UL
#define PR_WXSHADOW_GET_TLB_MODE 0x57580005UL
#define PR_WXSHADOW_PATCH        0x57580006UL
#define PR_WXSHADOW_RELEASE      0x57580008UL

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s <cmd> [arg2] [arg3] [arg4] [arg5]\n"
            "  %s set-enforcing\n"
            "  %s set-permissive\n"
            "  %s set-bp -p <pid> -a <addr>\n"
            "  %s set-reg -p <pid> -a <addr> -r <reg_idx> -v <value>\n"
            "  %s del-bp -p <pid> [-a <addr>]\n"
            "  %s patch -p <pid> -a <addr> --hex <hexbytes>\n"
            "  %s release -p <pid> [-a <addr>]\n"
            "  %s set-tlb -m <mode>\n"
            "  %s get-tlb\n",
            prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

static bool is_number_arg(const char *s)
{
    if (!s || !*s)
        return false;

    if (s[0] == '-' || s[0] == '+')
        s++;

    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        if (!*s)
            return false;
        while (*s) {
            if (!isxdigit((unsigned char)*s))
                return false;
            s++;
        }
        return true;
    }

    while (*s) {
        if (!isdigit((unsigned char)*s))
            return false;
        s++;
    }
    return true;
}

static unsigned long parse_ul(const char *s, const char *name)
{
    char *end = NULL;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 0);
    if (errno || !end || *end != '\0') {
        fprintf(stderr, "Invalid %s: %s\n", name, s);
        exit(2);
    }

    return v;
}

static long do_membarrier(unsigned long cmd, unsigned long arg2,
                          unsigned long arg3, unsigned long arg4,
                          unsigned long arg5)
{
#if defined(__linux__)
    long ret;
#ifndef __NR_membarrier
#ifdef SYS_membarrier
#define __NR_membarrier SYS_membarrier
#endif
#endif
#ifndef __NR_membarrier
    fprintf(stderr, "membarrier syscall number is unavailable on this libc/arch\n");
    return -1;
#endif

    errno = 0;
    ret = syscall(__NR_membarrier, MAGIC_KEY, cmd, arg2, arg3, arg4, arg5);
    fprintf(stderr,
            "membarrier sent: key=0x%lx cmd=0x%lx a2=0x%lx a3=0x%lx a4=0x%lx a5=0x%lx ret=%ld errno=%d(%s)\n",
            MAGIC_KEY, cmd, arg2, arg3, arg4, arg5, ret, errno,
            strerror(errno));
    return ret;
#else
    (void)cmd;
    (void)arg2;
    (void)arg3;
    (void)arg4;
    (void)arg5;
    fprintf(stderr, "hello_comm_test only works on Linux/Android\n");
    return -1;
#endif
}

static int parse_opt_value(int argc, char **argv, int *idx,
                           const char *opt, unsigned long *out)
{
    if (strcmp(argv[*idx], opt) != 0)
        return 0;
    if (*idx + 1 >= argc) {
        fprintf(stderr, "Missing value for %s\n", opt);
        return -1;
    }
    *out = parse_ul(argv[*idx + 1], opt);
    *idx += 2;
    return 1;
}

static int hex_to_bytes(const char *hex, unsigned char **out, unsigned long *out_len)
{
    size_t len;
    size_t i;
    unsigned char *buf;

    if (!hex || !out || !out_len)
        return -1;

    len = strlen(hex);
    if (len == 0 || (len % 2) != 0)
        return -1;

    buf = malloc(len / 2);
    if (!buf)
        return -1;

    for (i = 0; i < len; i += 2) {
        char tmp[3] = { hex[i], hex[i + 1], '\0' };
        char *end = NULL;
        unsigned long v = strtoul(tmp, &end, 16);
        if (!end || *end != '\0') {
            free(buf);
            return -1;
        }
        buf[i / 2] = (unsigned char)v;
    }

    *out = buf;
    *out_len = (unsigned long)(len / 2);
    return 0;
}

int main(int argc, char **argv)
{
    unsigned long cmd = 0;
    unsigned long arg2 = 0;
    unsigned long arg3 = 0;
    unsigned long arg4 = 0;
    unsigned long arg5 = 0;
    const char *sub;

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    if (is_number_arg(argv[1])) {
        if (argc > 7) {
            usage(argv[0]);
            return 2;
        }
        cmd = parse_ul(argv[1], "cmd");
        if (argc >= 3)
            arg2 = parse_ul(argv[2], "arg2");
        if (argc >= 4)
            arg3 = parse_ul(argv[3], "arg3");
        if (argc >= 5)
            arg4 = parse_ul(argv[4], "arg4");
        if (argc >= 6)
            arg5 = parse_ul(argv[5], "arg5");
        (void)do_membarrier(cmd, arg2, arg3, arg4, arg5);
        return 0;
    }

    sub = argv[1];
    if (strcmp(sub, "set-enforcing") == 0) {
        (void)do_membarrier(1, 0, 0, 0, 0);
        return 0;
    }
    if (strcmp(sub, "set-permissive") == 0) {
        (void)do_membarrier(0, 0, 0, 0, 0);
        return 0;
    }

    if (strcmp(sub, "get-tlb") == 0) {
        (void)do_membarrier(PR_WXSHADOW_GET_TLB_MODE, 0, 0, 0, 0);
        return 0;
    }

    if (strcmp(sub, "set-bp") == 0) {
        int i = 2;
        while (i < argc) {
            int r;
            r = parse_opt_value(argc, argv, &i, "-p", &arg2);
            if (r < 0)
                return 2;
            if (r > 0)
                continue;
            r = parse_opt_value(argc, argv, &i, "-a", &arg3);
            if (r < 0)
                return 2;
            if (r > 0)
                continue;
            usage(argv[0]);
            return 2;
        }
        (void)do_membarrier(PR_WXSHADOW_SET_BP, arg2, arg3, 0, 0);
        return 0;
    }

    if (strcmp(sub, "set-reg") == 0) {
        int i = 2;
        while (i < argc) {
            int r;
            r = parse_opt_value(argc, argv, &i, "-p", &arg2);
            if (r < 0)
                return 2;
            if (r > 0)
                continue;
            r = parse_opt_value(argc, argv, &i, "-a", &arg3);
            if (r < 0)
                return 2;
            if (r > 0)
                continue;
            r = parse_opt_value(argc, argv, &i, "-r", &arg4);
            if (r < 0)
                return 2;
            if (r > 0)
                continue;
            r = parse_opt_value(argc, argv, &i, "-v", &arg5);
            if (r < 0)
                return 2;
            if (r > 0)
                continue;
            usage(argv[0]);
            return 2;
        }
        (void)do_membarrier(PR_WXSHADOW_SET_REG, arg2, arg3, arg4, arg5);
        return 0;
    }

    if (strcmp(sub, "del-bp") == 0) {
        int i = 2;
        while (i < argc) {
            int r;
            r = parse_opt_value(argc, argv, &i, "-p", &arg2);
            if (r < 0)
                return 2;
            if (r > 0)
                continue;
            r = parse_opt_value(argc, argv, &i, "-a", &arg3);
            if (r < 0)
                return 2;
            if (r > 0)
                continue;
            usage(argv[0]);
            return 2;
        }
        (void)do_membarrier(PR_WXSHADOW_DEL_BP, arg2, arg3, 0, 0);
        return 0;
    }

    if (strcmp(sub, "release") == 0) {
        int i = 2;
        while (i < argc) {
            int r;
            r = parse_opt_value(argc, argv, &i, "-p", &arg2);
            if (r < 0)
                return 2;
            if (r > 0)
                continue;
            r = parse_opt_value(argc, argv, &i, "-a", &arg3);
            if (r < 0)
                return 2;
            if (r > 0)
                continue;
            usage(argv[0]);
            return 2;
        }
        (void)do_membarrier(PR_WXSHADOW_RELEASE, arg2, arg3, 0, 0);
        return 0;
    }

    if (strcmp(sub, "set-tlb") == 0) {
        int i = 2;
        while (i < argc) {
            int r = parse_opt_value(argc, argv, &i, "-m", &arg2);
            if (r < 0)
                return 2;
            if (r > 0)
                continue;
            usage(argv[0]);
            return 2;
        }
        (void)do_membarrier(PR_WXSHADOW_SET_TLB_MODE, arg2, 0, 0, 0);
        return 0;
    }

    if (strcmp(sub, "patch") == 0) {
        int i = 2;
        const char *hex = NULL;
        unsigned char *buf = NULL;
        unsigned long len = 0;

        while (i < argc) {
            int r;
            r = parse_opt_value(argc, argv, &i, "-p", &arg2);
            if (r < 0)
                return 2;
            if (r > 0)
                continue;
            r = parse_opt_value(argc, argv, &i, "-a", &arg3);
            if (r < 0)
                return 2;
            if (r > 0)
                continue;
            if (strcmp(argv[i], "--hex") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "Missing value for --hex\n");
                    return 2;
                }
                hex = argv[i + 1];
                i += 2;
                continue;
            }
            usage(argv[0]);
            return 2;
        }

        if (!hex) {
            fprintf(stderr, "patch requires --hex <hexbytes>\n");
            return 2;
        }

        if (hex_to_bytes(hex, &buf, &len) != 0) {
            fprintf(stderr, "invalid patch hex string\n");
            return 2;
        }

        arg4 = (unsigned long)(uintptr_t)buf;
        arg5 = len;
        (void)do_membarrier(PR_WXSHADOW_PATCH, arg2, arg3, arg4, arg5);
        free(buf);
        return 0;
    }

    usage(argv[0]);
    return 2;
}
