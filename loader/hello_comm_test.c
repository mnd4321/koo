#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [magic_key] [cmd] [token]\n", prog);
}

int main(int argc, char **argv)
{
	unsigned long magic_key = 0x53454c58UL;
	unsigned long cmd = 0x0UL;
	unsigned long token = 0x12345678UL;
	long ret;

	if (argc > 3) {
		usage(argv[0]);
		return 2;
	}
	if (argc >= 2)
		cmd = strtoul(argv[1], NULL, 0);

#if defined(__linux__)
#ifndef __NR_membarrier
#ifdef SYS_membarrier
#define __NR_membarrier SYS_membarrier
#endif
#endif
#ifndef __NR_membarrier
	fprintf(stderr, "membarrier syscall number is unavailable on this libc/arch\n");
	return 1;
#endif
	errno = 0;
	ret = syscall(__NR_membarrier, magic_key, cmd, token);
	fprintf(stderr,
		"membarrier test sent: key=0x%lx cmd=0x%lx token=0x%lx ret=%ld errno=%d(%s)\n",
		magic_key, cmd, token, ret, errno, strerror(errno));
	return 0;
#else
	fprintf(stderr, "hello_comm_test only works on Linux/Android\n");
	return 1;
#endif
}
