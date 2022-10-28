#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <elf.h>
#include <link.h>
#include <sys/prctl.h>
#include "arg.h"
#include "sys.h"
#include "tos.h"
#include "util.h"

#ifndef O_EXEC
#define O_EXEC O_PATH
#endif

#define ALIGN(v, a) (((v) + (a) - 1) & ~((a) - 1))
#define ERRMAX 128

static char intercept = SYSCALL_DISPATCH_FILTER_ALLOW;
static char *data;
static size_t datasize;
static char errstr[ERRMAX];
static int debug;

static void
truncstrcpy(char *dst, const char *src, size_t len)
{
	if (!memccpy(dst, src, '\0', len))
		dst[len - 1] = '\0';
}

static long long
seterr(long long ret)
{
	if (ret < 0)
		truncstrcpy(errstr, strerror(errno), sizeof errstr);
	return ret;
}

static int
sysexits(char *status)
{
	if (debug)
		fprintf(stderr, "exits %s\n", status ? status : "nil");
	exit(status && *status);
	return 0;
}

static int
sysclose(int fd)
{
	if (debug)
		fprintf(stderr, "close %d", fd);
	return seterr(close(fd));
}

static int
opencreate(char *name, int mode, int perm, int flag)
{
	switch (mode & 3) {
	case 0: flag |= O_RDONLY; break;
	case 1: flag |= O_WRONLY; break;
	case 2: flag |= O_RDWR; break;
	case 3: flag |= O_EXEC; break;
	}
	if (mode & 16)
		flag |= O_TRUNC;
	if (mode & 32)
		flag |= O_CLOEXEC;
	return seterr(open(name, flag, perm));
}

static int
sysopen(char *name, int mode)
{
	if (debug)
		fprintf(stderr, "open %s %d", name, mode);
	return opencreate(name, mode, 0, 0);
}

static int
syscreate(char *name, int mode, int perm)
{
	if (debug)
		fprintf(stderr, "create %s %d %d", name, mode, perm);
	return opencreate(name, mode, perm, O_CREAT);
}

static int
syspipe(int fd[2])
{
	if (debug)
		fprintf(stderr, "pipe %p", (void *)fd);
	return seterr(socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
}

static int
sysbrk_(char *addr)
{
	if (debug)
		fprintf(stderr, "brk_ %p", addr);
	if (mremap(data, datasize, addr - data, 0) == MAP_FAILED)
		return seterr(-1);
	datasize = addr - data;
	return 0;
}

static int
syserrstr(char *buf, unsigned len)
{
	char tmp[ERRMAX];

	if (debug)
		fprintf(stderr, "errstr %.*s %d", (int)len, buf, len);
	if (len > sizeof errstr)
		len = sizeof errstr;
	truncstrcpy(tmp, buf, len);
	truncstrcpy(buf, errstr, len);
	truncstrcpy(errstr, tmp, len);
	return 0;
}

static int
syswstat(char *name, unsigned char *edir, unsigned nedir)
{
	if (debug)
		fprintf(stderr, "wstat %s %p %u", name, (void *)edir, nedir);
	strcpy(errstr, "not implemented");
	return -1;
}

static int
sysfwstat(int fd, unsigned char *edir, unsigned nedir)
{
	if (debug)
		fprintf(stderr, "fwstat %d %p %u", fd, (void *)edir, nedir);
	strcpy(errstr, "not implemented");
	return -1;
}

static long long
syspread(int fd, void *buf, int len, long long off)
{
	if (debug)
		fprintf(stderr, "pread %d %p %d %lld", fd, buf, len, off);
	return seterr(off == -1 ? read(fd, buf, len) : pread(fd, buf, len, off));
}

static long long
syspwrite(int fd, void *buf, int len, long long off)
{
	if (debug)
		fprintf(stderr, "pwrite %d %p %d %lld", fd, buf, len, off);
	return seterr(off == -1 ? write(fd, buf, len) : pwrite(fd, buf, len, off));
}

static void
sigsys(int sig, siginfo_t *info, void *ptr)
{
	ucontext_t *uctx;
	mcontext_t *mctx;
	greg_t *greg;
	int sc;
	long long *sp;
	long ret;

	uctx = ptr;
	mctx = &uctx->uc_mcontext;
	greg = mctx->gregs;
	sc = greg[REG_RBP];
	sp = (long long *)greg[REG_RSP];
	switch (sc) {
	case EXITS:  ret = sysexits((char *)sp[1]); break;
	case CLOSE:  ret = sysclose((int)sp[1]); break;
	case OPEN:   ret = sysopen((char *)sp[1], (int)sp[1]); break;
	case PIPE:   ret = syspipe((int *)sp[1]); break;
	case CREATE: ret = syscreate((char *)sp[1], (int)sp[1], (int)sp[2]); break;
	case BRK_:   ret = sysbrk_((char *)sp[1]); break;
	case ERRSTR: ret = syserrstr((char *)sp[1], (unsigned)sp[2]); break;
	case WSTAT:  ret = syswstat((char *)sp[1], (unsigned char *)sp[2], (unsigned)sp[3]); break;
	case FWSTAT: ret = sysfwstat((int)sp[1], (unsigned char *)sp[2], (unsigned)sp[3]); break;
	case PREAD:  ret = syspread((int)sp[1], (void *)sp[2], (int)sp[3], (long long)sp[4]); break;
	case PWRITE: ret = syspwrite((int)sp[1], (void *)sp[2], (int)sp[3], (long long)sp[4]); break;
	default:
		if (debug)
			fprintf(stderr, "unknown syscall %d", sc);
		strcpy(errstr, "not implemented");
		ret = -1;
		break;
	}
	if (debug)
		fprintf(stderr, " \u2192 %ld\n", ret);
	greg[REG_RAX] = ret;
}

int
findlibc(struct dl_phdr_info *info, size_t size, void *ptr)
{
	const Elf64_Phdr *p;
	uintptr_t offset, length, libc;

	libc = (uintptr_t)read;  /* arbitrary function used to identify libc text segment */
	for (p = info->dlpi_phdr; p < info->dlpi_phdr + info->dlpi_phnum; ++p) {
		if (p->p_type != PT_LOAD || !(p->p_flags & PF_X))
			continue;
		offset = info->dlpi_addr + p->p_vaddr;
		length = p->p_memsz;
		if (offset < libc && libc - offset < length) {
			if (debug)
				fprintf(stderr, "found libc at [%"PRIxPTR"-%"PRIxPTR"]\n", offset, offset + length);
			if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, offset, length, &intercept) != 0) {
				perror("prctl PR_SET_SYSCALL_USER_DISPATCH");
				exit(1);
			}
			return 1;
		}
	}
	return 0;
}

void
start_c(uintptr_t entry, int argc, char *argv[])
{
	extern void start(uintptr_t entry, Tos *, int, char *[]);
	Tos tos;

	tos.pid = getpid();
	if (debug)
		fprintf(stderr, "jumping to entry point %"PRIxPTR"\n", entry);
	intercept = SYSCALL_DISPATCH_FILTER_BLOCK;
	start(entry, &tos, argc, argv);
}

static void
usage(void)
{
	fprintf(stderr, "usage: nine [-d] cmd [args...]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct sigaction sa = {
		.sa_sigaction = sigsys,
		.sa_flags = SA_SIGINFO,
	};
	int fd;
	char *name;
	unsigned char hdr[40];
	ssize_t ret;
	unsigned long magic, textsize, bsssize;
	uintptr_t entry, textaddr, dataaddr;
	void *text;
	unsigned char *exec;

	ARGBEGIN {
	case 'd':
		++debug;
		break;
	default:
		usage();
	} ARGEND;
	if (argc < 1)
		usage();

	name = argv[0];
	fd = open(name, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", name, strerror(errno));
		return 1;
	}
	ret = read(fd, hdr, sizeof hdr);
	if (ret < 0) {
		fprintf(stderr, "read %s: %s\n", name, strerror(errno));
		return 1;
	}
	if (ret < sizeof hdr) {
		fprintf(stderr, "read %s: short read\n", name);
		return 1;
	}
	magic = getbe32(hdr);
	if (magic != 0x8a97) {
		fprintf(stderr, "bad magic: %#lx != 0x8a97\n", magic);
		return 1;
	}
	textsize = 40 + getbe32(hdr + 4);
	datasize = getbe32(hdr + 8);
	bsssize = getbe32(hdr + 12);
	entry = getbe64(hdr + 32);

	textaddr = 0x200000;
	dataaddr = ALIGN(textaddr + textsize, 0x200000);

	exec = mmap(NULL, textsize + datasize, PROT_READ, MAP_PRIVATE, fd, 0);
	if (exec == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	if (debug)
		fprintf(stderr, "mapping text segment to %#"PRIxPTR"\n", textaddr);
	text = mmap((void *)textaddr, textsize, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0);
	if (text == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	if (debug)
		fprintf(stderr, "mapping data segment to %#"PRIxPTR"\n", dataaddr);
	data = mmap((void *)dataaddr, datasize + bsssize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED_NOREPLACE | MAP_ANONYMOUS, -1, 0);
	if (data == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	memcpy(data, exec + textsize, datasize);
	munmap(exec, textsize + datasize);
	datasize += bsssize;

	if (!dl_iterate_phdr(findlibc, NULL)) {
		fprintf(stderr, "could not find libc text segment\n");
		return 1;
	}
	sigaction(SIGSYS, &sa, NULL);
	start_c(entry, argc, argv);
}
