/* ============================================================================
 * bypass.c  ->  bypass.so   (LD_PRELOAD shim == the "injected module")
 *
 * Defeats two of the sentinel's three checks by interposing the public libc
 * functions it trusts.  This is the single most important idea in the whole
 * exercise: *the defender runs inside a world the attacker controls*, so every
 * fact it gathers about itself is attacker-filterable.
 *
 *   CHECK 1 (debugger):
 *     - open("/proc/self/status")  -> we return a memfd whose TracerPid is 0
 *     - ptrace(PTRACE_TRACEME)     -> we return 0 ("success"), hiding the tracer
 *
 *   CHECK 3 (injection):
 *     - getenv("LD_PRELOAD")       -> we return NULL (hide our own presence)
 *     - open("/proc/self/maps")    -> we strip the line that maps bypass.so
 *
 * CHECK 2 (code integrity) is NOT defeated here -- a preload can't un-patch
 * on-disk code.  That one is defeated by patch_binary.py, which rewrites the
 * trusted checksum.  Together they cover all three.
 *
 * Build:  cc -shared -fPIC -O2 -o bypass.so bypass.c -ldl
 * ==========================================================================*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/ptrace.h>

/* ---- pointers to the real libc functions (resolved lazily) ------------- */
static int   (*real_open)(const char *, int, ...);
static int   (*real_open64)(const char *, int, ...);
static int   (*real_openat)(int, const char *, int, ...);
static long  (*real_ptrace)(enum __ptrace_request, ...);
static char *(*real_getenv)(const char *);

static void *next(const char *name)
{
    void *p = dlsym(RTLD_NEXT, name);
    return p;
}
#define BIND(fp, name) do { if (!(fp)) *(void **)(&(fp)) = next(name); } while (0)

/* Serve some in-memory bytes as a real, readable fd. */
static int memfd_with(const char *data, size_t len)
{
    int fd = memfd_create("sentinel-screen", MFD_CLOEXEC);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w <= 0) { close(fd); return -1; }
        off += (size_t)w;
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

/* Read a whole (small, /proc-sized) file via the REAL open/read. */
static char *slurp_real(const char *path, size_t *out_len)
{
    BIND(real_open, "open");
    int fd = real_open(path, O_RDONLY);
    if (fd < 0) return NULL;
    size_t cap = 256 * 1024, len = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return NULL; }
    for (;;) {
        if (len + 4096 > cap) { cap *= 2; char *n = realloc(buf, cap); if (!n) { free(buf); close(fd); return NULL; } buf = n; }
        ssize_t r = read(fd, buf + len, 4096);
        if (r < 0) { free(buf); close(fd); return NULL; }
        if (r == 0) break;
        len += (size_t)r;
    }
    close(fd);
    buf[len] = 0;
    *out_len = len;
    return buf;
}

static int is_status(const char *p) { return p && strcmp(p, "/proc/self/status") == 0; }
static int is_maps(const char *p)   { return p && strcmp(p, "/proc/self/maps")   == 0; }

/* Rewrite /proc/self/status so TracerPid is always 0. */
static int fake_status(void)
{
    size_t len; char *src = slurp_real("/proc/self/status", &len);
    if (!src) return -1;
    char *out = malloc(len + 32); if (!out) { free(src); return -1; }
    size_t o = 0;
    for (char *line = src, *nl; line && *line; line = nl ? nl + 1 : NULL) {
        nl = strchr(line, '\n');
        size_t ll = nl ? (size_t)(nl - line) + 1 : strlen(line);
        if (strncmp(line, "TracerPid:", 10) == 0)
            o += (size_t)sprintf(out + o, "TracerPid:\t0\n");
        else { memcpy(out + o, line, ll); o += ll; }
    }
    free(src);
    int fd = memfd_with(out, o);
    free(out);
    return fd;
}

/* Rewrite /proc/self/maps so our own bypass.so is not listed. */
static int fake_maps(void)
{
    size_t len; char *src = slurp_real("/proc/self/maps", &len);
    if (!src) return -1;
    char *out = malloc(len + 1); if (!out) { free(src); return -1; }
    size_t o = 0;
    for (char *line = src, *nl; line && *line; line = nl ? nl + 1 : NULL) {
        nl = strchr(line, '\n');
        size_t ll = nl ? (size_t)(nl - line) + 1 : strlen(line);
        if (!strstr(line, "bypass.so")) {   /* keep every line that isn't us */
            memcpy(out + o, line, ll); o += ll;
        }
    }
    free(src);
    int fd = memfd_with(out, o);
    free(out);
    return fd;
}

/* ----------------------------- the hooks -------------------------------- */

int open(const char *path, int flags, ...)
{
    if (is_status(path)) { int fd = fake_status(); if (fd >= 0) return fd; }
    if (is_maps(path))   { int fd = fake_maps();   if (fd >= 0) return fd; }
    BIND(real_open, "open");
    va_list ap; va_start(ap, flags); mode_t m = va_arg(ap, mode_t); va_end(ap);
    return real_open(path, flags, m);
}

int open64(const char *path, int flags, ...)
{
    if (is_status(path)) { int fd = fake_status(); if (fd >= 0) return fd; }
    if (is_maps(path))   { int fd = fake_maps();   if (fd >= 0) return fd; }
    BIND(real_open64, "open64");
    if (!real_open64) { BIND(real_open, "open"); return real_open(path, flags); }
    va_list ap; va_start(ap, flags); mode_t m = va_arg(ap, mode_t); va_end(ap);
    return real_open64(path, flags, m);
}

int openat(int dirfd, const char *path, int flags, ...)
{
    if (is_status(path)) { int fd = fake_status(); if (fd >= 0) return fd; }
    if (is_maps(path))   { int fd = fake_maps();   if (fd >= 0) return fd; }
    BIND(real_openat, "openat");
    va_list ap; va_start(ap, flags); mode_t m = va_arg(ap, mode_t); va_end(ap);
    return real_openat(dirfd, path, flags, m);
}

long ptrace(enum __ptrace_request request, ...)
{
    /* The anti-debug trick is "if TRACEME fails, I'm being traced."
       We make it look like it always succeeds, so the tracer stays hidden. */
    if (request == PTRACE_TRACEME)
        return 0;
    BIND(real_ptrace, "ptrace");
    va_list ap; va_start(ap, request);
    void *pid  = va_arg(ap, void *);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    return real_ptrace(request, pid, addr, data);
}

char *getenv(const char *name)
{
    if (name && strcmp(name, "LD_PRELOAD") == 0)
        return NULL;                 /* "there is no preload here" */
    BIND(real_getenv, "getenv");
    return real_getenv(name);
}
