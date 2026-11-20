/* ============================================================================
 * sentinel.c  --  a *mini anti-cheat*: a process that guards its own integrity.
 *
 * It runs three self-protection checks on its OWN process, each the Linux
 * analogue of a classic Windows anti-cheat / anti-tamper technique:
 *
 *   1. Debugger detection    (Linux: TracerPid + PTRACE_TRACEME
 *                             ~ Windows: IsDebuggerPresent / CheckRemoteDebugger)
 *   2. Code-patch detection  (Linux: self-checksum of a function
 *                             ~ Windows: CRC of a .text region / anti-tamper)
 *   3. Injected-.so detection(Linux: scan /proc/self/maps + LD_PRELOAD
 *                             ~ Windows: enumerate loaded modules / injected DLL)
 *
 * It is COMPILED DELIBERATELY WEAK (-O0 -no-pie, checks in userland, reference
 * values baked into the binary) so that the companion bypass can defeat it.
 * That weakness is the whole lesson -- see WRITEUP.md.
 *
 * All of the /proc reads and the ptrace/getenv calls use the public libc
 * symbols on purpose: that is exactly the surface an LD_PRELOAD shim interposes.
 * ==========================================================================*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>

/* ---------------------------------------------------------------------------
 * The "asset" we are protecting.  In a real game this would be the code that
 * decides whether you may play / what you are allowed to do.  Here it just
 * reports whether this build is licensed.  A cheater wants it to return 1.
 *
 * aligned(64) + noinline + the trailing marker give us a stable, isolated
 * byte range to checksum.  At -O0 `return 0;` compiles to `mov eax, 0`
 * (bytes B8 00 00 00 00) -- that immediate is the byte the patcher flips.
 * ------------------------------------------------------------------------- */
__attribute__((noinline, aligned(64)))
int license_check(void)
{
    int licensed = 0;          /* trial build: NOT licensed            */
    if (licensed)              /* cheat target: force this true, or ... */
        return 1;              /* ... flip the immediate in `return 0;` */
    return 0;
}

/* Immediately after license_check so we can measure its length.          */
__attribute__((noinline, aligned(64)))
void license_check_end(void) { /* marker only */ }

/* The reference checksum.  Placeholder value is overwritten at build time
 * by embed_baseline (see Makefile).  It lives in .data INSIDE this same
 * binary -- which is precisely why a client-side integrity check is weak:
 * the attacker controls the file that stores the "trusted" answer.        */
volatile uint32_t g_expected_checksum = 0xAAAAAAAAu;

/* ---- FNV-1a: tiny, deterministic, good enough for a tamper tripwire --- */
static uint32_t fnv1a(const unsigned char *p, size_t n)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

static size_t license_check_len(void)
{
    uintptr_t a = (uintptr_t)&license_check;
    uintptr_t b = (uintptr_t)&license_check_end;
    return (b > a) ? (size_t)(b - a) : 64;   /* fallback if reordered */
}

static uint32_t checksum_self(void)
{
    return fnv1a((const unsigned char *)&license_check, license_check_len());
}

/* =====================  CHECK 1: debugger detection  ===================== */

/* 1a. The kernel records our tracer's PID in /proc/self/status.  A debugger
 *     (gdb, strace, ...) shows up as a non-zero TracerPid.                  */
static int dbg_tracerpid(void)
{
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return -1;
    char buf[8192];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    char *p = strstr(buf, "TracerPid:");
    if (!p) return -1;
    return atoi(p + 10) != 0;          /* 1 == something is tracing us */
}

/* 1b. A process may be ptrace-traced by only one tracer.  If we try to
 *     PTRACE_TRACEME and it fails, a debugger already holds that slot.      */
static int dbg_ptrace(void)
{
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
        return 1;                      /* TRACEME refused -> already traced */
    /* No debugger: we are now nominally self-traced by our parent shell,
       which is harmless for a short-lived process that catches no signals. */
    return 0;
}

/* =====================  CHECK 3: injected .so / DLL  ===================== */

/* Walk /proc/self/maps; any mapped *.so that is not on the allowlist of
 * things the loader brings in legitimately is treated as an injection.
 * Also flag LD_PRELOAD directly.  (Raw open/read so a preload can see it.)  */
static int injection_scan(char *found, size_t flen)
{
    const char *pre = getenv("LD_PRELOAD");
    if (pre && *pre) { strncpy(found, pre, flen - 1); found[flen - 1] = 0; return 1; }

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return -1;

    static char buf[256 * 1024];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;

    for (char *line = strtok(buf, "\n"); line; line = strtok(NULL, "\n")) {
        char *path = strchr(line, '/');
        if (!path) continue;                 /* anon / [heap] / [stack] */
        if (!strstr(path, ".so")) continue;  /* only shared objects */
        /* allowlist: the dynamic loader + core glibc family */
        if (strstr(path, "libc.so")   || strstr(path, "libc-")   ||
            strstr(path, "ld-linux")  || strstr(path, "/ld-")    ||
            strstr(path, "libdl")     || strstr(path, "libm.so") ||
            strstr(path, "libpthread"))
            continue;
        strncpy(found, path, flen - 1); found[flen - 1] = 0;
        return 1;                            /* an uninvited module */
    }
    return 0;
}

/* ===============================  report  =============================== */

static void line(const char *name, int bad, const char *ok, const char *fail)
{
    printf("  [%s] %-22s %s\n", bad ? "FAIL" : " OK ", name, bad ? fail : ok);
}

int main(int argc, char **argv)
{
    /* Build-time helper: print the checksum of the pristine function so the
       Makefile can bake it into g_expected_checksum. */
    if (argc > 1 && strcmp(argv[1], "--emit-baseline") == 0) {
        printf("%08x\n", checksum_self());
        return 0;
    }

    printf("== sentinel :: self-integrity report ==\n");

    int d1 = dbg_tracerpid();
    int d2 = dbg_ptrace();
    int dbg = (d1 == 1) || (d2 == 1);

    uint32_t now = checksum_self();
    int tampered = (now != g_expected_checksum);

    char who[512] = {0};
    int injected = injection_scan(who, sizeof who) == 1;

    line("debugger",        dbg,      "no tracer attached",   "DEBUGGER DETECTED");
    line("code integrity",  tampered, "license_check intact", "CODE PATCHED");
    line("module injection", injected, "no foreign modules",  "INJECTED MODULE");

    if (tampered)
        printf("        expected %08x  got %08x\n", g_expected_checksum, now);
    if (injected)
        printf("        -> %s\n", who);

    int licensed = license_check();
    int ok = !dbg && !tampered && !injected;

    printf("  ----------------------------------------------\n");
    printf("  license_check() -> %s\n", licensed ? "LICENSED" : "trial");
    printf("  VERDICT: %s\n", ok ? "integrity OK, running protected code"
                                 : "TAMPERING DETECTED, refusing to run");
    return ok ? 0 : 1;
}
