# Mini anti-cheat: building both sides

A small, self-contained exercise in client-side self-protection and why it
fails. One program (`sentinel`) tries to guarantee its own integrity; three
bypasses defeat it. Everything here attacks **code I wrote and control on both
sides** — it is a learning/interview artifact, not a tool for defeating anyone
else's protection.

Platform: Linux/x86-64. Each technique has a direct Windows analogue, noted
inline, because "DLL injection / IsDebuggerPresent" is where this normally
lives.

---

## TL;DR

A process cannot vouch for its own integrity, because every fact it gathers
about itself is read through an environment the attacker owns: the kernel
interfaces it queries, the libc functions it calls, and the bytes of the file
it was loaded from. The `sentinel` checks all three categories and all three
are bypassed:

| Check | Technique | Windows analogue | Beaten by |
|---|---|---|---|
| 1. Debugger | `TracerPid` + `PTRACE_TRACEME` | `IsDebuggerPresent`, `NtQueryInformationProcess` | `bypass.so` (hook `open`+`ptrace`) |
| 2. Code tamper | FNV-1a self-checksum of a function vs. an embedded baseline | CRC/hash of a `.text` region | `patch_binary.py` (patch code **and** rewrite the baseline) |
| 3. Injection | scan `/proc/self/maps` + `LD_PRELOAD` | `EnumProcessModules`, injected DLL scan | `bypass.so` (hook `open`+`getenv`, hide its own map) |

---

## The defender: `sentinel.c`

It is compiled **deliberately weak** so it can be attacked, and so the attacks
stay short enough to read: `-O0` (predictable codegen), `-no-pie` (fixed
addresses, trivial virtual-address → file-offset mapping), symbols kept. A real
target would be optimized, PIE, and stripped — that raises the effort, not the
ceiling.

The "asset" is `license_check()`, which returns `0` (trial). A cheater wants
`1` (licensed). The three checks are supposed to stop them.

### Clean run

```
== sentinel :: self-integrity report ==
  [ OK ] debugger               no tracer attached
  [ OK ] code integrity         license_check intact
  [ OK ] module injection       no foreign modules
  ----------------------------------------------
  license_check() -> trial
  VERDICT: integrity OK, running protected code
```

### Check 1 — debugger detection

Two independent signals:

- **`TracerPid`** in `/proc/self/status` is non-zero when anything (gdb,
  strace, another process) is ptrace-attached.
- **`PTRACE_TRACEME`**: a process can have only one tracer. If the call fails,
  someone already holds that slot.

Windows equivalent: `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` /
`NtQueryInformationProcess(ProcessDebugPort)`.

Detected correctly under gdb:

```
  [FAIL] debugger               DEBUGGER DETECTED
```

### Check 2 — code-patch / tamper detection

At startup the program computes FNV-1a over the bytes of `license_check()` and
compares it to `g_expected_checksum`, a value baked into the binary at build
time (`embed_baseline.py` runs `sentinel --emit-baseline` and writes the result
into `.data`). If anyone patches the function, the hash changes.

Windows equivalent: hashing/CRC of a `.text` range and comparing to a stored
constant — a staple of anti-tamper and DRM.

A naive attacker who patches only the code (`return 0` → `return 1`) is caught,
because they changed the function but not the stored answer:

```
  [FAIL] code integrity         CODE PATCHED
        expected 1ea98ac8  got 30103607
  license_check() -> LICENSED          <- cheat worked...
  VERDICT: TAMPERING DETECTED, refusing to run   <- ...but was noticed
```

### Check 3 — injected module detection

Walk `/proc/self/maps`, flag any mapped `*.so` that is not on an allowlist of
loader/glibc modules; also flag `LD_PRELOAD` directly.

Windows equivalent: `EnumProcessModules` / walking the PEB loader list to spot
an injected DLL.

Detected correctly when a module is preloaded:

```
  [FAIL] module injection       INJECTED MODULE
        -> /home/.../injected.so
```

---

## The attacker

### Bypass A — `bypass.so` (defeats checks 1 and 3)

An `LD_PRELOAD` shim — itself the "injected module" — that interposes the exact
libc functions the sentinel trusts. The sentinel calls the public `open`,
`read`, `ptrace`, and `getenv` symbols, so they resolve through the PLT to our
versions first:

- `open("/proc/self/status")` → we return a **memfd** holding a doctored copy
  with `TracerPid: 0`.
- `open("/proc/self/maps")` → we return a copy with our own `bypass.so` line
  stripped out.
- `ptrace(PTRACE_TRACEME)` → we return `0` ("success"), so the "am I traced?"
  probe always looks clean.
- `getenv("LD_PRELOAD")` → we return `NULL`, hiding our own presence.

Injection check, bypassed (the preload hides itself):

```
# LD_PRELOAD=bypass.so ./sentinel
  [ OK ] module injection       no foreign modules
  VERDICT: integrity OK, running protected code
```

Debugger check, bypassed **while actually running under gdb** (gdb via
`exec-wrapper` so the inferior keeps our preload):

```
# gdb -batch -ex "set exec-wrapper env LD_PRELOAD=bypass.so" -ex run ./sentinel
  [ OK ] debugger               no tracer attached     <- it IS being traced
  VERDICT: integrity OK, running protected code
```

The headline: the process is genuinely debugged and genuinely has a foreign
module mapped, and it reports itself clean — because it asked libc, and libc is
ours now. Interposition is the Linux analogue of IAT/inline hooking the
corresponding Win32 calls.

### Bypass B — `patch_binary.py` (defeats check 2)

The self-checksum's weakness is structural: the "trusted" value lives in the
same file the attacker edits. So we do both halves:

1. Patch `license_check()`: at `-O0`, `return 0;` is `mov eax, 0`
   (`b8 00 00 00 00`); flip the immediate to get `mov eax, 1`
   (`b8 01 00 00 00`). (The `return 1` path is `b8 01...`, so the search
   pattern `b8 00 00 00 00` is unambiguous.)
2. Recompute FNV-1a over the **patched** bytes and overwrite
   `g_expected_checksum` to match.

Note that step 2 reuses `elfpatch.py` — the very helper the honest build used
to embed the baseline in the first place. Defender and attacker run the same
tool.

```
[1] patched return 0 -> return 1 at file offset 0x131c
[2] rewrote g_expected_checksum 0x1ea98ac8 -> 0x30103607 at file offset 0x3078

# ./sentinel.cheated
  [ OK ] code integrity         license_check intact   <- the lie checks out
  license_check() -> LICENSED
  VERDICT: integrity OK, running protected code
```

---

## Why client-side self-protection is fundamentally weak

The checks are not "buggy"; the model is. A self-check asks the process to be
both the thing under test and the judge, while the attacker owns the ground it
stands on:

- **The data source is attacker-controlled.** `/proc`, libc, syscalls — the
  attacker sits between the check and the truth and edits the answer
  (bypass A).
- **The reference value is attacker-controlled.** Any baked-in baseline ships
  inside the artifact the attacker can rewrite (bypass B).
- **There is no root of trust.** Nothing here is anchored to something the
  attacker can't reach, so every result is forgeable.

This is why it is an *arms race* in practice: real anti-cheats push the checks
somewhere harder to reach and raise cost, rather than achieving a proof.

- **Kernel driver / early-boot (ring 0):** EAC, BattlEye, Vanguard. Harder to
  interpose from userland — but kernel exploits and (now) hypervisor-level
  cheats move the fight up another layer.
- **Server-authoritative logic:** the strongest move. If the server never
  trusts the client's "I'm licensed / my shot hit," there is nothing locally
  worth patching. You can't checksum your way to trust; you can refuse to need
  it.
- **Attestation / TPM / secure boot:** anchor a measurement in hardware the
  user can't trivially forge — an actual (if attackable) root of trust.
- **Obfuscation, packing, virtualized code, timing checks:** raise the cost of
  reversing. Buys time, never immunity.

The honest framing for an interview: *self-integrity on an attacker-controlled
machine is a cost problem, not a correctness problem. The only durable fix is
to stop trusting the client — move the authority to a party the attacker
doesn't control.*

---

## Files

| File | Role |
|---|---|
| `sentinel.c` | The anti-cheat: three self-checks + the protected `license_check()`. |
| `bypass.c` → `bypass.so` | LD_PRELOAD shim; defeats debugger + injection checks. |
| `patch_binary.py` | Patches code and rewrites the checksum baseline; defeats tamper check. |
| `injected.so` | Benign "hostile" module, used to show the injection check firing. |
| `elfpatch.py` | Shared ELF symbol-locator / byte-patcher (used by build *and* attack). |
| `embed_baseline.py` | Build step: bakes the pristine checksum into the binary. |
| `Makefile` | Two-pass build (`make`). |
| `demo.sh` | Reproduces every case below (`./demo.sh`). |

## Build & run

```sh
make            # builds sentinel (with baseline embedded), bypass.so, injected.so
./demo.sh       # runs all 7 cases: clean, 3x detected, 3x bypassed
```

Everything was built and run on Ubuntu 24.04, gcc 13.3, gdb 15.1. The outputs
quoted above are captured verbatim from `./demo.sh`.

## Mapping to a Windows interview story

| Here (Linux) | Say this (Windows) |
|---|---|
| `TracerPid` / `PTRACE_TRACEME` | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, PEB `BeingDebugged`, `NtQueryInformationProcess` |
| FNV-1a of a function vs. embedded value | CRC/SHA of a `.text` region vs. a stored hash (anti-tamper/DRM) |
| `/proc/self/maps` + `LD_PRELOAD` scan | `EnumProcessModules` / PEB `InLoadOrderModuleList` to find an injected DLL |
| `LD_PRELOAD` libc interposition | IAT hooking / inline (trampoline) hooking of the equivalent Win32/NT calls |
| `b8 00→01` immediate flip | same idea: flip a `jz`→`jnz`, NOP a check, patch a return |
| rewrite `g_expected_checksum` | patch the stored hash the integrity check compares against |
