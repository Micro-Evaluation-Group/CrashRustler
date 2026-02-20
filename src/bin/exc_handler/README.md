# exc_handler

Mach exception handler binary that intercepts crashes from a target process, analyzes them for exploitability, writes crash logs, and exits with coded return values. It is a Rust replacement for CrashWrangler's `exc_handler`.

## Build

```bash
cargo build --release
```

The binary is at `target/release/exc_handler`.

## Usage

**Fork+exec mode** — launch a program under exception monitoring:

```bash
# Basic usage: run a program and catch crashes
./target/release/exc_handler /path/to/program arg1 arg2

# Check the exit code to determine exploitability
echo $?
# 0       = no crash (normal exit)
# 1-99    = crash signal number (not exploitable)
# 101-199 = crash signal number + 100 (exploitable)
# -1      = error
# -2      = non-crash signal (SIGTERM, SIGKILL, etc.)
```

**Attach mode** — attach to an already-running process:

```bash
CR_ATTACH_PID=12345 ./target/release/exc_handler
# or
./target/release/exc_handler --attach-pid 12345
```

**Launchd service mode** — register as a Mach bootstrap service and wait for exceptions:

```bash
./target/release/exc_handler --launchd-name com.example.crashhandler
# or
CR_REGISTER_LAUNCHD_NAME=com.example.crashhandler ./target/release/exc_handler
```

In this mode, exc_handler registers the service name with the Mach bootstrap server via `bootstrap_check_in()` and blocks waiting for exception messages. A separate process or tool must set the target's exception ports to point to the registered service name. This enables monitoring launchd-managed daemons without fork+exec or PID attachment.

## CLI flags

All configuration can be set via CLI flags (which override environment variables):

```bash
# Quiet mode with custom log directory
./target/release/exc_handler --quiet --log-dir /tmp/logs ./target_binary

# Attach to a running process
./target/release/exc_handler --attach-pid 12345

# Treat read-access crashes as exploitable
./target/release/exc_handler --exploitable-reads ./target_binary < input.bin
```

Run `exc_handler --help` for the full list of options.

## Fuzzing example

```bash
# Run a test case through exc_handler and check exploitability
./target/release/exc_handler ./target_binary < crash_input.bin
EXIT_CODE=$?

if [ $EXIT_CODE -gt 100 ]; then
    echo "EXPLOITABLE (signal $(($EXIT_CODE - 100)))"
elif [ $EXIT_CODE -gt 0 ] && [ $EXIT_CODE -lt 100 ]; then
    echo "NOT EXPLOITABLE (signal $EXIT_CODE)"
else
    echo "No crash (exit $EXIT_CODE)"
fi
```

## Environment variables

All configuration can be set via `CR_*` environment variables. CLI flags take precedence over environment variables.

| Variable | CLI Flag | Description |
|----------|----------|-------------|
| `CR_ATTACH_PID` | `--attach-pid <PID>` | PID to attach to (instead of fork+exec) |
| `CR_QUIET` | `-q`, `--quiet` | Suppress stderr output |
| `CR_LOG_DIR` | `--log-dir <DIR>` | Crash log directory (default: `./crashlogs/`) |
| `CR_LOG_PATH` | `--log-path <PATH>` | Explicit crash log file path |
| `CR_NO_LOG` | `--no-log` | Don't write crash logs |
| `CR_EXPLOITABLE_READS` | `--exploitable-reads` | Treat read-access crashes as exploitable |
| `CR_EXPLOITABLE_JIT` | `--exploitable-jit` | Treat crashes in JIT code as exploitable |
| `CR_IGNORE_FRAME_POINTER` | `--ignore-frame-pointer` | Ignore frame pointer inconsistency |
| `CR_NO_KILL_CHILD` | `--no-kill-child` | Don't kill child process on exit |
| `CR_CURRENT_CASE` | `--current-case <ID>` | Test case identifier (written to crash log) |
| `CR_CASE_FILE` | `--case-file <PATH>` | File to write current case identifier to |
| `CR_PID_FILE` | `--pid-file <PATH>` | File to write child PID to |
| `CR_LOCK_FILE` | `--lock-file <PATH>` | Lock file path (default: `./cr.lck`) |
| `CR_FORWARD_CRASH_REPORTER` | `--forward-crash-reporter` | Forward exceptions to CrashReporter |
| `CR_USE_GMAL` | `--use-gmal` | Use GMAL for crash reporter |
| `CR_MACHINE_READABLE` | `--machine-readable` | Machine-readable output |
| `CR_REGISTER_LAUNCHD_NAME` | `--launchd-name <NAME>` | Launchd service name for bootstrap registration |
| `CR_LOG_INFO` | `--log-info <INFO>` | Additional log info string |
| `CR_TEST_CASE_PATH` | `--test-case-path <PATH>` | Path to the test case file |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No crash — child exited normally |
| `1`–`99` | Crash signal number — not exploitable (e.g., `11` = SIGSEGV) |
| `101`–`199` | Signal + 100 — exploitable (e.g., `111` = exploitable SIGSEGV) |
| `-1` | Error |
| `-2` | Non-crash signal (SIGTERM, SIGKILL, etc.) |

The exit code scheme encodes both the **crash signal** and the **exploitability verdict** in a single integer, so fuzzers and automation scripts can branch on a single `$?` check without parsing log files. The two non-overlapping ranges — `1`–`99` for non-exploitable and `101`–`199` for exploitable — let you extract both pieces of information:

- **Signal number:** `exit_code % 100` (e.g., `111 % 100 = 11` → SIGSEGV)
- **Exploitable?** `exit_code > 100`

This is directly compatible with CrashWrangler's exit code convention, so existing fuzzer harnesses that check `$? > 100` to detect exploitable crashes work without modification.

## Codesigning

The `exc_handler` binary uses Mach APIs (`task_for_pid`, `mach_vm_read`, etc.) that require the `com.apple.security.get-task-allow` entitlement on modern macOS. Without codesigning, the binary can only inspect child processes it spawns via fork+exec, and attach mode will fail.

**Sign after building:**

```bash
cargo build --release
./scripts/codesign.sh
```

The script auto-detects a signing identity from your keychain, signs with the entitlements at `entitlements/exc_handler.entitlements`, and verifies the result. If no identity is found, it exits cleanly — signing is optional.

You can sign a specific binary path:

```bash
./scripts/codesign.sh target/debug/exc_handler
```

### Certificate setup

You need an Apple Development certificate with a valid trust chain. If you have a certificate from the [Apple Developer portal](https://developer.apple.com/account/resources/certificates/list) but `security find-identity -p codesigning -v` reports `0 valid identities found`, the Apple WWDR intermediate certificate is likely missing or expired.

**Install the WWDR G3 intermediate:**

```bash
curl -O https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
security import AppleWWDRCAG3.cer -k ~/Library/Keychains/login.keychain-db -T /usr/bin/codesign
rm AppleWWDRCAG3.cer
```

**Verify:**

```bash
# Should show your identity with "1 valid identities found"
security find-identity -p codesigning -v
```

The `build.rs` script detects valid signing identities at build time and emits a `cargo:warning` indicating whether a certificate was found. If no identity is available, the build proceeds normally — signing is not required for building or running fork+exec mode against child processes.

## Crash logs

By default, crash logs are written to `./crashlogs/` with filenames like:

```
program-12345.crashlog.txt                  # not exploitable
program-12345.exploitable.crashlog.txt      # exploitable
program-12345.unknown.crashlog.txt          # unknown
```

Crash logs include:
- Process info (name, PID, bundle identifier, path, SHA256, date)
- Exception type, codes, and crashing instruction disassembly
- Exploitability classification with reasoning
- Application Specific Information (sanitizer error reports, when present — see below)
- Thread backtraces for all threads (crashed thread first) with resolved symbol names and offsets
- Full ARM64/x86_64 register state for the crashed thread
- Binary images with load addresses and UUIDs

## Sanitizer crash reports

When the target process is built with AddressSanitizer (or other sanitizers like UBSan or TSan), `exc_handler` automatically extracts the full sanitizer error report from the crashed process's memory. The report appears in the crash log under an **"Application Specific Information:"** section, between the exploitability rating and the thread backtraces.

This works by scanning all loaded binary images using two complementary mechanisms:

1. **`___crashreporter_info__` nlist symbol** — A `const char*` that Rust's sanitizer runtimes populate with their error report before calling `abort()`. Found via Mach-O nlist symbol table scanning.

2. **`__DATA,__crash_info` Mach-O section** — The modern macOS crash reporter mechanism used by clang's sanitizer runtimes. Contains a `crashreporter_annotations_t` struct whose `message` field (offset 0x08) points to the error report string.

The extraction reads up to 64 KB from target process memory, capturing the complete report including error type, access details, allocation/deallocation backtraces, and shadow memory state. Both Rust and C/C++ binaries compiled with sanitizers are supported.

### Supported toolchains

| Toolchain | Sanitizers | Extraction Mechanism |
|-----------|-----------|---------------------|
| Rust nightly (`-Zsanitizer=*`) | ASan, TSan | `___crashreporter_info__` nlist symbol |
| Apple clang (`-fsanitize=*`) | ASan, TSan, UBSan, IntSan | `__DATA,__crash_info` section |
| Homebrew LLVM clang (`-fsanitize=cfi`) | CFI | `___crashreporter_info__` nlist symbol (via UBSan runtime) |

CFI requires Homebrew LLVM clang — Apple clang does not support `-fsanitize=cfi`. CFI diagnostic mode (`-fno-sanitize-trap=cfi`) links the UBSan runtime which populates `___crashreporter_info__`.

GCC is not supported for sanitizer crash reporting on macOS. Homebrew GCC does not ship sanitizer runtime libraries (`libasan`, `libtsan`), and GCC's sanitizer instrumentation is ABI-incompatible with clang's runtimes. Since CrashRustler is macOS-only, clang is the appropriate C/C++ toolchain for sanitizer-instrumented binaries.

Example (ASan heap-use-after-free):

```
Exploitability:  NOT_EXPLOITABLE
  EXC_CRASH (undemuxed) — not exploitable

Application Specific Information:
=================================================================
==95879==ERROR: AddressSanitizer: heap-use-after-free on address 0x6060000002c0 ...
READ of size 1 at 0x6060000002c0 thread T0
    #0 0x0001002a4be4 in asan_crash_dummy::do_heap_uaf+0x164 ...
    ...
0x6060000002c0 is located 0 bytes inside of 64-byte region [0x6060000002c0,0x606000000300)
freed by thread T0 here:
    #0 0x000100b19958 in free+0x70 ...
    ...
previously allocated by thread T0 here:
    #0 0x000100b1986c in malloc+0x6c ...
    ...
SUMMARY: AddressSanitizer: heap-use-after-free ...
Shadow bytes around the buggy address:
  ...

Thread 0 Crashed:
...
```

All sanitizer crashes arrive as `EXC_CRASH` → `SIGABRT` → exit code `6` (not exploitable), since the sanitizer detects the corruption and aborts before the process can be exploited. The sanitizer report in the crash log provides the actual memory error details that would otherwise be lost.

This feature requires no special configuration — it activates automatically whenever `___crashreporter_info__` is populated or a `__crash_info` section contains a message pointer in any loaded library in the target process.
