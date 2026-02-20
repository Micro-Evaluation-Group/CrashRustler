# Tests

## Commands

```bash
cargo test                              # 315 lib + 33 bin + 14 doc + 64 integration (426 total)
cargo test unwind                       # Unwind module tests only (61 tests)
cargo test --test exc_handler           # Fork+exec integration tests (11 tests)
cargo test --test attach_exc_handler    # Attach-mode integration tests (8 tests, requires entitlement)
cargo test --test launchd_exc_handler   # Launchd service mode tests (5 tests, requires entitlement)
cargo test --test asan_exc_handler      # Rust ASan integration tests (8 tests, builds on demand)
cargo test --test tsan_exc_handler      # Rust TSan integration tests (4 tests, builds on demand)
cargo test --test c_asan_exc_handler    # C ASan integration tests (8 tests, builds with clang on demand)
cargo test --test c_tsan_exc_handler    # C TSan integration tests (4 tests, builds with clang on demand)
cargo test --test c_ubsan_exc_handler   # C UBSan integration tests (6 tests, builds with clang on demand)
cargo test --test c_intsan_exc_handler  # C integer sanitizer tests (8 tests, builds with clang on demand)
cargo test --test c_cfi_exc_handler     # C CFI integration tests (2 tests, builds with Homebrew LLVM on demand)
cargo clippy                            # Lint (zero warnings)
cargo fmt -- --check                    # Formatting check
```

## Library unit tests

315 tests co-located with their source modules across 30 submodules covering types, initialization, exploitability classification (with cross-architecture ARM64 and x86_64 coverage), accessors, descriptions, string utilities, binary images, backtrace methods, crash analysis, problem dictionaries, and the full unwind stack (registers, DWARF expressions, DWARF CFI, compact unwind, Mach-O parsing, frame pointer walking, and cursor integration).

- **init.rs:** `tests` (7 tests)
- **types.rs:** `types` (10 tests)
- **crash_rustler.rs:** `default_impl` (1 test)
- **exploitability.rs:** `classify` (24), `stack_suspicious` (19), `access_type_detection` (8)
- **accessors.rs:** `accessors` (18), `boolean_flags` (18), `version_methods` (11)
- **formatting.rs:** `descriptions` (21), `string_utils` (30), `mac_roman` (2)
- **memory.rs:** `record_error` (5), `crash_reporter_info` (8)
- **backtrace.rs:** `binary_images` (19), `backtrace_methods` (19)
- **analysis.rs:** `crash_analysis` (14), `dictionary_methods` (15)
- **unwind/mod.rs:** `tests` (3 tests)
- **unwind/registers.rs:** `tests` (8 tests)
- **unwind/arch.rs:** `tests` (6 tests)
- **unwind/macho.rs:** `tests` (4 tests)
- **unwind/compact_unwind.rs:** `tests` (19 tests)
- **unwind/dwarf_cfi.rs:** `tests` (3 tests)
- **unwind/dwarf_expr.rs:** `tests` (10 tests)
- **unwind/frame_pointer.rs:** `tests` (5 tests)
- **unwind/cursor.rs:** `tests` (3 tests)

## exc_handler binary unit tests

33 tests covering pure logic functions in the exc_handler binary crate (no Mach kernel state required):

- **ffi.rs:** `tests` (14 tests — shell_escape_arg, parse_procargs2)
- **handler.rs:** `tests` (8 tests — extract_pc register state parsing)
- **image_enum.rs:** `tests` (11 tests — demangle_symbol, read_c_string, read_large_c_string)

## ARM64 crash tests

The `dummy` test module (`src/dummy.rs`) contains 5 real ARM64 crash tests that trigger hardware exceptions via inline assembly — these run only on ARM64 hardware.

## Fork+exec integration tests (exc_handler.rs)

11 tests that launch `exc_handler` against `crash_dummy` in fork+exec mode to verify exit codes, crash log creation, crash log suppression, and backtrace symbol resolution. Tests that require Mach exception port privileges skip automatically if the debug entitlement is missing.

## Attach-mode integration tests (attach_exc_handler.rs)

8 tests that exercise `--attach-pid` mode: spawn crash dummies with `--wait`, read PID from stdout, launch exc_handler with `--attach-pid`, wait for readiness via stderr, send SIGUSR1 to trigger the crash. Covers core crash types (sigsegv, sigabrt, sigill), Rust ASan, and C ASan in attach mode.

Requires the `com.apple.security.get-task-allow` entitlement for `task_for_pid()`. Skips gracefully on CI runners with specific diagnostic messages.

## Launchd service mode integration tests (launchd_exc_handler.rs)

5 tests that exercise `--launchd-name` mode: register a Mach bootstrap service, spawn a crash dummy with `--wait`, look up the service via `bootstrap_look_up`, set exception ports on the dummy's task, then signal the dummy to crash. Also tests error handling for duplicate service name registration.

Requires the codesign entitlement. Skips gracefully on CI runners.

## Rust ASan integration tests (asan_exc_handler.rs)

8 tests that build a standalone Rust `asan-crash-dummy` binary with `-Zsanitizer=address` and run it under `exc_handler` to verify handling of AddressSanitizer-detected memory errors (heap overflow, heap use-after-free, stack overflow, stack use-after-free).

The ASan binary is built on demand and cached per test process. Tests skip if the build fails (no nightly, no ASan support) or entitlements are missing.

The crash log content tests verify that the "Application Specific Information" section contains the full ASan error report with the specific error type (e.g., `heap-buffer-overflow`, `heap-use-after-free`, `stack-buffer-overflow`, `stack-use-after-scope`). Rust's sanitizer runtime exports the `___crashreporter_info__` nlist symbol, which exc_handler reads directly.

## Rust TSan integration tests (tsan_exc_handler.rs)

4 tests that build a standalone Rust `tsan-crash-dummy` binary with `-Zsanitizer=thread -Zbuild-std --target aarch64-apple-darwin` and run it under `exc_handler` to verify handling of ThreadSanitizer-detected data races.

Tests skip if the build fails (missing `rust-src` component or no `-Zbuild-std` support) or entitlements are missing.

The crash log content tests verify that the "Application Specific Information" section contains the TSan data race report.

## C ASan integration tests (c_asan_exc_handler.rs)

8 tests that build a C `c-asan-crash-dummy` binary with `clang -fsanitize=address` and run it under `exc_handler` to verify handling of ASan-detected memory errors from C binaries (heap overflow, heap use-after-free, stack overflow, stack use-after-scope).

The binary is built via `make` on demand. Tests skip if clang is unavailable or entitlements are missing.

These tests exercise the `__DATA,__crash_info` Mach-O section extraction path — clang's sanitizer runtime uses the modern `crashreporter_annotations_t` struct rather than the `___crashreporter_info__` nlist symbol used by Rust's runtime.

## C TSan integration tests (c_tsan_exc_handler.rs)

4 tests that build a C `c-tsan-crash-dummy` binary with `clang -fsanitize=thread` and run it under `exc_handler` to verify handling of TSan-detected data races from C binaries (data race on global, data race on heap).

The binary is built via `make` on demand. Tests skip if clang is unavailable or entitlements are missing.

Like the C ASan tests, these exercise the `__crash_info` section extraction path.

## C UBSan integration tests (c_ubsan_exc_handler.rs)

6 tests that build a C `c-ubsan-crash-dummy` binary with `clang -fsanitize=undefined -fno-sanitize-recover=undefined` and run it under `exc_handler` to verify handling of UBSan-detected undefined behavior from C binaries (shift overflow, signed integer overflow, division by zero).

The `-fno-sanitize-recover=undefined` flag is required because UBSan's default behavior is to print and continue — this flag makes it abort so exc_handler can catch the crash.

The binary is built via `make` on demand. Tests skip if clang is unavailable or entitlements are missing.

Like the C ASan and TSan tests, these exercise the `__crash_info` section extraction path.

## C integer sanitizer integration tests (c_intsan_exc_handler.rs)

8 tests that build a C `c-intsan-crash-dummy` binary with `clang -fsanitize=integer -fno-sanitize-recover=integer` and run it under `exc_handler` to verify handling of integer sanitizer-detected errors from C binaries (unsigned integer overflow, unsigned shift base overflow, implicit unsigned integer truncation, implicit signed integer truncation).

The `-fsanitize=integer` group covers checks NOT included in `-fsanitize=undefined`: `unsigned-integer-overflow`, `unsigned-shift-base`, `implicit-unsigned-integer-truncation`, and `implicit-signed-integer-truncation`. The `-fno-sanitize-recover=integer` flag is required to abort on error.

The binary is built via `make` on demand. Tests skip if clang is unavailable or entitlements are missing.

Like the other Apple clang sanitizer tests, these exercise the `__crash_info` section extraction path.

## C CFI integration tests (c_cfi_exc_handler.rs)

2 tests that build a C `c-cfi-crash-dummy` binary with Homebrew LLVM clang (`-fsanitize=cfi -fno-sanitize-trap=cfi -flto -fvisibility=hidden`) and run it under `exc_handler` to verify handling of Control Flow Integrity violations from C binaries (indirect call type mismatch).

CFI requires Homebrew LLVM clang — Apple clang does not support `-fsanitize=cfi`. In diagnostic mode (`-fno-sanitize-trap=cfi`), the UBSan runtime is linked and populates `___crashreporter_info__` with the CFI error report before aborting. This means CFI tests exercise the `___crashreporter_info__` nlist symbol extraction path — the same mechanism used by Rust sanitizer runtimes — from a C binary.

The binary is built via `make` on demand. Tests skip if Homebrew LLVM clang is not installed or entitlements are missing.

## Toolchain coverage

The Rust and C (clang) sanitizer test suites together provide full coverage of exc_handler's two crash reporter info extraction mechanisms:

| Toolchain | Tests | Extraction Mechanism |
|-----------|-------|---------------------|
| Rust nightly (`-Zsanitizer=*`) | 12 (8 ASan + 4 TSan) | `___crashreporter_info__` nlist symbol |
| Apple clang (`-fsanitize=*`) | 26 (8 ASan + 4 TSan + 6 UBSan + 8 IntSan) | `__DATA,__crash_info` section |
| Homebrew LLVM clang (`-fsanitize=cfi`) | 2 (CFI) | `___crashreporter_info__` nlist symbol (via UBSan runtime) |

GCC sanitizer tests are not included — Homebrew GCC on macOS does not ship sanitizer runtime libraries, and GCC's sanitizer instrumentation is ABI-incompatible with clang's runtimes.

## macOS Tahoe 26.x: Sanitizer runtime initialization issues

A regression in macOS Tahoe's dyld breaks sanitizer runtime initialization. See [apple-sanitizer-tahoe-bug.md](../apple-sanitizer-tahoe-bug.md) for full root cause analysis with backtraces and disassembly.

### With Xcode 26.4 RC (Apple clang 21) — recommended

Xcode 26.4 fixes Apple clang's ASan and TSan runtimes. Expected test results:

| Test suite | Status | Notes |
|---|---|---|
| `asan_exc_handler` (Rust ASan) | Pass | Rust ships independent ASan runtime |
| `tsan_exc_handler` (Rust TSan) | **Fail** | Rust's TSan runtime lacks `_dyld_get_dyld_header`; crashes during init |
| `c_asan_exc_handler` (C ASan) | Pass | Fixed in Apple clang 21 |
| `c_tsan_exc_handler` (C TSan) | Pass | Fixed in Apple clang 21 |
| `c_ubsan_exc_handler` (C UBSan) | Pass | UBSan was never affected |
| `c_intsan_exc_handler` (C IntSan) | Pass | IntSan was never affected |
| `c_cfi_exc_handler` (C CFI) | Pass | Uses Homebrew LLVM |

### With Xcode 26.3 (Apple clang 17)

| Test suite | Status | Issue |
|---|---|---|
| `asan_exc_handler` (Rust ASan) | Pass | Rust ships independent ASan runtime |
| `tsan_exc_handler` (Rust TSan) | **Fail** | TSan crash affects all runtimes |
| `c_asan_exc_handler` (C ASan) | **Fail** (Apple clang) / Pass (Homebrew LLVM) | Apple ASan deadlocks; Homebrew ASan works |
| `c_tsan_exc_handler` (C TSan) | **Fail** | TSan crash affects all runtimes |
| `c_ubsan_exc_handler` (C UBSan) | **Fail** (Apple clang) / Pass (Homebrew LLVM) | Apple UBSan hangs due to shared ASan init path; Homebrew works |
| `c_intsan_exc_handler` (C IntSan) | Pass (both) | IntSan not affected |
| `c_cfi_exc_handler` (C CFI) | Pass | Already uses Homebrew LLVM |

**Workaround for Xcode 26.3 C ASan/UBSan tests:** Create `test-fixtures/local.mk` (gitignored) with `CC = /opt/homebrew/opt/llvm/bin/clang` to use Homebrew LLVM. See the [test fixtures README](../test-fixtures/README.md) for details.

**Rust TSan (no workaround yet):** Rust nightly's TSan runtime (`librustc-nightly_rt.tsan.dylib`, LLVM 22.1.0) lacks `_dyld_get_dyld_header` and crashes during init on Tahoe regardless of Xcode version. The fix has landed upstream in LLVM ([`2e7d07a3`](https://github.com/llvm/llvm-project/commit/2e7d07a33725a82ecfc514e27f047ece3ff13d4c)) but has not yet been released. Rust TSan tests will fail until the next Rust nightly picks up this commit.
