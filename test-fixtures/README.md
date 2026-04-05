# Test Fixtures

Standalone test binaries that trigger sanitizer-detected errors. Used by integration tests and useful for manual testing of sanitizer crash handling.

Includes both Rust crates (compiled with nightly `-Zsanitizer=*` flags) and C binaries (compiled with `clang -fsanitize=*`). The Rust and C variants exercise different crash reporter info extraction mechanisms in exc_handler:

- **Rust sanitizer runtimes** export the `___crashreporter_info__` nlist symbol
- **Apple clang sanitizer runtimes** (ASan, TSan, UBSan, IntSan) use the `__DATA,__crash_info` Mach-O section (`crashreporter_annotations_t` struct)
- **Homebrew LLVM clang CFI** (in diagnostic mode) links the UBSan runtime which populates `___crashreporter_info__`

Together these three toolchains provide full coverage of exc_handler's sanitizer crash report extraction. GCC is not supported — Homebrew GCC on macOS does not ship sanitizer runtime libraries (`libasan`, `libtsan`), and GCC's sanitizer instrumentation is ABI-incompatible with clang's runtimes. Since CrashRustler is macOS-only (Mach exception handling), and clang is the native macOS C/C++ compiler with production sanitizer support, GCC sanitizer coverage is not applicable.

### macOS Tahoe 26.x: Sanitizer runtime initialization issues

A regression in macOS Tahoe's dyld (dyld-1376.6) breaks sanitizer runtime initialization during startup. See [apple-sanitizer-tahoe-bug.md](../apple-sanitizer-tahoe-bug.md) for full root cause analysis.

**Xcode 26.4 RC (Apple clang 21) fixes Apple's ASan and TSan runtimes.** Update Xcode to resolve all Apple clang sanitizer issues.

**Xcode 26.3 ASan workaround:** The Makefiles for `c-asan`, `c-tsan`, `c-ubsan`, and `c-intsan` support a local compiler override via a gitignored `test-fixtures/local.mk` file. To use Homebrew LLVM clang instead of Apple clang:

```makefile
# test-fixtures/local.mk (create this file — it is gitignored)
CC = /opt/homebrew/opt/llvm/bin/clang
```

This is no longer necessary with Xcode 26.4 but remains supported for environments that cannot upgrade.

**Rust TSan and Homebrew LLVM TSan remain affected** on Tahoe even with Xcode 26.4. These runtimes lack `_dyld_get_dyld_header` and crash during init. The fix has landed upstream ([`2e7d07a3`](https://github.com/llvm/llvm-project/commit/2e7d07a33725a82ecfc514e27f047ece3ff13d4c)) but has not yet been released. **Rust ASan** is unaffected (Rust ships its own independent ASan runtime).

## Rust: asan-crash-dummy

Rust crate excluded from the workspace (`[workspace] exclude` in root `Cargo.toml`) because it must be compiled with sanitizer-specific `RUSTFLAGS`.

**Crash modes:** `heap_overflow`, `heap_uaf`, `stack_overflow`, `stack_uaf`

```bash
cd test-fixtures/asan
RUSTFLAGS="-Zsanitizer=address" cargo +nightly build --release
```

Run under `exc_handler`:

```bash
./target/release/exc_handler ./target/asan/release/asan-crash-dummy heap_uaf
echo $?  # 6 (SIGABRT, not exploitable)
```

## Rust: tsan-crash-dummy

Rust crate excluded from the workspace. TSan on macOS requires `-Zbuild-std` and the `rust-src` component:

**Crash modes:** `data_race`, `heap_race`

```bash
rustup component add rust-src
cd test-fixtures/tsan
RUSTFLAGS="-Zsanitizer=thread" cargo +nightly build --release -Zbuild-std --target aarch64-apple-darwin
```

Run under `exc_handler`:

```bash
./target/release/exc_handler ./target/tsan/aarch64-apple-darwin/release/tsan-crash-dummy data_race
echo $?  # 6 (SIGABRT, not exploitable)
```

## C: c-asan-crash-dummy

C binary compiled with `clang -fsanitize=address`. Exercises the `__crash_info` section extraction path in exc_handler.

**Crash modes:** `heap_overflow`, `heap_uaf`, `stack_overflow`, `stack_uaf`

```bash
cd test-fixtures/c-asan
make
```

Run under `exc_handler`:

```bash
./target/release/exc_handler ./test-fixtures/c-asan/c-asan-crash-dummy heap_overflow
echo $?  # 6 (SIGABRT, not exploitable)
```

## C: c-tsan-crash-dummy

C binary compiled with `clang -fsanitize=thread`. Exercises the `__crash_info` section extraction path in exc_handler.

**Crash modes:** `data_race`, `heap_race`

```bash
cd test-fixtures/c-tsan
make
```

Run under `exc_handler`:

```bash
./target/release/exc_handler ./test-fixtures/c-tsan/c-tsan-crash-dummy data_race
echo $?  # 6 (SIGABRT, not exploitable)
```

## C: c-ubsan-crash-dummy

C binary compiled with `clang -fsanitize=undefined -fno-sanitize-recover=undefined`. Exercises the `__crash_info` section extraction path in exc_handler. The `-fno-sanitize-recover=undefined` flag is required because UBSan's default behavior is to print and continue — this flag makes it abort so exc_handler can catch the crash.

**Crash modes:** `shift_overflow`, `signed_overflow`, `divide_by_zero`

```bash
cd test-fixtures/c-ubsan
make
```

Run under `exc_handler`:

```bash
./target/release/exc_handler ./test-fixtures/c-ubsan/c-ubsan-crash-dummy shift_overflow
echo $?  # 6 (SIGABRT, not exploitable)
```

## C: c-intsan-crash-dummy

C binary compiled with `clang -fsanitize=integer -fno-sanitize-recover=integer`. Exercises the `__crash_info` section extraction path in exc_handler. The `-fsanitize=integer` group covers checks NOT included in `-fsanitize=undefined`: unsigned integer overflow, unsigned shift base overflow, and implicit integer truncation.

**Crash modes:** `unsigned_overflow`, `unsigned_shift_base`, `implicit_unsigned_truncation`, `implicit_signed_truncation`

```bash
cd test-fixtures/c-intsan
make
```

Run under `exc_handler`:

```bash
./target/release/exc_handler ./test-fixtures/c-intsan/c-intsan-crash-dummy unsigned_overflow
echo $?  # 6 (SIGABRT, not exploitable)
```

## C: c-cfi-crash-dummy

C binary compiled with Homebrew LLVM clang (`-fsanitize=cfi -fno-sanitize-trap=cfi -flto -fvisibility=hidden`). Apple clang does not support CFI. In diagnostic mode (`-fno-sanitize-trap=cfi`), the UBSan runtime is linked and populates `___crashreporter_info__` before aborting — this exercises the nlist symbol extraction path from a C binary.

CFI requires `-flto` (whole-program type information) and `-fvisibility=hidden`. Only `cfi-icall` (indirect call type mismatch) is testable in C; other CFI sub-checks (`cfi-vcall`, `cfi-nvcall`, `cfi-derived-cast`, `cfi-unrelated-cast`) require C++.

**Crash modes:** `cfi_icall`

```bash
cd test-fixtures/c-cfi
make
```

Run under `exc_handler`:

```bash
./target/release/exc_handler ./test-fixtures/c-cfi/c-cfi-crash-dummy cfi_icall
echo $?  # 6 (SIGABRT, not exploitable)
```

## C: c-asan-multilib (multi-module ASan)

Multiple ASan-instrumented C dynamic libraries linked into a single binary. Used to verify that `extract_crash_reporter_info()` correctly extracts the sanitizer error report from the ASan runtime when multiple instrumented modules are loaded but only one triggers a violation.

- `lib_safe.dylib` — performs valid heap operations (no violation)
- `lib_buggy.dylib` — triggers `heap-buffer-overflow`
- `main.c` — calls safe first, then buggy

```bash
cd test-fixtures/c-asan-multilib
make
```

Run under `exc_handler`:

```bash
./target/release/exc_handler ./test-fixtures/c-asan-multilib/c-asan-multilib-crash-dummy
echo $?  # 6 (SIGABRT, not exploitable)
```

Both `___crashreporter_info__` and `__DATA,__crash_info` reside in the single ASan runtime dylib (`libclang_rt.asan_osx_dynamic.dylib`), not in individual user modules. The iterative lookup in `extract_crash_reporter_info()` correctly finds the one populated instance regardless of how many instrumented modules are loaded.

## Example crash log excerpt (sanitizer report)

```
Exploitability:  NOT_EXPLOITABLE
  EXC_CRASH (undemuxed) — not exploitable

Application Specific Information:
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x606000000300 ...
WRITE of size 1 at 0x606000000300 thread T0
    #0 0x... in do_heap_overflow crash_dummy.c:20
    ...
SUMMARY: AddressSanitizer: heap-buffer-overflow crash_dummy.c:20 in do_heap_overflow
...

Thread 0 Crashed:
...
```
