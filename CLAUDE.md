# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
cargo build          # Debug build
cargo build --release # Release build
cargo run            # Build and run
cargo test           # Run all tests
cargo test <name>    # Run a single test by name
cargo clippy         # Lint
cargo fmt            # Format code
cargo fmt -- --check # Check formatting without modifying
cargo doc --open     # Generate and open rustdoc
```

## Project Overview

CrashRustler is a Rust reimplementation of CrashWrangler's `CrashReport` Objective-C class. It captures all state needed to represent a macOS crash report — process info, exception details, thread backtraces, binary image mappings, and crash analysis metadata.

- **Crate structure:** Library crate (zero FFI, split across 13 modules in `src/` including `src/unwind/`) + three binary crates (`src/main.rs` stub, `src/bin/exc_handler/` Mach exception handler, `src/bin/crash_dummy.rs` test crash generator)
- **Edition:** Rust 2024
- **Dependencies:** `chrono` (date formatting), `capstone` (disassembly in exc_handler binary)
- **Architecture support:** ARM64 + x86_64, runtime-dispatched per-arch compact unwind decoding, exploitability analysis, register formatting, and disassembly
- **Toolchain:** Nightly Rust (uses Rust 2024 edition features)
- **Design principle:** All FFI is isolated in the `exc_handler` binary crate — the library has zero FFI calls

### Key Public Types

| Type | Description |
|------|-------------|
| `CrashRustler` | Main crash report struct holding all crash state |
| `CrashParams` | Pre-gathered crash data passed to `CrashRustler::new()` |
| `ExceptionType` | Mach exception types (`EXC_BAD_ACCESS`, etc.) |
| `CpuType` | CPU architecture constants (x86, ARM, PowerPC) |
| `ExploitabilityRating` | Crash exploitability classification (Exploitable/NotExploitable/Unknown) |
| `AccessType` | Memory access type at crash site (Read/Write/Exec/Recursion/Unknown) |
| `BinaryImage` | A loaded binary image in the crashed process |
| `BacktraceFrame` | Single frame in a thread's backtrace |
| `ThreadBacktrace` | A thread's full backtrace with metadata |
| `ThreadState` | Register state for a thread |
| `ExceptionState` | Mach exception port state |
| `PlistValue` | Apple plist value types for crash report metadata |
| `MappedMemory` | Memory-mapped region from the crashed process |
| `unwind::MemoryReader` | Trait for reading target process memory (no FFI in lib) |
| `unwind::BinaryImageInfo` | Binary image with cached section locations for unwinding |
| `unwind::RegisterContext` | Arch-abstracted register state indexed by DWARF register number |
| `unwind::UnwindError` | Errors from stack unwinding |

### Module Structure

```
src/
  lib.rs              — Crate docs, mod declarations, pub use re-exports
  types.rs            — ExceptionType, CpuType, ExploitabilityRating, AccessType, CrashParams,
                        BinaryImage, BacktraceFrame, ThreadBacktrace, ThreadState, ExceptionState,
                        VmRegion, PlistValue, MappedMemory
  exploitability.rs   — Exploitability classification (classify_exception, is_stack_suspicious,
                        get_access_type_arm64, get_access_type_x86). All analysis dispatches on
                        CpuType at runtime — no compile-time arch assumptions. Ported from CrashWrangler.
  crash_rustler.rs    — CrashRustler struct definition, Default impl, mac_roman_to_char
  init.rs             — CrashRustler::new(CrashParams), new_from_corpse() — pure data, no FFI
  accessors.rs        — Getters/setters, bundle_identifier, is_x86_cpu, is_arm_cpu, sanitize_version
  formatting.rs       — Signal/exception descriptions, string utils, Apple path checks
  memory.rs           — Memory reading from MappedMemory, crash reporter info extraction
  backtrace.rs        — Binary image management, backtrace formatting, thread state description
  analysis.rs         — Crash analysis, path cleansing, dictionary/plist generation
  test_helpers.rs     — Shared test fixtures (cfg(test) only)
  dummy.rs            — ARM64 inline assembly crash tests (cfg(test, aarch64) only)
  main.rs             — Binary entry point (stub)
  bin/crash_dummy.rs  — Test binary that crashes on command (exit0/sigsegv/sigill/sigtrap/sigabrt/sigfpe)

src/unwind/           — Stack unwinding (DWARF CFI, Compact Unwind, frame pointers — zero FFI)
  mod.rs              — MemoryReader trait, BinaryImageInfo, unwind_thread() public API
  registers.rs        — RegisterContext: arch-abstracted register state indexed by DWARF reg number
  arch.rs             — ARM64 + x86_64 DWARF register maps, compact encoding decoders
  macho.rs            — Mach-O section finder (__unwind_info, __eh_frame, __text)
  compact_unwind.rs   — __unwind_info parser + register restoration (CpuType-dispatched decoding)
  dwarf_cfi.rs        — .eh_frame CIE/FDE parsing, CFA state machine
  dwarf_expr.rs       — DWARF expression evaluator (stack machine)
  frame_pointer.rs    — FP-chain walking (fallback unwinder)
  cursor.rs           — FrameCursor: drives compact → DWARF → FP fallback chain, PAC bit stripping

src/bin/exc_handler/  — Mach exception handler binary (all FFI lives here)
  main.rs             — Entry point, Config from CR_* env vars + CLI flags, fork+exec, attach mode
  ffi.rs              — All Mach + POSIX FFI bindings (ports, messaging, memory, process info)
  mach_msg.rs         — #[repr(C)] Mach message structs + dispatch (replaces MiG)
  handler.rs          — Exception handling, backtrace generation, symbol resolution, disassembly,
                        crash reporter info extraction (___crashreporter_info__ + __crash_info),
                        crash log writing
  remote_memory.rs    — RemoteMemoryReader: MemoryReader impl wrapping mach_vm_read()
  thread_enum.rs      — Thread enumeration via task_threads() + thread_get_state()
  image_enum.rs       — Binary image enumeration via dyld_all_image_infos, Mach-O nlist symbol
                        table parsing, symbol lookup by name (find_symbol_address),
                        large string reading (read_large_c_string), __crash_info section discovery

test-fixtures/asan/     — Standalone Rust ASan crash dummy crate (not a workspace member)
  Cargo.toml          — Minimal package, built on demand with -Zsanitizer=address
  src/main.rs         — Four crash modes: heap_overflow, heap_uaf, stack_overflow, stack_uaf

test-fixtures/tsan/     — Standalone Rust TSan crash dummy crate (not a workspace member)
  Cargo.toml          — Minimal package, built on demand with -Zsanitizer=thread -Zbuild-std
  src/main.rs         — Two crash modes: data_race, heap_race

test-fixtures/c-asan/   — C ASan crash dummy (compiled with clang -fsanitize=address)
  crash_dummy.c       — Four crash modes: heap_overflow, heap_uaf, stack_overflow, stack_uaf
  Makefile            — Builds with clang -fsanitize=address -O1 -fno-omit-frame-pointer -g

test-fixtures/c-tsan/   — C TSan crash dummy (compiled with clang -fsanitize=thread)
  crash_dummy.c       — Two crash modes: data_race, heap_race
  Makefile            — Builds with clang -fsanitize=thread -O1 -fno-omit-frame-pointer -g

test-fixtures/c-ubsan/  — C UBSan crash dummy (compiled with clang -fsanitize=undefined)
  crash_dummy.c       — Three crash modes: shift_overflow, signed_overflow, divide_by_zero
  Makefile            — Builds with clang -fsanitize=undefined -fno-sanitize-recover=undefined

test-fixtures/c-intsan/ — C integer sanitizer crash dummy (compiled with clang -fsanitize=integer)
  crash_dummy.c       — Four crash modes: unsigned_overflow, unsigned_shift_base, implicit_unsigned_truncation, implicit_signed_truncation
  Makefile            — Builds with clang -fsanitize=integer -fno-sanitize-recover=integer

test-fixtures/c-cfi/    — C CFI crash dummy (compiled with Homebrew LLVM clang -fsanitize=cfi)
  crash_dummy.c       — One crash mode: cfi_icall (indirect call type mismatch)
  Makefile            — Builds with Homebrew LLVM clang -fsanitize=cfi -fno-sanitize-trap=cfi -flto -fvisibility=hidden

test-fixtures/c-asan-multilib/ — Multi-module ASan crash dummy (two dylibs + main binary)
  lib_safe.c          — ASan-instrumented library with valid heap operations (no violation)
  lib_buggy.c         — ASan-instrumented library that triggers heap-buffer-overflow
  main.c              — Links both libraries, calls safe then buggy to verify correct report extraction
  Makefile            — Builds lib_safe.dylib, lib_buggy.dylib, and the main binary with -fsanitize=address

tests/
  exc_handler.rs        — Integration tests: launch exc_handler against crash_dummy, verify exit codes and crash logs
  asan_exc_handler.rs   — Rust ASan integration tests: build asan-crash-dummy, run under exc_handler, verify crash handling
  tsan_exc_handler.rs   — Rust TSan integration tests: build tsan-crash-dummy, run under exc_handler, verify crash handling
  c_asan_exc_handler.rs — C ASan integration tests: build c-asan-crash-dummy, run under exc_handler, verify __crash_info extraction
  c_tsan_exc_handler.rs  — C TSan integration tests: build c-tsan-crash-dummy, run under exc_handler, verify __crash_info extraction
  c_ubsan_exc_handler.rs  — C UBSan integration tests: build c-ubsan-crash-dummy, run under exc_handler, verify __crash_info extraction
  c_intsan_exc_handler.rs — C integer sanitizer integration tests: build c-intsan-crash-dummy, run under exc_handler, verify __crash_info extraction
  c_cfi_exc_handler.rs    — C CFI integration tests: build c-cfi-crash-dummy (Homebrew LLVM), run under exc_handler, verify ___crashreporter_info__ extraction
```

### Design Notes

- **Mach message structs** (`mach_msg.rs`): MIG wire format uses `#pragma pack(4)`, so all `#[repr(C)]` message structs must avoid fields with >4-byte alignment (e.g. use `[u32; 4]` instead of `[i64; 2]` for exception codes).
- **Architecture-agnostic library**: The library crate contains zero `#[cfg(target_arch)]` directives. All architecture-specific behavior (compact unwind decoding, exploitability analysis, PAC bit stripping, page size selection, instruction classification, trap instruction detection, non-canonical address heuristics) dispatches on `CpuType` at runtime. This allows crash data from any supported architecture to be analyzed regardless of the host architecture the library is compiled on. Only the `exc_handler` binary crate uses `#[cfg(target_arch)]` for host-specific FFI (Capstone disassembly mode, CPU type detection).
- **Unwind fallback chain**: For each frame, the cursor tries compact unwind → DWARF CFI → frame pointer walking, matching Apple's `libunwind` behavior.
- **Compact unwind format**: The `__unwind_info` parser implements the full Apple format (28-byte header, first-level index with sentinel exclusion, regular and compressed second-level pages). `decode_encoding()` dispatches to ARM64 or x86_64 decoders based on `CpuType`.
- **Section resolution is lazy**: `BinaryImageInfo` sections (`__unwind_info`, `__eh_frame`) are resolved on first access via `resolve_sections()` to avoid parsing Mach-O headers for images that are never hit during unwinding.
- **Symbol resolution**: Backtrace frames are resolved to function names via Mach-O nlist symbol table parsing from target process memory. Supports Rust and C++ demangling.
- **Crash reporter info extraction**: After enumerating binary images, `handler.rs` extracts crash reporter messages using two mechanisms: (1) scanning nlist symbol tables for the `___crashreporter_info__` symbol (a `const char*` used by Rust sanitizer runtimes), and (2) reading the `crashreporter_annotations_t` struct from `__DATA,__crash_info` Mach-O sections (the modern mechanism used by clang sanitizer runtimes). When found, the pointer is dereferenced and up to 64 KB is read from target process memory. The content appears in the crash log under "Application Specific Information:". Both symbols/sections reside in the single sanitizer runtime dylib (`libclang_rt.asan_osx_dynamic.dylib`), not in individual user modules — the iterative lookup over loaded images correctly finds the one populated instance regardless of how many sanitizer-instrumented modules are loaded. Verified with multi-module integration tests (`c-asan-multilib`).
- **Sanitizer crash dummies (Rust)**: The `test-fixtures/asan/` and `test-fixtures/tsan/` crates are intentionally excluded from the workspace (`[workspace] exclude` in root `Cargo.toml`) because they must be compiled with sanitizer-specific `RUSTFLAGS` which cannot be applied per-target within a single workspace. The integration tests build them on demand.
- **Sanitizer crash dummies (C, Apple clang)**: The `test-fixtures/c-asan/`, `test-fixtures/c-tsan/`, `test-fixtures/c-ubsan/`, and `test-fixtures/c-intsan/` directories contain C crash dummies compiled with Apple clang using `-fsanitize=address`, `-fsanitize=thread`, `-fsanitize=undefined`, and `-fsanitize=integer` respectively. These exercise the `__crash_info` section extraction path. UBSan and integer sanitizer require `-fno-sanitize-recover` to abort on error. The integer sanitizer covers checks unique to `-fsanitize=integer` that are not in `-fsanitize=undefined`: unsigned overflow, unsigned shift base, and implicit integer truncation.
- **Sanitizer crash dummies (C, Homebrew LLVM clang)**: The `test-fixtures/c-cfi/` directory contains a C crash dummy compiled with Homebrew LLVM clang (Apple clang does not support CFI). CFI requires `-flto -fvisibility=hidden` and uses diagnostic mode (`-fno-sanitize-trap=cfi`) which links the UBSan runtime and populates `___crashreporter_info__` before aborting. This exercises the nlist symbol extraction path from a C binary — the same mechanism used by Rust sanitizer runtimes.
- **Sanitizer toolchain coverage**: Sanitizer crash report extraction is tested with three toolchains: Rust nightly (uses `___crashreporter_info__` nlist symbol), Apple clang (uses `__DATA,__crash_info` Mach-O section), and Homebrew LLVM clang for CFI (uses `___crashreporter_info__` via the UBSan runtime). GCC is not supported — Homebrew GCC on macOS does not ship sanitizer runtime libraries (`libasan`, `libtsan`), and GCC's sanitizer instrumentation is ABI-incompatible with clang's runtimes.
- **macOS Tahoe 26.x sanitizer breakage**: A dyld regression in Tahoe breaks sanitizer runtime init. Xcode 26.4 RC (Apple clang 21) fixes Apple's ASan and TSan runtimes via `_dyld_get_dyld_header()`. Rust nightly's and Homebrew LLVM's TSan runtimes remain affected (no `_dyld_get_dyld_header`); fix landed upstream (LLVM commit `2e7d07a3`) but not yet released. Rust ASan is unaffected (ships own runtime). C sanitizer Makefiles support a `test-fixtures/local.mk` override (gitignored) to use Homebrew LLVM clang on Xcode 26.3. See `apple-sanitizer-tahoe-bug.md` for full analysis.
- **TSan build requirements**: TSan on macOS requires `-Zbuild-std --target aarch64-apple-darwin` in addition to `RUSTFLAGS="-Zsanitizer=thread"`, and the `rust-src` component must be installed. Rust's TSan runtime defaults to `abort_on_error=1` on macOS, so TSan crashes produce SIGABRT like ASan.

### Codesigning

The `exc_handler` binary requires the `com.apple.security.get-task-allow` entitlement for Mach exception port access (`task_for_pid`, `mach_vm_read`, etc.). Without signing, it can only inspect child processes via fork+exec, and even that may fail depending on SIP configuration.

- **Entitlements plist:** `entitlements/exc_handler.entitlements`
- **Build-time detection:** `build.rs` runs `security find-identity -p codesigning -v` and writes the identity to `$OUT_DIR/codesign-identity.txt`
- **Post-build signing:** `./scripts/codesign.sh [binary_path]` signs the binary with entitlements (defaults to `target/release/exc_handler`)
- Signing is optional — builds succeed without a certificate, and integration tests skip gracefully when entitlements are missing

#### Certificate setup

An Apple Development certificate requires the Apple WWDR intermediate certificate in the keychain to form a valid trust chain. If `security find-identity -p codesigning -v` shows `0 valid identities found` but `security find-identity` shows your certificate with `CSSMERR_TP_NOT_TRUSTED`, the WWDR intermediate is missing or expired.

To install the correct intermediate (G3, valid through 2030):

```bash
curl -O https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
security import AppleWWDRCAG3.cer -k ~/Library/Keychains/login.keychain-db -T /usr/bin/codesign
rm AppleWWDRCAG3.cer
```

Verify the identity is now trusted:

```bash
security find-identity -p codesigning -v
# Should show: 1) <HASH> "Apple Development: ..." with "1 valid identities found"
```

### CI

Four GitHub Actions workflows:

- **CI** (`.github/workflows/ci.yml`): Runs on push to `main`, pull requests, and manual dispatch. Parallel jobs: fmt check, clippy, `cargo audit` (RustSec CVE database), `cargo machete` (unused dependency detection). Test job (depends on fmt+clippy) runs on `macos-26`. Uses `dtolnay/rust-toolchain@nightly` and `Swatinem/rust-cache@v2`.

- **Release** (`.github/workflows/release.yml`): Triggers on tags matching `v*`. Verifies `Cargo.toml` version matches the tag (e.g., `v0.2.0` requires `version = "0.2.0"` in `Cargo.toml`). Runs fmt, clippy, audit, tests, then builds release binary, generates rustdoc, and creates GitHub release with artifacts. Uses `softprops/action-gh-release@v2`.

- **Security Audit** (`.github/workflows/audit.yml`): Scheduled weekly (Monday 08:00 UTC) `cargo audit` run against the RustSec advisory database.

- **Docs** (`.github/workflows/docs.yml`): Builds rustdoc on push to `main` and deploys to GitHub Pages. Published at `https://micro-evaluation-group.github.io/CrashRustler/crashrustler/`.

- **Stale** (`.github/workflows/stale.yml`): Scheduled weekly cleanup of stale issues (60 days) and PRs (60 days), with 14-day grace period before close. Issues/PRs labeled `pinned` or `security` are exempt.

**Dependency management:** Dependabot is configured (`.github/dependabot.yml`) for weekly Cargo and GitHub Actions dependency updates.

Integration tests that require debugger entitlements skip gracefully on CI runners. Sanitizer tests additionally skip if the nightly toolchain lacks sanitizer support or the binary fails to build.

### Test Structure

315 library unit tests across 30 submodules + 33 exc_handler binary unit tests + 14 doctests + 11 fork+exec integration tests + 8 attach-mode integration tests + 5 launchd service mode integration tests + 8 Rust ASan integration tests + 4 Rust TSan integration tests + 8 C ASan integration tests + 4 C ASan multi-module integration tests + 4 C TSan integration tests + 6 C UBSan integration tests + 8 C integer sanitizer integration tests + 2 C CFI integration tests (430 total). Tests are co-located with their source modules:

- **types.rs:** `types` (10 tests)
- **init.rs:** `tests` (7 tests)
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
- **dummy.rs:** 5 ARM64 crash tests via inline assembly (hardware crashes on ARM64 only)
- **tests/exc_handler.rs:** 11 fork+exec integration tests (exit codes, crash log creation/suppression, backtrace symbol validation)
- **tests/attach_exc_handler.rs:** 8 attach-mode integration tests (exit codes and crash log content for sigsegv/sigabrt/sigill, Rust ASan, C ASan via --attach-pid)
- **tests/launchd_exc_handler.rs:** 5 launchd service mode integration tests (exit codes, crash log content, duplicate name error handling via --launchd-name)
- **tests/asan_exc_handler.rs:** 8 Rust ASan integration tests (exit codes and crash log content for heap_overflow, heap_uaf, stack_overflow, stack_uaf)
- **tests/tsan_exc_handler.rs:** 4 Rust TSan integration tests (exit codes and crash log content for data_race, heap_race)
- **tests/c_asan_exc_handler.rs:** 8 C ASan integration tests (exit codes and crash log content via __crash_info extraction)
- **tests/c_asan_multilib_exc_handler.rs:** 4 C ASan multi-module integration tests (verifies correct crash report extraction when multiple ASan-instrumented dylibs are loaded)
- **tests/c_tsan_exc_handler.rs:** 4 C TSan integration tests (exit codes and crash log content via __crash_info extraction)
- **tests/c_ubsan_exc_handler.rs:** 6 C UBSan integration tests (exit codes and crash log content via __crash_info extraction)
- **tests/c_intsan_exc_handler.rs:** 8 C integer sanitizer integration tests (exit codes and crash log content via __crash_info extraction)
- **tests/c_cfi_exc_handler.rs:** 2 C CFI integration tests (exit codes and crash log content via ___crashreporter_info__ extraction, requires Homebrew LLVM)
- **src/bin/exc_handler/ffi.rs:** `tests` (14 tests — shell_escape_arg, parse_procargs2)
- **src/bin/exc_handler/handler.rs:** `tests` (8 tests — extract_pc register state parsing)
- **src/bin/exc_handler/image_enum.rs:** `tests` (11 tests — demangle_symbol, read_c_string, read_large_c_string)
