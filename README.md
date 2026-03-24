# CrashRustler

[![CI](https://github.com/Micro-Evaluation-Group/CrashRustler/actions/workflows/ci.yml/badge.svg)](https://github.com/Micro-Evaluation-Group/CrashRustler/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024_edition-orange.svg)](https://www.rust-lang.org/)
[![macOS](https://img.shields.io/badge/platform-macOS-lightgrey.svg)]()
[![ARM64 | x86_64](https://img.shields.io/badge/arch-ARM64_%7C_x86__64-green.svg)]()

A Rust reimplementation of Apple's [CrashWrangler](https://download.developer.apple.com/macOS/CrashWrangler/CrashWrangler.zip) (requires developer.apple.com login). CrashRustler captures, analyzes, and classifies macOS crash reports — including a drop-in `exc_handler` binary for intercepting Mach exceptions and triaging exploitability.

## Features

- **exc_handler binary** — Mach exception handler that intercepts crashes, generates backtraces for all threads, classifies exploitability, and writes crash logs with coded exit values
- **Sanitizer-aware crash reporting** — Automatically extracts crash reporter messages via two mechanisms: `___crashreporter_info__` nlist symbol (Rust sanitizer runtimes, CFI diagnostic mode) and `__DATA,__crash_info` Mach-O section (clang sanitizer runtimes). Captures up to 64 KB of full AddressSanitizer, UBSan, TSan, integer sanitizer, and CFI error reports including error type, access details, shadow memory state, and allocation/deallocation backtraces. Works with Rust, Apple clang, and Homebrew LLVM clang binaries compiled with sanitizers
- **Stack unwinding** — DWARF CFI (.eh_frame), Apple Compact Unwind (__unwind_info), and frame pointer walking with automatic fallback chain
- **Symbol resolution** — Resolves backtrace addresses to function names via Mach-O nlist symbol table parsing, with Rust and C++ demangling
- **Exploitability analysis** — Classifies crashes as exploitable, not exploitable, or unknown based on exception type, access type, disassembly, and backtrace heuristics, with architecture-specific page sizes, instruction classifiers, trap detection, and address validation dispatched on the target's CPU type
- Full crash report state: process info, bundle identifier, exception details, thread backtraces, binary images, VM regions, and mapped memory
- Remote process introspection: binary image enumeration via `dyld_all_image_infos`, thread enumeration via `task_threads()`, register state capture
- Mach exception type and signal decoding (`EXC_BAD_ACCESS`, `SIGSEGV`, etc.)
- Exception code interpretation (e.g., `KERN_INVALID_ADDRESS at 0x...`)
- Crashed thread instruction disassembly (via capstone)
- Problem dictionary generation for crash deduplication
- ARM64 and x86_64 register state formatting
- Zero-FFI, architecture-agnostic library design — all Mach/system calls are isolated in the binary crate; the library dispatches all architecture-specific logic on `CpuType` at runtime, enabling cross-architecture crash analysis (e.g. analyzing ARM64 crash data on an x86_64 host)

## Requirements

- Rust nightly (2024 edition features)
- macOS (Mach exception handling is macOS-only)
- ARM64 or x86_64

## Build

```bash
cargo build --release
```

## Usage

```bash
# Run a program under exception monitoring
./target/release/exc_handler /path/to/program arg1 arg2
echo $?
```

See [exc_handler documentation](src/bin/exc_handler/README.md) for CLI flags, environment variables, codesigning, crash log format, and sanitizer crash report details.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No crash — child exited normally |
| `1`–`99` | Crash signal number — not exploitable (e.g., `11` = SIGSEGV) |
| `101`–`199` | Signal + 100 — exploitable (e.g., `111` = exploitable SIGSEGV) |
| `-1` | Error |
| `-2` | Non-crash signal (SIGTERM, SIGKILL, etc.) |

## Library usage

The library crate has zero FFI calls and can be used independently for crash report analysis. All architecture-specific logic dispatches on `CpuType` at runtime, so crash data from ARM64 and x86_64 processes can be analyzed from any host:

```rust
use crashrustler::{CrashRustler, CrashParams, CpuType, ThreadState, ExceptionState};

let params = CrashParams {
    task: 0,
    pid: 1234,
    ppid: 1,
    uid: 501,
    is_64_bit: true,
    thread: 0,
    exception_type: 1, // EXC_BAD_ACCESS
    exception_codes: vec![1, 0x0000_DEAD], // KERN_INVALID_ADDRESS
    thread_state: ThreadState { flavor: 6, registers: vec![] },
    exception_state: ExceptionState { state: vec![], count: 0 },
    process_name: Some("MyApp".into()),
    executable_path: Some("/usr/local/bin/MyApp".into()),
    r_process_pid: -1,
    date: Some("2025-01-15 10:30:45.1234 -0800".into()),
    awake_system_uptime: 3600,
    cpu_type: CpuType::ARM64,
};

let cr = CrashRustler::new(params);
println!("{}", cr.signal_name());                 // "SIGSEGV"
println!("{}", cr.exception_type_description());   // "EXC_BAD_ACCESS"
println!("{}", cr.exception_codes_description());  // "KERN_INVALID_ADDRESS at 0x000000000000dead"
```

### Exploitability classification

```rust
use crashrustler::CpuType;
use crashrustler::exploitability::{classify_exception, ClassifyConfig};

let result = classify_exception(
    1,                          // EXC_BAD_ACCESS
    &[2, 0x4141_4141],         // KERN_PROTECTION_FAILURE at 0x41414141
    "str x0, [x1]",            // crashing instruction (write)
    0x1_0000_0100,             // PC
    CpuType::ARM64,            // target CPU type
    &ClassifyConfig::default(),
);

println!("{:?}", result.rating);  // Exploitable
println!("signal: {}", result.signal);
for msg in &result.messages {
    println!("  {msg}");
}
```

### Stack unwinding

The `unwind` module provides a `MemoryReader` trait so all unwinding algorithms live in the zero-FFI library crate. The binary crate provides a `RemoteMemoryReader` implementation wrapping `mach_vm_read()`.

Three unwinding strategies are tried in order for each frame (matching Apple's `libunwind`):

1. **Compact Unwind** — Apple's `__unwind_info` section (first-level index, regular and compressed second-level pages, common and page-local encoding tables).
2. **DWARF CFI** — `.eh_frame` section with CIE/FDE records and CFA state machine
3. **Frame Pointer Walking** — FP chain traversal as a fallback

The unwinder supports both ARM64 and x86_64, with runtime-dispatched compact unwind decoders (based on `CpuType`), architecture-abstracted DWARF register maps, and PAC bit stripping (ARM64). All unwinding logic is architecture-agnostic — the library can unwind crash data from any supported architecture regardless of the host it runs on.

## Key types

| Type | Description |
|------|-------------|
| `CrashRustler` | Main crash report struct holding all crash state |
| `CrashParams` | Pre-gathered crash data passed to `CrashRustler::new()` |
| `ExceptionType` | Mach exception types (`EXC_BAD_ACCESS`, `EXC_CRASH`, etc.) |
| `CpuType` | CPU architecture constants (x86, x86_64, ARM, ARM64, PowerPC) |
| `ExploitabilityRating` | Crash exploitability classification |
| `AccessType` | Memory access type at crash site (Read/Write/Exec) |
| `BinaryImage` | A loaded binary image in the crashed process |
| `BacktraceFrame` | Single frame in a thread's backtrace |
| `ThreadBacktrace` | A thread's full backtrace with metadata |
| `ThreadState` | Register state for a thread |
| `ExceptionState` | Mach exception port state |
| `MappedMemory` | Memory-mapped region from the crashed process |
| `unwind::MemoryReader` | Trait for reading target process memory (no FFI in lib) |
| `unwind::BinaryImageInfo` | Binary image with cached section locations for unwinding |
| `unwind::RegisterContext` | Arch-abstracted register state indexed by DWARF register number |

## Module structure

```
src/                     — Library crate (zero FFI) + binary entry points
src/unwind/              — Stack unwinding (DWARF CFI, Compact Unwind, frame pointers)
src/bin/exc_handler/     — Mach exception handler binary (all FFI lives here)
src/bin/crash_dummy.rs   — Test crash generator binary
test-fixtures/asan/      — Rust ASan crash dummy crate (not a workspace member)
test-fixtures/tsan/      — Rust TSan crash dummy crate (not a workspace member)
test-fixtures/c-asan/    — C ASan crash dummy (clang -fsanitize=address)
test-fixtures/c-tsan/    — C TSan crash dummy (clang -fsanitize=thread)
test-fixtures/c-ubsan/   — C UBSan crash dummy (clang -fsanitize=undefined)
test-fixtures/c-intsan/  — C integer sanitizer crash dummy (clang -fsanitize=integer)
test-fixtures/c-cfi/     — C CFI crash dummy (Homebrew LLVM clang -fsanitize=cfi)
tests/                   — Integration tests
```

See [exc_handler README](src/bin/exc_handler/README.md), [test fixtures README](test-fixtures/README.md), and [tests README](tests/README.md) for detailed documentation of each area.

## Testing

```bash
cargo test                              # 315 lib + 33 bin + 14 doc + 64 integration (426 total)
cargo test --test exc_handler           # Fork+exec integration tests (11 tests)
cargo test --test attach_exc_handler    # Attach-mode integration tests (8 tests, requires entitlement)
cargo test --test launchd_exc_handler   # Launchd service mode tests (5 tests, requires entitlement)
cargo test --test asan_exc_handler      # Rust ASan integration tests (8 tests)
cargo test --test tsan_exc_handler      # Rust TSan integration tests (4 tests)
cargo test --test c_asan_exc_handler    # C ASan integration tests (8 tests)
cargo test --test c_tsan_exc_handler    # C TSan integration tests (4 tests)
cargo test --test c_ubsan_exc_handler   # C UBSan integration tests (6 tests)
cargo test --test c_intsan_exc_handler  # C integer sanitizer integration tests (8 tests)
cargo test --test c_cfi_exc_handler     # C CFI integration tests (2 tests, requires Homebrew LLVM)
cargo clippy                            # Lint (zero warnings)
cargo fmt -- --check                    # Formatting check
```

Sanitizer integration tests cover three toolchains — Rust nightly, Apple clang, and Homebrew LLVM clang — which together exercise both crash reporter info extraction mechanisms (`___crashreporter_info__` nlist symbol and `__DATA,__crash_info` Mach-O section). CFI tests require Homebrew LLVM (Apple clang does not support CFI) and skip gracefully if unavailable. GCC sanitizer support is not available on macOS (no runtime libraries shipped by Homebrew GCC).

> **macOS Tahoe 26.x:** A dyld regression on Tahoe breaks sanitizer runtime initialization. Xcode 26.4 RC fixes Apple clang's runtimes, but Rust nightly's and Homebrew LLVM's TSan runtimes remain affected. See [Known Issues](#known-issues) and [apple-sanitizer-tahoe-bug.md](apple-sanitizer-tahoe-bug.md) for details.

See [tests README](tests/README.md) for detailed test structure and skip conditions.

## CI

GitHub Actions CI runs on every push, pull request, and manual dispatch. Parallel lint jobs: `cargo fmt`, `cargo clippy`, `cargo audit` (RustSec CVE checks), and `cargo machete` (unused dependency detection). Test jobs run on `macos-26` and `macos-15` (both ARM64 Apple Silicon) after lints pass.

A weekly scheduled `cargo audit` run catches new advisories between CI runs. Dependabot is configured for weekly Cargo and GitHub Actions dependency updates.

Integration tests that require Mach exception port privileges skip automatically on CI runners. The CI workflow is at [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Releases

Tagging a version (e.g., `git tag v0.2.0 && git push --tags`) triggers the release workflow at [`.github/workflows/release.yml`](.github/workflows/release.yml). The workflow verifies that `Cargo.toml`'s version matches the tag (e.g., tag `v0.2.0` requires `version = "0.2.0"`), then runs the full test suite, security audit, builds a release binary, generates rustdoc, and creates a GitHub release with auto-generated release notes and two attached artifacts:

- `exc_handler-<tag>-aarch64-apple-darwin.tar.gz` — release binary
- `docs-<tag>.tar.gz` — rustdoc HTML documentation

## Known Issues

### Sanitizer runtime initialization broken on macOS Tahoe 26.x

A regression in macOS Tahoe's dyld (dyld-1376.6) breaks sanitizer runtime initialization. The new `dyld_shared_cache_iterate_text_swift` function calls `_Block_copy` and `dispatch_once` where previous macOS versions did not, re-entering sanitizer-intercepted functions before init completes.

**Xcode 26.4 RC (Apple clang 21) resolves this** for Apple's bundled runtimes by adding `_dyld_get_dyld_header()`, which bypasses the problematic code path. Update Xcode to 26.4 to fix Apple clang ASan and TSan.

**Rust nightly TSan and Homebrew LLVM TSan remain affected** on Tahoe even with Xcode 26.4 — their runtimes lack `_dyld_get_dyld_header` and still crash during init. Rust ASan is unaffected (ships its own independent runtime). The fix has landed upstream in LLVM ([`2e7d07a3`](https://github.com/llvm/llvm-project/commit/2e7d07a33725a82ecfc514e27f047ece3ff13d4c)) but has not yet been released in Homebrew LLVM or Rust nightly.

See [apple-sanitizer-tahoe-bug.md](apple-sanitizer-tahoe-bug.md) for full analysis, backtraces, disassembly, and suggested fixes.

## Documentation

Rustdoc is published automatically to GitHub Pages on every push to `main`:

**[API Documentation](https://micro-evaluation-group.github.io/CrashRustler/crashrustler/)**

To build locally:

```bash
cargo doc --open
```

All public types and methods have rustdoc documentation with examples.
