# Sanitizer Runtime Deadlock/Crash on macOS Tahoe 26.x

## Summary

A regression in macOS Tahoe's dyld (dyld-1376.6) breaks sanitizer runtime initialization. The `dyld_shared_cache_iterate_text_swift` function — new in Tahoe — calls `_Block_copy` and `dispatch_once` where previous macOS versions did not, re-entering sanitizer-intercepted functions (`malloc`, `dispatch_once`) before the sanitizer runtimes have completed their own initialization. This causes AddressSanitizer to deadlock and ThreadSanitizer to crash with `EXC_BAD_ACCESS` at startup, before user code reaches `main()`.

**Xcode 26.4 RC (Apple clang 21.0.0) resolves both issues for Apple's bundled runtimes** by adding the `_dyld_get_dyld_header()` fast path, which bypasses `dyld_shared_cache_iterate_text` entirely. However, third-party TSan runtimes (Rust nightly, Homebrew LLVM) remain affected because they lack this API and still traverse the shared cache during init.

## Environment

### Affected (Xcode 26.3)

| Component | Version |
|---|---|
| macOS | Tahoe 26.4 (Build 25E241) |
| Kernel | Darwin 25.4.0, xnu-12377.101.14~18/RELEASE_ARM64_T6041 |
| Xcode | 26.3 (Build 17C529) |
| Apple clang | 17.0.0 (clang-1700.6.4.2) |
| macOS SDK | 26.2 |
| dyld | dyld-1376.6 |
| Architecture | ARM64 (Apple Silicon) |
| ASan runtime | `libclang_rt.asan_osx_dynamic.dylib` (SHA256: `96f04575544d5b9a947e8560b6e5c2429ee34adeb999897ce79525b0ac39a9be`) |

### Fixed (Xcode 26.4 RC)

| Component | Version |
|---|---|
| Xcode | 26.4 (Build 17E192) |
| Apple clang | 21.0.0 (clang-2100.0.123.102) |
| macOS SDK | 26.4 |

### Still affected (third-party runtimes on Tahoe, even with Xcode 26.4 dyld)

| Component | Version | Issue |
|---|---|---|
| Homebrew LLVM | 22.1.1 | TSan crashes (no `_dyld_get_dyld_header`); ASan works (has `__mod_init_func`) |
| Rust nightly | 1.96.0-nightly (LLVM 22.1.0) | TSan crashes (no `_dyld_get_dyld_header`); ASan works (ships own runtime) |

## Reproducer

Any program compiled with `-fsanitize=address` or `-fsanitize=thread` triggers the bug, including trivial programs that perform no memory operations:

```c
// test.c
#include <stdio.h>
int main() { printf("hello\n"); return 0; }
```

```bash
# AddressSanitizer: hangs forever (never prints "hello")
clang -fsanitize=address -o test_asan test.c
./test_asan    # hangs

# ThreadSanitizer: crashes immediately with EXC_BAD_ACCESS
clang -fsanitize=thread -o test_tsan test.c
./test_tsan    # segfault (exit 139)
```

UBSan (`-fsanitize=undefined`) is **not** affected.

## Root Cause: AddressSanitizer Deadlock

A reentrant call to `__asan_init` during dyld library initialization causes a single-threaded deadlock on a non-recursive `StaticSpinMutex`.

### Backtrace (captured via `lldb -b -p <PID>`)

```
* thread #1, stop reason = signal SIGSTOP
  * frame #0:  libsystem_kernel.dylib`swtch_pri + 8
    frame #1:  libsystem_pthread.dylib`cthread_yield + 36
    frame #2:  libclang_rt.asan_osx_dynamic.dylib`__sanitizer::internal_sched_yield() + 16
    frame #3:  libclang_rt.asan_osx_dynamic.dylib`__sanitizer::StaticSpinMutex::LockSlow() + 64
    frame #4:  libclang_rt.asan_osx_dynamic.dylib`__asan_init.cold.1 + 68
    frame #5:  libclang_rt.asan_osx_dynamic.dylib`__asan::AsanInitFromRtl() + 40
    frame #6:  libclang_rt.asan_osx_dynamic.dylib`__sanitizer_mz_malloc + 36
    frame #7:  libsystem_malloc.dylib`_malloc_zone_malloc_instrumented_or_legacy + 152
    frame #8:  libsystem_malloc.dylib`_malloc_type_malloc_outlined + 96
    frame #9:  libsystem_blocks.dylib`_Block_copy + 84
    frame #10: Dyld`dyld_shared_cache_iterate_text_swift + 28
    frame #11: libclang_rt.asan_osx_dynamic.dylib`__sanitizer::get_dyld_hdr() + 236
    frame #12: libclang_rt.asan_osx_dynamic.dylib`__sanitizer::MemoryMappingLayout::Next() + 148
    frame #13: libclang_rt.asan_osx_dynamic.dylib`__sanitizer::MemoryRangeIsAvailable() + 172
    frame #14: libclang_rt.asan_osx_dynamic.dylib`__asan::InitializeShadowMemory() + 112
    frame #15: libclang_rt.asan_osx_dynamic.dylib`__asan::AsanInitInternal() (.cold.1) + 260
    frame #16: libclang_rt.asan_osx_dynamic.dylib`__asan::AsanInitInternal() + 52
    frame #17: libclang_rt.asan_osx_dynamic.dylib`__asan_init.cold.1 + 40
    frame #18: libclang_rt.asan_osx_dynamic.dylib`__asan::AsanInitFromRtl() + 40
    frame #19: libclang_rt.asan_osx_dynamic.dylib`wrap_malloc_default_zone + 16
    frame #20: libsystem_malloc.dylib`__malloc_init + 1524
    frame #21: libSystem.B.dylib`libSystem_initializer + 204
    frame #22: dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers() + 444
    ...
    frame #33: dyld`start + 6904
```

### Call chain analysis

```
dyld4::start
 → libSystem_initializer                              (dyld runs library initializers)
  → __malloc_init                                      (libsystem_malloc initialization)
   → wrap_malloc_default_zone                          (ASan's malloc zone interposer)
    → AsanInitFromRtl                                  (first entry — acquires init lock)
     → AsanInitInternal
      → InitializeShadowMemory
       → MemoryRangeIsAvailable
        → MemoryMappingLayout::Next
         → get_dyld_hdr
          → GetDyldImageHeaderViaSharedCache
           → dyld_shared_cache_iterate_text
            → dyld_shared_cache_iterate_text_swift     ← NEW in Tahoe's dyld-1376.6
             → _Block_copy                             ← copies the ObjC block, triggers malloc
              → _malloc_zone_malloc_instrumented_or_legacy
               → __sanitizer_mz_malloc                 (ASan's malloc interceptor)
                → AsanInitFromRtl                      ← REENTRANT ENTRY (lock already held)
                 → StaticSpinMutex::LockSlow           ← SPINS FOREVER (same thread holds lock)
```

### Regression trigger

The regression is in `dyld_shared_cache_iterate_text_swift`, a new function in Tahoe's dyld-1376.6. The ASan runtime's `GetDyldImageHeaderViaSharedCache()` passes an Objective-C block to `dyld_shared_cache_iterate_text`. On previous macOS versions, this function invoked the block directly as a stack block. On Tahoe, it dispatches to `dyld_shared_cache_iterate_text_swift`, which calls `_Block_copy` on the block parameter, triggering a heap allocation via `malloc`. Since ASan has already interposed the malloc zone (but hasn't finished initializing), this `malloc` call re-enters `AsanInitFromRtl`, which attempts to acquire the `StaticSpinMutex` that is already held by the outer init on the same thread, resulting in an infinite spin.

### Disassembly confirmation

Disassembly of Apple's `GetDyldImageHeaderViaSharedCache` (at offset `0x571c8` in `libclang_rt.asan_osx_dynamic.dylib`) confirms:
- The function creates an `__NSConcreteStackBlock` referencing the block invoke at offset `0x57bf0`
- It calls `dyld_shared_cache_iterate_text` (stub at `0x83940`) with this block
- There is **no** check for `_dyld_get_dyld_header` (a newer dyld API that would bypass the block-based iteration entirely)
- Apple's runtime has **no** `__mod_init_func` section, so ASan is lazily initialized via `wrap_malloc_default_zone` during `__malloc_init`, creating the reentrant condition

## Root Cause: ThreadSanitizer Crash

TSan crashes with a null pointer dereference during initialization, caused by a similar dyld interaction.

### Backtrace (captured via `lldb`)

```
* thread #1, stop reason = EXC_BAD_ACCESS (code=1, address=0x0)
  * frame #0:  libclang_rt.tsan_osx_dynamic.dylib`__tsan::SlotLock(__tsan::ThreadState*) + 28
    frame #1:  libclang_rt.tsan_osx_dynamic.dylib`__tsan::Release() + 48
    frame #2:  libclang_rt.tsan_osx_dynamic.dylib`wrap_dispatch_once + 176
    frame #3:  libdyld.dylib`dyldFrameworkIntrospectionVtable() + 44
    frame #4:  libdyld.dylib`dyld_shared_cache_iterate_text + 108
    frame #5:  libclang_rt.tsan_osx_dynamic.dylib`__sanitizer::get_dyld_hdr() + 236
    frame #6:  libclang_rt.tsan_osx_dynamic.dylib`__sanitizer::MemoryMappingLayout::Next() + 148
    frame #7:  libclang_rt.tsan_osx_dynamic.dylib`__tsan::CheckAndProtect() + 172
    frame #8:  libclang_rt.tsan_osx_dynamic.dylib`__tsan::InitializePlatform() + 40
    frame #9:  libclang_rt.tsan_osx_dynamic.dylib`__tsan::Initialize(__tsan::ThreadState*) + 264
    frame #10: libclang_rt.tsan_osx_dynamic.dylib`__tsan::ScopedInterceptor::ScopedInterceptor() + 108
    frame #11: libclang_rt.tsan_osx_dynamic.dylib`wrap_strlcpy + 88
    frame #12: libsystem_c.dylib`__guard_setup + 132
    frame #13: libsystem_c.dylib`_libc_initializer + 72
    frame #14: libSystem.B.dylib`libSystem_initializer + 168
    ...
    frame #26: dyld`start + 6904
```

Register state at crash: `x19 = 0x0000000000000000` (null `ThreadState*`).

### Call chain analysis

```
dyld4::start
 → libSystem_initializer
  → _libc_initializer
   → __guard_setup
    → wrap_strlcpy                                     (TSan's string interceptor)
     → ScopedInterceptor
      → __tsan::Initialize(ThreadState*)               (first entry — init incomplete)
       → InitializePlatform
        → CheckAndProtect
         → MemoryMappingLayout::Next
          → get_dyld_hdr
           → dyld_shared_cache_iterate_text
            → dyld_shared_cache_iterate_text_swift
             → dispatch_once                           (TSan intercepts dispatch_once)
              → wrap_dispatch_once
               → __tsan::Release(ThreadState*, ...)    (ThreadState* is NULL — init not done)
                → SlotLock(NULL)
                 → ldr x10, [x19]                     ← x19=0x0, EXC_BAD_ACCESS
```

TSan's `dispatch_once` interceptor fires during TSan's own initialization because `dyld_shared_cache_iterate_text_swift` uses `dispatch_once` internally. TSan attempts to track the `dispatch_once` synchronization, but `ThreadState` hasn't been allocated yet (init is still in progress), resulting in a null pointer dereference.

**Note:** With Xcode 26.3, the TSan crash affects all tested clang toolchains, including Homebrew LLVM 22.1.1 and Rust nightly's TSan runtime. With Xcode 26.4 RC, Apple's TSan runtime is fixed (see below), but Homebrew LLVM and Rust nightly TSan runtimes remain affected.

## How Xcode 26.4 RC Fixes Apple's Runtimes

Apple clang 21.0.0 (Xcode 26.4 RC, Build 17E192) resolves both the ASan deadlock and the TSan crash by adding `_dyld_get_dyld_header()` — a direct dyld API that returns the dyld Mach-O header without iterating the shared cache. This bypasses `dyld_shared_cache_iterate_text` (and its `_Block_copy`/`dispatch_once` calls) entirely.

Confirmed via symbol table inspection:

```
$ nm -arch arm64 libclang_rt.tsan_osx_dynamic.dylib | grep dyld_get_dyld_header
                 U __dyld_get_dyld_header    ← NEW in clang 21, absent in clang 17
```

The `get_dyld_hdr()` function in Apple clang 21's runtime now checks for `_dyld_get_dyld_header` first and only falls through to `dyld_shared_cache_iterate_text` if the API is unavailable. Since Tahoe's dyld provides this symbol (confirmed via `dlsym`), the block-based iteration path is never reached.

## Why Homebrew LLVM 22.1.1 ASan Is Not Affected

Homebrew's `libclang_rt.asan_osx_dynamic.dylib` (LLVM 22.1.1) has a `__mod_init_func` section:

```
$ otool -arch arm64 -l libclang_rt.asan_osx_dynamic.dylib | grep -A 5 "__mod_init_func"
  sectname __mod_init_func
   segname __DATA_CONST
```

This gives it a proper dyld module initializer that runs **after** `libSystem_initializer` completes. By the time ASan's `get_dyld_hdr` calls `dyld_shared_cache_iterate_text_swift`, `libSystem` is fully initialized and `_Block_copy`'s `malloc` call goes through the normal allocator (not ASan's interposed zone).

Apple's clang 17 runtime had **no** `__mod_init_func` — it was lazily initialized via `wrap_malloc_default_zone` during `__malloc_init`, which runs inside `libSystem_initializer`, before `libSystem` init was complete.

## Why Homebrew LLVM and Rust Nightly TSan Are Still Affected

Despite the Xcode 26.4 dyld fix, TSan runtimes from Homebrew LLVM 22.1.1 and Rust nightly (LLVM 22.1.0) **still crash** on Tahoe. These runtimes:

1. Have **no `__mod_init_func`** — TSan is initialized lazily during `libSystem_initializer` when `wrap_strlcpy` intercepts `__guard_setup`
2. Have **no `_dyld_get_dyld_header`** — they call `dyld_shared_cache_iterate_text` which triggers `dispatch_once`, re-entering the TSan interceptor with null `ThreadState*`

Confirmed via symbol table inspection:

```
$ nm -arch arm64 librustc-nightly_rt.tsan.dylib | grep dyld_get_dyld_header
(no output — symbol not present)

$ nm -arch arm64 /opt/homebrew/.../libclang_rt.tsan_osx_dynamic.dylib | grep dyld_get_dyld_header
(no output — symbol not present)
```

The fix has landed in upstream LLVM as commit [`2e7d07a3`](https://github.com/llvm/llvm-project/commit/2e7d07a33725a82ecfc514e27f047ece3ff13d4c), which adds the `_dyld_get_dyld_header` check to `compiler-rt/lib/sanitizer_common/sanitizer_procmaps_mac.cpp`. This has not yet been picked up by Homebrew LLVM or Rust nightly as of March 2026.

## Why Rust's ASan Runtime Is Not Affected

Rust nightly ships its own independent ASan runtime (`librustc-nightly_rt.asan.dylib`), separate from Apple's `libclang_rt.asan_osx_dynamic.dylib`. Rust's ASan runtime is not affected by the deadlock on any Tahoe version.

## Affected Components

### With Xcode 26.3 (Apple clang 17)

| Sanitizer | Apple clang 17 | Homebrew LLVM 22.1.1 | Rust nightly (LLVM 22.1.0) |
|---|---|---|---|
| ASan | **Deadlock** (infinite spin in `StaticSpinMutex::LockSlow`) | Works (has `__mod_init_func`) | Works (ships independent `librustc-nightly_rt.asan.dylib`) |
| TSan | **Crash** (`EXC_BAD_ACCESS` at `0x0` in `SlotLock`) | **Crash** (same) | **Crash** (same — all TSan runtimes affected) |
| UBSan | Works | Works | N/A |
| IntSan | Works | Works | N/A |
| CFI | N/A (Apple clang does not support CFI) | Works | N/A |

### With Xcode 26.4 RC (Apple clang 21)

| Sanitizer | Apple clang 21 | Homebrew LLVM 22.1.1 | Rust nightly (LLVM 22.1.0) |
|---|---|---|---|
| ASan | **Fixed** (has `_dyld_get_dyld_header`) | Works (has `__mod_init_func`) | Works (ships independent runtime) |
| TSan | **Fixed** (has `_dyld_get_dyld_header`) | **Crash** (no `_dyld_get_dyld_header`) | **Crash** (no `_dyld_get_dyld_header`) |
| UBSan | Works | Works | N/A |
| IntSan | Works | Works | N/A |
| CFI | N/A | Works | N/A |

## Impact

These bugs affect sanitizer runtime initialization on macOS Tahoe, not user code. The regressions are triggered by changes in Tahoe's dyld (dyld-1376.6) that introduced `dyld_shared_cache_iterate_text_swift` — a new dispatch target that calls `_Block_copy` and `dispatch_once` where previous macOS versions did not.

**With Xcode 26.3:** ASan and TSan are completely broken for Apple clang. ASan deadlocks at startup; TSan crashes with SIGSEGV. All TSan runtimes (Apple, Homebrew, Rust) are affected.

**With Xcode 26.4 RC:** Apple's runtimes are fixed via the `_dyld_get_dyld_header()` fast path. However, **TSan runtimes from Homebrew LLVM and Rust nightly remain broken** because they lack this API. The fix has landed upstream in LLVM ([`2e7d07a3`](https://github.com/llvm/llvm-project/commit/2e7d07a33725a82ecfc514e27f047ece3ff13d4c)) but has not yet been released in Homebrew LLVM or Rust nightly.

## Upstream LLVM Comparison

Three different mitigation strategies exist across the runtimes we tested:

1. **`_dyld_get_dyld_header()` fast path (Apple clang 21; landed upstream)**: Apple's clang 21 runtime (Xcode 26.4 RC) imports `_dyld_get_dyld_header` — a Tahoe-era dyld API that returns the dyld Mach-O header directly without iterating the shared cache. This completely bypasses `dyld_shared_cache_iterate_text` and its problematic `_Block_copy`/`dispatch_once` calls. The same fix has landed in upstream LLVM ([`2e7d07a3`](https://github.com/llvm/llvm-project/commit/2e7d07a33725a82ecfc514e27f047ece3ff13d4c)) but has not yet been picked up by Homebrew LLVM (22.1.1) or Rust nightly (LLVM 22.1.0), leaving their TSan runtimes vulnerable until the next release.

2. **`__mod_init_func` section (Homebrew LLVM ASan only)**: Homebrew's ASan runtime includes a `__mod_init_func` section, giving it a proper dyld module initializer that runs **after** `libSystem_initializer` completes. This avoids the ASan reentrant `malloc` deadlock. Apple's clang 17 ASan runtime and all TSan runtimes lack this section.

3. **Independent runtime (Rust ASan only)**: Rust nightly ships its own `librustc-nightly_rt.asan.dylib`, separate from Apple's `libclang_rt.asan_osx_dynamic.dylib`. Rust's ASan runtime is unaffected on all Tahoe versions.

For TSan, the only effective fix is `_dyld_get_dyld_header()` — `__mod_init_func` does not help because TSan's init is triggered by `wrap_strlcpy` intercepting `__guard_setup` during `_libc_initializer`, which runs before any module initializers. Only avoiding the `dyld_shared_cache_iterate_text` call path entirely (via `_dyld_get_dyld_header`) prevents the `dispatch_once` reentrance.

## Workarounds

### Update to Xcode 26.4 (recommended)

Updating to Xcode 26.4 RC (Apple clang 21.0.0) fixes both ASan and TSan for Apple clang. This is the primary resolution for C/C++ code compiled with Apple's toolchain.

### ASan workaround for Xcode 26.3 (C code only)

On Xcode 26.3, C sanitizer test fixtures can be compiled with Homebrew LLVM clang instead of Apple clang. This project supports this via a gitignored `test-fixtures/local.mk` file:

```makefile
# test-fixtures/local.mk (gitignored — local override only)
CC = /opt/homebrew/opt/llvm/bin/clang
```

The C sanitizer Makefiles include this file with `-include ../local.mk` and use `CC ?= clang`, so the override takes effect when the file exists and falls through to Apple clang when it doesn't. This workaround is no longer necessary with Xcode 26.4.

### TSan workaround for Rust nightly and Homebrew LLVM

There is currently no workaround for Rust nightly's or Homebrew LLVM's ThreadSanitizer runtimes on macOS Tahoe, even with Xcode 26.4. The `dispatch_once` interception crash affects these runtimes because they lack the `_dyld_get_dyld_header` fast path. The fix has landed upstream in LLVM ([`2e7d07a3`](https://github.com/llvm/llvm-project/commit/2e7d07a33725a82ecfc514e27f047ece3ff13d4c)) but has not yet been released. Rust TSan tests will fail on Tahoe until the next Homebrew LLVM and Rust nightly releases pick up this commit.

### Rust ASan

Rust nightly ships its own independent ASan runtime (`librustc-nightly_rt.asan.dylib`), which is not affected by the deadlock on any Tahoe version. Rust ASan tests pass.

## Suggested Fixes

### Apple's runtimes (resolved in Xcode 26.4 RC)

Apple chose fix #3 below. Both ASan and TSan runtimes in Apple clang 21.0.0 now import `_dyld_get_dyld_header`, bypassing the problematic `dyld_shared_cache_iterate_text` path entirely.

### Upstream LLVM (landed, pending release)

The fix has landed in upstream LLVM as commit [`2e7d07a3`](https://github.com/llvm/llvm-project/commit/2e7d07a33725a82ecfc514e27f047ece3ff13d4c), which adds the `_dyld_get_dyld_header()` fast path to `compiler-rt/lib/sanitizer_common/sanitizer_procmaps_mac.cpp`. This is the same approach Apple used in clang 21 (Xcode 26.4 RC).

As of March 2026, this commit has not yet been picked up by:
- **Homebrew LLVM** (current: 22.1.1)
- **Rust nightly** (current: LLVM 22.1.0)

Once the next releases of these toolchains incorporate this commit, the TSan crash on macOS Tahoe will be resolved.
