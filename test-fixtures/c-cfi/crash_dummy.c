/*
 * CFI crash dummy: triggers Control Flow Integrity violations.
 *
 * Used by integration tests to exercise exc_handler's handling of CFI-detected
 * violations from clang-compiled C binaries. Accepts one CLI arg to select the
 * crash mode.
 *
 * Must be compiled with Homebrew LLVM clang (Apple clang does not support CFI):
 *   /opt/homebrew/opt/llvm/bin/clang -fsanitize=cfi -fno-sanitize-trap=cfi \
 *       -flto -fvisibility=hidden -O1 -fno-omit-frame-pointer -g
 *
 * Flags explained:
 *   -fsanitize=cfi              Enable CFI checks
 *   -fno-sanitize-trap=cfi      Use diagnostic mode (prints report + aborts)
 *                                instead of trap mode (which just emits brk)
 *   -flto                       Required — CFI needs whole-program type info
 *   -fvisibility=hidden         Required — CFI needs hidden default visibility
 *
 * In diagnostic mode, the UBSan runtime is linked and populates
 * ___crashreporter_info__ with the CFI error report before aborting.
 *
 * When --wait is passed, prints its PID to stdout and blocks until SIGUSR1
 * is received, allowing exc_handler to attach via PID before the crash.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void sigusr1_handler(int sig) { (void)sig; }

static void wait_for_signal(void) {
    signal(SIGUSR1, sigusr1_handler);
    printf("%d\n", getpid());
    fflush(stdout);
    pause();
}

typedef int (*binop_fn)(int, int);

__attribute__((noinline))
static int addi(int a, int b) {
    return a + b;
}

__attribute__((noinline))
static float addf(float a, float b) {
    return a + b;
}

/*
 * cfi-icall violation: call a function through a pointer with the wrong type.
 * addf has signature (float, float) -> float, but we call it as (int, int) -> int.
 */
__attribute__((noinline))
static void do_cfi_icall(void) {
    /* Suppress type mismatch warning — this is intentional. */
    binop_fn fn = (binop_fn)(void *)addf;
    volatile int result = fn(1, 2);
    (void)result;
}

/*
 * Prevent the linker from stripping addi as unused — it's needed to make
 * addf reachable through a different type, which is what CFI validates.
 */
__attribute__((used))
static int (*keep_addi)(int, int) = addi;

int main(int argc, char *argv[]) {
    int wait = 0;
    const char *mode = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--wait") == 0)
            wait = 1;
        else if (!mode)
            mode = argv[i];
    }

    if (!mode) {
        fprintf(stderr, "Usage: c-cfi-crash-dummy [--wait] <cfi_icall>\n");
        return 2;
    }

    if (wait)
        wait_for_signal();

    if (strcmp(mode, "cfi_icall") == 0)
        do_cfi_icall();
    else {
        fprintf(stderr, "Unknown crash mode: %s\n", mode);
        return 2;
    }

    return 0;
}
