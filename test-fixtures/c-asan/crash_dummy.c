/*
 * ASan crash dummy: triggers AddressSanitizer-detected memory errors.
 *
 * Used by integration tests to exercise exc_handler's handling of ASan-detected
 * crashes from clang-compiled C binaries. Accepts one CLI arg to select the
 * crash mode.
 *
 * Must be compiled with: clang -fsanitize=address -O1 -fno-omit-frame-pointer
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

__attribute__((noinline))
static void do_heap_overflow(void) {
    volatile char *buf = (volatile char *)malloc(64);
    if (!buf) _exit(3);
    buf[64] = 0x41; /* 1 byte past the end */
    free((void *)buf);
}

__attribute__((noinline))
static void do_heap_uaf(void) {
    volatile char *buf = (volatile char *)malloc(64);
    if (!buf) _exit(3);
    memset((void *)buf, 0xBB, 64);
    free((void *)buf);
    /* read through dangling pointer */
    volatile char val = buf[0];
    (void)val;
}

/* Helper to get a pointer past the buffer end without triggering
 * compile-time warnings. The noinline prevents the compiler from
 * seeing through the indirection. */
__attribute__((noinline))
static char *offset_ptr(char *p, int n) {
    return p + n;
}

__attribute__((noinline))
static void do_stack_overflow(void) {
    char buf[16];
    memset(buf, 0, sizeof(buf));
    char *oob = offset_ptr(buf, 16);
    *oob = 0x42; /* 1 byte past the end */
}

__attribute__((noinline))
static void do_stack_uaf(void) {
    volatile char *ptr;
    {
        volatile char local[16];
        memset((void *)local, 0xCC, sizeof(local));
        ptr = local;
    }
    /* local is out of scope */
    volatile char val = ptr[0];
    (void)val;
}

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
        fprintf(stderr,
            "Usage: c-asan-crash-dummy [--wait] "
            "<heap_overflow|heap_uaf|stack_overflow|stack_uaf>\n");
        return 2;
    }

    if (wait)
        wait_for_signal();

    if (strcmp(mode, "heap_overflow") == 0)
        do_heap_overflow();
    else if (strcmp(mode, "heap_uaf") == 0)
        do_heap_uaf();
    else if (strcmp(mode, "stack_overflow") == 0)
        do_stack_overflow();
    else if (strcmp(mode, "stack_uaf") == 0)
        do_stack_uaf();
    else {
        fprintf(stderr, "Unknown crash mode: %s\n", mode);
        return 2;
    }

    return 0;
}
