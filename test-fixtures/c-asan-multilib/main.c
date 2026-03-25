/*
 * Multi-library ASan crash dummy: loads two ASan-instrumented dynamic libraries,
 * calls the safe one first, then the buggy one. Used to verify that
 * exc_handler extracts the sanitizer report from the correct module.
 *
 * When --wait is passed, prints PID to stdout and blocks until SIGUSR1.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void safe_heap_operation(void);
extern void buggy_heap_overflow(void);

static void sigusr1_handler(int sig) { (void)sig; }

static void wait_for_signal(void) {
    signal(SIGUSR1, sigusr1_handler);
    printf("%d\n", getpid());
    fflush(stdout);
    pause();
}

int main(int argc, char *argv[]) {
    int wait = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--wait") == 0)
            wait = 1;
    }

    if (wait)
        wait_for_signal();

    /* Call the safe library first — its ASan instrumentation is loaded */
    safe_heap_operation();

    /* Now crash in the buggy library */
    buggy_heap_overflow();

    return 0;
}
