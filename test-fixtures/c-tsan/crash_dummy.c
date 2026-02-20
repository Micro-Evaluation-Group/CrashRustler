/*
 * TSan crash dummy: triggers ThreadSanitizer-detected data races.
 *
 * Used by integration tests to exercise exc_handler's handling of TSan-detected
 * crashes from clang-compiled C binaries. Accepts one CLI arg to select the
 * crash mode.
 *
 * Must be compiled with: clang -fsanitize=thread -O1 -fno-omit-frame-pointer
 *
 * When --wait is passed, prints its PID to stdout and blocks until SIGUSR1
 * is received, allowing exc_handler to attach via PID before the crash.
 */

#include <pthread.h>
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

/* --- data_race: two threads increment a shared global without synchronization --- */

static volatile long counter = 0;

static void *data_race_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < 1000; i++) {
        counter++;
    }
    return NULL;
}

__attribute__((noinline))
static void do_data_race(void) {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, data_race_thread, NULL);
    pthread_create(&t2, NULL, data_race_thread, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    (void)counter;
}

/* --- heap_race: two threads read/write shared heap allocation without synchronization --- */

static void *heap_race_thread(void *arg) {
    volatile long *p = (volatile long *)arg;
    for (int i = 0; i < 1000; i++) {
        (*p)++;
    }
    return NULL;
}

__attribute__((noinline))
static void do_heap_race(void) {
    volatile long *data = (volatile long *)malloc(sizeof(long));
    if (!data) _exit(3);
    *data = 0;

    pthread_t t1, t2;
    pthread_create(&t1, NULL, heap_race_thread, (void *)data);
    pthread_create(&t2, NULL, heap_race_thread, (void *)data);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    (void)*data;
    free((void *)data);
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
        fprintf(stderr, "Usage: c-tsan-crash-dummy [--wait] <data_race|heap_race>\n");
        return 2;
    }

    if (wait)
        wait_for_signal();

    if (strcmp(mode, "data_race") == 0)
        do_data_race();
    else if (strcmp(mode, "heap_race") == 0)
        do_heap_race();
    else {
        fprintf(stderr, "Unknown crash mode: %s\n", mode);
        return 2;
    }

    return 0;
}
