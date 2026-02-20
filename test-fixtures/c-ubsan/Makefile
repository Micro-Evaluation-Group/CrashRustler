-include ../local.mk
CC ?= clang
CFLAGS = -fsanitize=undefined -fno-sanitize-recover=undefined -O1 -fno-omit-frame-pointer -g
TARGET = c-ubsan-crash-dummy

.PHONY: all clean

all: $(TARGET)

$(TARGET): crash_dummy.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
