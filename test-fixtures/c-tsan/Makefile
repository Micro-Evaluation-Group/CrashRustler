-include ../local.mk
CC ?= clang
CFLAGS = -fsanitize=thread -O1 -fno-omit-frame-pointer -g
TARGET = c-tsan-crash-dummy

.PHONY: all clean

all: $(TARGET)

$(TARGET): crash_dummy.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
