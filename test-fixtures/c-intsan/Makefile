-include ../local.mk
CC ?= clang
CFLAGS = -fsanitize=integer -fno-sanitize-recover=integer -O1 -fno-omit-frame-pointer -g
TARGET = c-intsan-crash-dummy

.PHONY: all clean

all: $(TARGET)

$(TARGET): crash_dummy.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
