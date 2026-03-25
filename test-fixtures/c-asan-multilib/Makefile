-include ../local.mk
CC ?= clang
CFLAGS = -fsanitize=address -O1 -fno-omit-frame-pointer -g
TARGET = c-asan-multilib-crash-dummy
LIB_SAFE = lib_safe.dylib
LIB_BUGGY = lib_buggy.dylib

all: $(TARGET)

$(LIB_SAFE): lib_safe.c
	$(CC) $(CFLAGS) -shared -install_name @rpath/$(LIB_SAFE) -o $@ $<

$(LIB_BUGGY): lib_buggy.c
	$(CC) $(CFLAGS) -shared -install_name @rpath/$(LIB_BUGGY) -o $@ $<

$(TARGET): main.c $(LIB_SAFE) $(LIB_BUGGY)
	$(CC) $(CFLAGS) -o $@ main.c -L. -l_safe -l_buggy -Wl,-rpath,$(CURDIR)

clean:
	rm -rf $(TARGET) $(LIB_SAFE) $(LIB_BUGGY) *.dSYM

.PHONY: all clean
