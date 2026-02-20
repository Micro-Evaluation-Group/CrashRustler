# CFI requires Homebrew LLVM clang — Apple clang does not support -fsanitize=cfi.
# Detect Homebrew LLVM path for both ARM64 and x86_64 installs.
HOMEBREW_LLVM_ARM64 = /opt/homebrew/opt/llvm/bin/clang
HOMEBREW_LLVM_X86 = /usr/local/opt/llvm/bin/clang

# Try ARM64 path first, then x86_64 path
CC := $(shell if [ -x "$(HOMEBREW_LLVM_ARM64)" ]; then echo "$(HOMEBREW_LLVM_ARM64)"; \
              elif [ -x "$(HOMEBREW_LLVM_X86)" ]; then echo "$(HOMEBREW_LLVM_X86)"; \
              else echo "NOT_FOUND"; fi)

CFLAGS = -fsanitize=cfi -fno-sanitize-trap=cfi -flto -fvisibility=hidden -O1 -fno-omit-frame-pointer -g
TARGET = c-cfi-crash-dummy

.PHONY: all clean

all: $(TARGET)

$(TARGET): crash_dummy.c
ifeq ($(CC),NOT_FOUND)
	@echo "SKIP: Homebrew LLVM clang not found (Apple clang does not support CFI)" >&2
	@exit 1
endif
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
