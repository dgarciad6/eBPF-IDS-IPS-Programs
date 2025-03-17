# Compiler
CC := clang

# Compiling Options
CFLAGS := -Wall -O2 -g \
    -I/usr/include/$(shell uname -m)-linux-gnu/ \
    -D__KERNEL__ -D__ASM_SYSREG_H \
    -target bpf -S -emit-llvm

# Main Rule
%: %.c
	$(CC) $(CFLAGS) $< -o $@.ll
	llc -march=bpf -filetype=obj -o $@.bpf $@.ll
	rm -f $@.ll
	@echo " $@.bpf compilation completed."

# Clean generated files
clean:
	rm -f *.ll *.bpf

# Rule to force the clean process
.PHONY: % clean
