# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

BPF_SRC = networking

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
GCC ?= gcc
INCLUDES = -I.
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -Wall
BPF_OBJ = $(BPF_SRC).bpf.o
BPF_SKEL = $(BPF_SRC).skel.h

APP_SRCS = networking.c
APP_BINARY = networking
APP_CFLAGS = -Wall -g $(INCLUDES)
APP_LDFLAGS = -lbpf -lelf -lz

all: networking

$(BPF_OBJ): $(BPF_SRC).bpf.c vmlinux.h Makefile
	$(info CLANG $(BPF_SRC).bpf.c -> $@)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
$(BPF_SKEL): $(BPF_OBJ) $(BPFTOOL) Makefile
	$(info GEN HDR $@ from $<)
	$(BPFTOOL) gen skeleton $< > $@
$(APP_BINARY): $(APP_SRC) $(BPF_SKEL) Makefile
	$(info CC $(APP_SRC) -> $@)
	$(GCC) $(APP_CFLAGS) $< $(APP_LDFLAGS) -o $@

clean:
	$(info CLEAN)
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(APP_BINARY) *~

.PHONY: all clean
