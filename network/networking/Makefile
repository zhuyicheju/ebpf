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
APP_CFLAGS = -Wall -g $(INCLUDES) $(shell pkg-config --cflags libbpf)
APP_LDFLAGS = $(shell pkg-config --libs libbpf) -lbpf -lelf -lz -lpthread

all: networking

$(BPF_OBJ): $(BPF_SRC).bpf.c vmlinux.h Makefile
	$(info CLANG $(BPF_SRC).bpf.c -> $@)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC).bpf.c -o $@
$(BPF_SKEL): $(BPF_OBJ) Makefile
	$(info GEN HDR $@ from $(BPF_OBJ))
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $@
$(APP_BINARY): $(APP_SRC) $(BPF_SKEL) Makefile
	$(info CC $(APP_SRC) -> $@)
	$(GCC) $(APP_CFLAGS) $(APP_SRCS) $(APP_LDFLAGS) -o $@

clean:
	$(info CLEAN)
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(APP_BINARY) *~

.PHONY: all clean
