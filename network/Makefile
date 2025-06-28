# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

SRC_DIR = networking

BPF_SRC = networking

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
GCC ?= gcc
INCLUDES = -I$(SRC_DIR)
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -Wall
BPF_OBJ = $(SRC_DIR)/$(BPF_SRC).bpf.o
BPF_SKEL = $(SRC_DIR)/$(BPF_SRC).skel.h

APP_SRCS = $(SRC_DIR)/networking.c
APP_BINARY = $(SRC_DIR)/networking
APP_CFLAGS = -Wall -g $(INCLUDES) $(shell pkg-config --cflags libbpf)
APP_LDFLAGS = $(shell pkg-config --libs libbpf) -lbpf -lelf -lz -lpthread

all: $(APP_BINARY)

$(BPF_OBJ): $(SRC_DIR)/$(BPF_SRC).bpf.c $(SRC_DIR)/vmlinux.h Makefile
	$(info CLANG $(SRC_DIR)/$(BPF_SRC).bpf.c -> $@)
	$(CLANG) $(BPF_CFLAGS) -c $(SRC_DIR)/$(BPF_SRC).bpf.c -o $@
$(BPF_SKEL): $(BPF_OBJ) Makefile
	$(info GEN HDR $@ from $(BPF_OBJ))
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $@
$(APP_BINARY): $(APP_SRCS) $(BPF_SKEL) Makefile
	$(info CC $(APP_SRCS) -> $@)
	$(GCC) $(APP_CFLAGS) $(APP_SRCS) $(APP_LDFLAGS) -o $@

clean:
	$(info CLEAN)
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(APP_BINARY) *~

.PHONY: all clean
