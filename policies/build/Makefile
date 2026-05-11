CLANG ?= clang
SRC ?= ../code/block_af_alg.bpf.c
OUT_DIR ?= /output
OUT ?= $(OUT_DIR)/program.bpf.o
TARGET_ARCH ?= x86
INCLUDES ?= -I/usr/include

.PHONY: build clean

build: $(OUT)

$(OUT): $(SRC)
	mkdir -p $(OUT_DIR)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) $(INCLUDES) -Wall -Werror -c $(SRC) -o $(OUT)

clean:
	rm -f $(OUT)
