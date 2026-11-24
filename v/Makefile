V ?= v
VFLAGS ?=
R2 ?= radare2
R2_LIB ?= $(shell $(R2) -H R2_LIBDIR 2>/dev/null)/libr_core.$(shell $(R2) -H R2_LIBEXT 2>/dev/null)
BUILD_DIR ?= ../.build

.PHONY: all test integration

all:
	mkdir -p "$(BUILD_DIR)"
	$(V) $(VFLAGS) -o "$(BUILD_DIR)/r2pipe-v-example" test.v

test:
	$(V) $(VFLAGS) test r2pipe

integration:
	R2PIPE_TEST_R2="$(R2)" R2PIPE_TEST_LIBRARY="$(R2_LIB)" R2PIPE_TEST_HTTP=1 $(V) $(VFLAGS) test r2pipe
