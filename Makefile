# Makefile
# Copyright (c) 2021, zhiayang
# Licensed under the Apache License Version 2.0.

CC                  ?= clang
CXX                 ?= clang++

WARNINGS        = -Wno-padded -Wno-cast-align -Wno-unreachable-code -Wno-packed -Wno-missing-noreturn -Wno-float-equal -Wno-unused-macros -Wextra -Wconversion -Wpedantic -Wall -Wno-unused-parameter -Wno-trigraphs
WARNINGS += -Werror
WARNINGS += -Wno-error=unused-parameter
WARNINGS += -Wno-error=unused-variable
WARNINGS += -Wno-error=unused-function
WARNINGS += -Wno-unused-but-set-variable
WARNINGS += -Wshadow
WARNINGS += -Wno-error=shadow

CXX_VERSION_STRING = $(shell $(CXX) --version | head -n1 | tr '[:upper:]' '[:lower:]')

ifeq ("$(findstring gcc,$(CXX_VERSION_STRING))", "gcc")
	WARNINGS += -Wno-missing-field-initializers
else
endif

UNAME_IDENT := $(shell uname)
ifeq ("$(UNAME_IDENT)", "Linux")
    LIBCAP_LIB = -lcap
endif

OPT_FLAGS           := -O2
LINKER_OPT_FLAGS    :=
COMMON_CFLAGS       := -g $(OPT_FLAGS)

OUTPUT_DIR          := build

CFLAGS              = $(COMMON_CFLAGS) -std=c99 -fPIC -O3 -march=native
CXXFLAGS            = $(COMMON_CFLAGS) -Wno-old-style-cast -std=c++20 -fno-exceptions

CXXSRC              := $(shell find source -iname "*.cpp" -print)
CXXOBJ              := $(CXXSRC:%.cpp=$(OUTPUT_DIR)/%.cpp.o)
CXXDEPS             := $(CXXOBJ:.o=.d)

CXXHDR              := $(shell find source -iname "*.h" -print)
CXX_COMPDB          := $(CXXHDR:%=%.compile_db) $(CXXSRC:%=%.compile_db)

INCLUDES            := -Isource -Iexternal

OUTPUT_BIN          := $(OUTPUT_DIR)/wgman

PREFIX              ?=
DEFINES             := -DPREFIX=\"$(PREFIX)\"

.PHONY: all clean build test format iwyu %.pdf.gdb %.pdf.lldb compile_commands.json
.PRECIOUS: $(OUTPUT_DIR)/%.cpp.o
.DEFAULT_GOAL = all

all: build

build: $(OUTPUT_BIN)

compdb: $(CXX_COMPDB) $(SPECIAL_HDRS_COMPDB)

$(OUTPUT_BIN): $(PRECOMP_OBJ) $(CXXOBJ) $(EXTERNAL_OBJS)
	@echo "  $(notdir $@)"
	@mkdir -p $(shell dirname $@)
	@$(CXX) $(CXXFLAGS) $(WARNINGS) $(DEFINES) $(LDFLAGS) $(LINKER_OPT_FLAGS) -o $@ $^ $(LIBCAP_LIB)

$(OUTPUT_DIR)/%.cpp.o: %.cpp $(PRECOMP_GCH)
	@echo "  $<"
	@mkdir -p $(shell dirname $@)
	@$(CXX) $(PCH_INCLUDE_FLAGS) $(CXXFLAGS) $(NONGCH_CXXFLAGS) $(WARNINGS) $(INCLUDES) $(DEFINES) -MMD -MP -c -o $@ $<

$(OUTPUT_DIR)/%.c.o: %.c
	@echo "  $<"
	@mkdir -p $(shell dirname $@)
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

%.h.compile_db: %.h
	@$(CXX) $(CXXFLAGS) $(WARNINGS) $(INCLUDES) -include $(PRECOMP_HDR) -x c++-header -o /dev/null $<

%.h.special_compile_db: %.h
	@$(CXX) $(CXXFLAGS) $(WARNINGS) $(INCLUDES) -x c++-header -o /dev/null $<

%.cpp.compile_db: %.cpp
	@$(CXX) $(CXXFLAGS) $(WARNINGS) $(INCLUDES) -include $(PRECOMP_HDR) -o /dev/null $<

clean:
	-@rm -fr $(OUTPUT_DIR)

-include $(CXXDEPS)










