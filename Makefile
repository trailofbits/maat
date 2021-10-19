CC = gcc
CXX = g++

PY3CONFIG := python3-config

OUTDIR = ./build
LIB_FILE = libmaat.so
BINDINGS_FILE = maat.so

## Basic default flags 
CFLAGS ?=
CXXFLAGS ?=
LDFLAGS ?=
LDLIBS ?=
LDLIBS +=  -lgmp

## Flags for LIEF backend
LIEF ?= 1
ifeq ($(LIEF), 1)
    # USE CXX11 ABI = 0 if we use LIEF (otherwise linking problems :( with std::string and basic_string<> )
	CXXFLAGS += -DLIEF_BACKEND=1 -D_GLIBCXX_USE_CXX11_ABI=0
	CXXFLAGS += -DHAS_LOADER_BACKEND=1
	LDLIBS += -lLIEF
endif

## Flags for Z3 backend
Z3 ?= 1
ifeq ($(Z3), 1)
	CXXFLAGS += -DZ3_BACKEND=1
	CXXFLAGS += -DHAS_SOLVER_BACKEND=1
	LDLIBS += -lz3
endif

## Bindings
BINDINGS ?= 1
ifeq ($(BINDINGS), 1)
	CXXFLAGS += `$(PY3CONFIG) --cflags` -DPYTHON_BINDINGS -Ibindings/python
	BINDINGS_DIR = ./bindings/python
	BINDINGS_SRCS = $(wildcard $(BINDINGS_DIR)/*.cpp)
	BINDINGS_OBJS = $(BINDINGS_SRCS:.cpp=.o)
	BINDINGS_RULE = bindings
	LDLIBS += `$(PY3CONFIG) --libs` `$(PY3CONFIG) --ldflags`

else
	BINDINGS_RULE = 
endif

## Flags for debug mode
DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CFLAGS += -g -O0
	CXXFLAGS += -g -O0
	LDFLAGS += -g
else
	CFLAGS += -O2
	CXXFLAGS += -O2
endif

## Final C++ flags
CXXFLAGS += -std=c++17 -fPIC -I src/include -I src/third-party/murmur3 -I src/third-party/sleigh/native/sleigh -I src/third-party/sleigh/native/ -Wno-write-strings -Wno-sign-compare -Wno-reorder
CXXFLAGS += -Wno-register -Wno-error# to avoid errors with clang and ISO C++17

# Source files
SRCDIR=./src
SRCS=$(wildcard $(SRCDIR)/expression/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/memory/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/ir/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/engine/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/arch/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/solver/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/loader/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/env/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/env/emulated_libs/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/utils/*.cpp)
SRCS+= $(SRCDIR)/third-party/sleigh/native/sleigh_interface.cpp
OBJS=$(SRCS:.cpp=.o)

# Unit test files
TESTDIR = ./tests/unit-tests
TESTSRCS = $(wildcard $(TESTDIR)/*.cpp)
TESTOBJS = $(TESTSRCS:.cpp=.o)

# Advanced test files
ADVTESTDIR = ./tests/adv-tests
ADVTESTSRCS = $(wildcard $(ADVTESTDIR)/*.cpp)
ADVTESTOBJS = $(ADVTESTSRCS:.cpp=.o)

# Third party dependencies
DEPDIR = $(SRCDIR)/third-party
DEPSRCS = $(DEPDIR)/murmur3/murmur3.c 

# Add sleigh files manually
SLEIGH_DIR = $(DEPDIR)/sleigh/native/sleigh
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/address.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/context.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/float.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/globalcontext.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/opcodes.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/pcodecompile.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/pcodeparse.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/pcoderaw.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/semantics.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/sleigh.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/sleighbase.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/slghpatexpress.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/slghpattern.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/slghsymbol.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/space.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/translate.cc
SLEIGH_BASE_SRCS += $(SLEIGH_DIR)/xml.cc
DEPSRCS += $(SLEIGH_BASE_SRCS)

DEPOBJS_C = $(DEPSRCS:.c=.o)
DEPOBJS = $(DEPOBJS_C:.cc=.o)

# Sources for sleigh binary 
SLEIGH_BIN_SRCS = $(SLEIGH_BASE_SRCS)
SLEIGH_BIN_SRCS += $(SLEIGH_DIR)/filemanage.cc
SLEIGH_BIN_SRCS += $(SLEIGH_DIR)/slgh_compile.cc
SLEIGH_BIN_SRCS += $(SLEIGH_DIR)/slghparse.cc
SLEIGH_BIN_SRCS += $(SLEIGH_DIR)/slghscan.cc

SLEIGH_BIN_OBJS = $(SLEIGH_BIN_SRCS:.cc=.o)

# Maat data files for SLEIGH / SLA processor specifications
MAAT_PROC_DIR = $(DEPDIR)/sleigh/processors
SPECFILES:=$(shell find $(MAAT_PROC_DIR) -name '*.slaspec')
PROC_SPECFILES:=$(shell find $(MAAT_PROC_DIR) -name '*.pspec')
SLAFILES:=$(SPECFILES:.slaspec=.sla)
SLEIGH_BIN:=$(OUTDIR)/sleigh

# Include for Maat's sources
INCLUDEDIR = ./src/include

# Compile lib and tests 
all: build_dir sleigh_bin slafiles lib unit-tests adv-tests $(BINDINGS_RULE)

# Create build output dir if it doesn't exist
build_dir: $(SLEIGH_BIN_OBJS) $(TESTOBJS) $(ADVTESTOBJS) $(OBJS) $(BINDINGS_OBJS)
	@mkdir -p $(OUTDIR)

# sleigh binary
sleigh_bin: $(SLEIGH_BIN_OBJS)
	$(CXX) $(CXXFLAGS) -o $(SLEIGH_BIN) $(SLEIGH_BIN_OBJS)

# sla files
slafiles: $(SLAFILES)

# unit tests
unit-tests: $(TESTOBJS) $(OBJS) $(DEPOBJS) $(BINDINGS_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/unit-tests $(TESTOBJS) $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS)  $(LDLIBS) 

# advanced tests
adv-tests: $(ADVTESTOBJS) $(OBJS) $(DEPOBJS) $(BINDINGS_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/adv-tests $(ADVTESTOBJS) $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS) $(LDLIBS)

# libmaat
lib: $(OBJS) $(DEPOBJS) $(BINDINGS_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/libmaat.so -shared $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS) $(LDLIBS)

# bindings
bindings: $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/maat.so -shared $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS) $(LDLIBS)

# generic 
%.o : %.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c $< -o $@ $(LDLIBS)

%.o : %.cc
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c $< -o $@ $(LDLIBS)

%.o : %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@ $(LDLIBS)

%.sla: %.slaspec
	@echo "sleigh  $@"
	@ $(SLEIGH_BIN) $< $@ >/dev/null

# Installation (assuming Linux system) 
# If prefix not set, set default
ifeq ($(PREFIX),)
    PREFIX = /usr
endif

# Output dir for configuration/necessary files
MAAT_DATA_OUTDIR = /usr/local/etc/maat

# Check if lib and binding files exist
ifneq (,$(wildcard $(OUTDIR)/libmaat.so))
    INSTALL_LIB_RULE=install_lib
else
	INSTALL_LIB_RULE=
endif
ifneq (,$(wildcard $(OUTDIR)/maat.so)) 
    INSTALL_BINDINGS_RULE=install_bindings
    PYTHONDIR=$(shell python3 -m site --user-site)/
else
	INSTALL_BINDINGS_RULE=
endif

# make install command
install: $(INSTALL_LIB_RULE) $(INSTALL_BINDINGS_RULE) install_data
	@echo "Maat was successfully installed."

install_lib:
	install -d $(DESTDIR)$(PREFIX)/lib/	
	install -c $(OUTDIR)/libmaat.so $(DESTDIR)$(PREFIX)/lib/
# install -D $(OUTDIR)/libmaat.so $(DESTDIR)$(PREFIX)/lib/
# install -d $(DESTDIR)$(PREFIX)/include/
# install -D $(INCLUDEDIR)/maat.hpp $(DESTDIR)$(PREFIX)/include/

install_bindings:
	install -d $(PYTHONDIR)
	install -c $(OUTDIR)/maat.so $(PYTHONDIR)/
# install -D $(OUTDIR)/maat.so $(PYTHONDIR)

install_data:
	install -d $(MAAT_DATA_OUTDIR)
	install -d $(MAAT_DATA_OUTDIR)/processors
	cp $(SLAFILES) $(MAAT_DATA_OUTDIR)/processors/
	for f in $(PROC_SPECFILES); do \
		cp $$f $(MAAT_DATA_OUTDIR)/processors/ ; \
	done

# make test command
test:
	$(OUTDIR)/unit-tests
	$(OUTDIR)/adv-tests

# cleaning 
cleanall: clean

clean:
	rm -f $(OBJS)
	rm -f $(TESTOBJS)
	rm -f $(ADVTESTOBJS)
	rm -f $(DEPOBJS)
	rm -f $(BINDINGS_OBJS)
	rm -f $(SLEIGH_BIN_OBJS)
	rm -f `find . -type f -name "*.gch"`
	rm -f $(OUTDIR)/*
	rm -f $(SLAFILES)
