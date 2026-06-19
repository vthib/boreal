builddir = _build
outdir = $(builddir)/bin
sources = $(wildcard src/*.c)
objs = $(patsubst src/%.c,$(builddir)/%.o,$(sources))
binaries = $(patsubst src/%.c,$(outdir)/%,$(sources))
tests = $(patsubst $(outdir)/%,test-%,$(binaries))

CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic
CARGO_TARGET = debug
BOREAL_LIB_PATH = ../../target/${CARGO_TARGET}

###
# phonies
###

.PHONY: all clean check

all: $(binaries)

clean:
	rm -rf $(builddir)

check: $(tests)

####
# tests
####

test-%: $(outdir)/%
	LD_LIBRARY_PATH=$(BOREAL_LIB_PATH) ./$<

###
# .c -> .o
###

$(builddir):
	mkdir $(builddir)

$(builddir)/ihct.o: | $(builddir)
$(builddir)/ihct.o: src/ihct/*
	$(CC) $(CFLAGS) -c $< -o $@

$(objs): | $(builddir)
$(builddir)/%.o: src/%.c
	$(CC) $(CFLAGS) -Isrc/ihct -I../include -c $< -o $@

###
# .o -> bins
###

$(outdir): | $(builddir)
	mkdir $(outdir)

$(binaries): | $(outdir)
$(outdir)/%: $(builddir)/%.o $(builddir)/ihct.o
	$(CC) $(CFLAGS) -L${BOREAL_LIB_PATH} -lboreal_capi $^ -o $@
