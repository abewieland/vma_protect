CFLAGS = -Wall -Wextra -O2 -g -pthread
CXXFLAGS = $(CFLAGS) -std=c++11
LDLIBS = -lcapstone -lelf -lcrypt
CPROGS = $(patsubst %.c,%,$(wildcard *.c))
CPROGS_S = $(patsubst %,%-static,$(CPROGS))
CCPROGS = $(patsubst %.cc,%,$(wildcard *.cc))
PROGS = $(CPROGS) $(CCPROGS) $(CPROGS_S)

all: $(PROGS)

%-static: %.c
	musl-gcc $(CFLAGS) $^ -static -o $@

clean:
	rm -rf $(PROGS)

.PHONY: clean
