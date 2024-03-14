CFLAGS = -Wall -Wextra -O2 -g $(CPPFLAGS)
CXXFLAGS = $(CFLAGS) -std=c++11
PROGS = check_critical unit_tests passwd passwd-static
NDEBUG_FILE = .ndebug_opt

include users.mk

# Rebuild libcrypt when NDEBUG changes

ifneq ($(wildcard $(NDEBUG_FILE)),)
include $(NDEBUG_FILE)
endif

NDEBUG ?= 1

ifneq ($(NDEBUG),$(OLD_NDEBUG))
OLD_NDEBUG := $(shell echo "OLD_NDEBUG := $(NDEBUG)" > $(NDEBUG_FILE))
endif

ifeq ($(NDEBUG),1)
CPPFLAGS += -DNDEBUG
NDEBUG_OPT := CPPFLAGS=-DNDEBUG
else
NDEBUG_OPT :=
endif

all: $(PROGS)

check_critical: check_critical.cc
	g++ $(CXXFLAGS) $^ -lcapstone -lelf -o $@

unit_tests: unit_tests.c
	gcc $(CFLAGS) -pthread $^ -o $@

passwd: passwd.c pass.c pass.h
	gcc $(CFLAGS) -DCRYPT_DYN_CALL $^ -lcrypt -o $@

passwd-static: passwd.c pass.c pass.h libcrypt/.libs/libcrypt.a
	musl-gcc $(CFLAGS) -Ilibcrypt -static $^ -o $@

libcrypt/.libs/libcrypt.a: $(NDEBUG_FILE)
	sed -i 's/#undef NDEBUG//' libcrypt/lib/crypt-port.h
	sh -c "cd libcrypt; [ -x configure ] || ./autogen.sh"
	sh -c "cd libcrypt; ./configure CC=musl-gcc $(NDEBUG_OPT)"
	make -C libcrypt

reset-pass:
	for u in $(USERS); do echo "$$u:$$u"; done | chpasswd

clean:
	rm -f $(PROGS) $(NDEBUG_FILE)

distclean: clean
	git -C libcrypt restore lib/crypt-port.h
	make -C libcrypt distclean || true

.PHONY: all clean distclean reset-pass
