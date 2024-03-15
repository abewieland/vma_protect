PASS_PROGS = passtests passwd passbench
PASS_PROGS_S = $(patsubst %,%-static,$(PASS_PROGS))
VMA_PROGS = unit_tests $(PASS_PROGS) $(PASS_PROGS_S) aggregate aggregate-static
PROGS = check_critical $(VMA_PROGS)
CFLAGS = -Wall -Wextra -O2 -g
CXXFLAGS = $(CFLAGS) -std=c++11
BUILDSTAMP = .build
FLAGS_FILE = .cpp_opt

include users.mk

# Rebuild libcrypt and all dependents of vma_protect.h when CPPFLAGS change

NDEBUG ?= 1
NVMA ?= 0

ifeq ($(NDEBUG),1)
CPPFLAGS += -DNDEBUG
endif

ifeq ($(NVMA),1)
CPPFLAGS += -DVMA_PROT_DISABLE
endif

ifneq ($(wildcard $(FLAGS_FILE)),)
include $(FLAGS_FILE)
endif

ifneq ($(CPPFLAGS),$(P_CPPFLAGS))
P_CPPFLAGS := $(shell echo > $(BUILDSTAMP); echo "P_CPPFLAGS := $(CPPFLAGS)" > $(FLAGS_FILE))
endif

all: $(PROGS)

check_critical: check_critical.cc
	g++ $(CXXFLAGS) $^ -lcapstone -lelf -o $@

$(VMA_PROGS): vma_protect.h $(BUILDSTAMP)
unit_tests: unit_tests.c
	gcc $(CFLAGS) $(CPPFLAGS) -pthread $^ -o $@

aggregate: aggregate.c
	gcc $(CFLAGS) $(CPPFLAGS) $^ -lm -o $@

aggregate-static: aggregate.c
	musl-gcc $(CFLAGS) $(CPPFLAGS) -static $^ -lm -o $@

$(PASS_PROGS): pass.h
$(PASS_PROGS): %: %.c pass.c
	gcc $(CFLAGS) $(CPPFLAGS) -DCRYPT_DYN_CALL $^ -lcrypt -o $@

$(PASS_PROGS_S): pass.h
$(PASS_PROGS_S): %-static: %.c pass.c libcrypt/.libs/libcrypt.a
	musl-gcc $(CFLAGS) $(CPPFLAGS) -Ilibcrypt -static $^ -o $@

libcrypt/.libs/libcrypt.a: $(BUILDSTAMP)
	sed -i 's/#undef NDEBUG//' libcrypt/lib/crypt-port.h
	sh -c "cd libcrypt; [ -x configure ] || ./autogen.sh"
	sh -c "cd libcrypt; ./configure CC=musl-gcc \"CPPFLAGS=$(CPPFLAGS)\""
	make -C libcrypt -j 4

install: passwd passwd-static
	cp passwd passwd-static /usr/local/bin
	chmod u+s /usr/local/bin/passwd*

reset-pass:
	for u in $(USERS); do echo "$$u:$$u"; done | chpasswd

clean:
	rm -f $(PROGS) $(BUILDSTAMP) $(FLAGS_FILE)

distclean: clean
	git -C libcrypt restore lib/crypt-port.h || true
	make -C libcrypt distclean || true

.PHONY: all clean distclean reset-pass install
