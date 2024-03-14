CFLAGS = -Wall -Wextra -O2 -g $(CPPFLAGS)
CXXFLAGS = $(CFLAGS) -std=c++11
PROGS = check_critical unit_tests passwd passwd-static

all: $(PROGS)

check_critical: check_critical.cc
	g++ $(CXXFLAGS) $^ -lcapstone -lelf -o $@

unit_tests: unit_tests.c
	gcc $(CFLAGS) -pthread $^ -o $@

passwd: passwd.c
	gcc $(CFLAGS) -DCRYPT_DYN_CALL $^ -lcrypt -o $@

passwd-static: passwd.c libcrypt/.libs/libcrypt.a
	musl-gcc $(CFLAGS) -Ilibcrypt -static $^ -o $@

libcrypt/.libs/libcrypt.a:
	sed -i 's/#undef NDEBUG//' libcrypt/lib/crypt-port.h
	sh -c "cd libcrypt && ./autogen.sh"
	sh -c "cd libcrypt && ./configure CC=musl-gcc CPPFLAGS=-DNDEBUG"
	make -C libcrypt

clean:
	rm -rf $(PROGS)

distclean: clean
	git -C libcrypt restore lib/crypt-port.h
	make -C libcrypt distclean

.PHONY: clean distclean
