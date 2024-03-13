#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

/* Some essential kernel constants needed by userspace */

#define MAP_PROTECT 0x400000
#define SYS_vma_protect 451

enum vma_protect_cmd {
    VMA_ADD_ADDR = 0,
    VMA_OPEN,
    VMA_CLOSE
};

/* Handy for using VMA_ADD_ADDR */

#ifdef __has_attribute
# if __has_attribute(noipa)
#  define __vma_prot __attribute__((noipa))
# elif __has_attribute(noinline) && __has_attribute(noclone)
#  define __vma_prot __attribute__((noinline,noclone))
# elif __has_attribute(noinline)
#  define __vma_prot __attribute__((noinline))
# else
#  define __vma_prot
# endif
#else
# define __vma_prot
#endif

/*
 * global_label and vma_open defined labels globally, so they should only be
 * used in functions declared __vma_prot to ensure they aren't duplicated
 */

#define global_label(name) asm (".L"name":")
#define vma_open(name, addr) \
    ({register uint64_t __ax asm ("rax") = SYS_vma_protect; \
      register uint64_t __di asm ("rdi") = (uint64_t) addr; \
      register uint64_t __si asm ("rsi") = VMA_OPEN; \
      asm volatile ("syscall\n\t" \
                    ".L"name":\n\t" \
                    : "+a" (__ax), "+D" (__di), "+S" (__si) \
                    : \
                    : "cc", "rdx", "rcx", "r8", "r9", "r10", "r11"); \
      if (__builtin_expect(__ax > -4096UL, 0)) { \
          errno = -__ax; \
          __ax = -1; \
      } \
      (int) __ax; \
    })
#define global_addr(name) \
    ({void* __addr; asm ("lea .L"name"(%%rip), %0" : "=r" (__addr)); __addr;})

/*
 * vma_close could be implemented just as a call to syscall, but to simplify
 * the critical region checks, this macro hard-codes its syscall number and
 * operation
 */
#define vma_close(addr) \
    ({register uint64_t __ax asm ("rax") = SYS_vma_protect; \
      register uint64_t __di asm ("rdi") = (uint64_t) addr; \
      register uint64_t __si asm ("rsi") = VMA_CLOSE; \
      asm volatile ("syscall\n\t" \
                    : "+a" (__ax), "+D" (__di), "+S" (__si) \
                    : \
                    : "cc", "rdx", "rcx", "r8", "r9", "r10", "r11"); \
      if (__builtin_expect(__ax > -4096UL, 0)) { \
          errno = -__ax; \
          __ax = -1; \
      } \
      (int) __ax; \
    })
