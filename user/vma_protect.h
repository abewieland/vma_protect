#ifndef VMA_PROTECT_H
#define VMA_PROTECT_H

#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#define PAGESIZE        0x1000

/* Evaluate their arguments more than once */
#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) < (y) ? (x) : (y))

/* Ensure global labels are (somewhat) safe within functions */

#ifdef __has_attribute
# if __has_attribute(noipa)
#  define _label_safe __attribute__((noipa))
# elif __has_attribute(noinline) && __has_attribute(noclone)
#  define _label_safe __attribute__((noinline,noclone))
# elif __has_attribute(noinline)
#  define _label_safe __attribute__((noinline))
# else
#  define _label_safe
# endif
#else
# define _label_safe
#endif

/* Make labels a little unique to avoid gcc */
#define LABEL_PRE ".L_user_def_"

/*
 * global_label should only be used in functions declared _label_safe, since
 * it declares a global label (which shouldn't be duplicated); labels may
 * therefore also not be repeated at the program level. global_addr refers
 * to such a label, so must be a name defined somewhere in the file
 */
#define global_label(name) asm (LABEL_PRE name ":")
#define global_addr(name) \
    ({void* __addr; \
      asm ("lea " LABEL_PRE name "(%%rip), %0" : "=r" (__addr)); \
      __addr; \
    })

#ifdef VMA_PROT_DISABLE

#define MAP_PROTECT                 0
#define vma_open(addr, name)        0
#define vma_close(addr)             0
#define vma_add_addr(addr, name)    0

#else

#define MAP_PROTECT     0x400000
#define SYS_vma_protect 451

enum vma_protect_cmd {
    VMA_ADD_ADDR = 0,
    VMA_OPEN,
    VMA_CLOSE
};

/*
 * vma_close could be implemented by calling the libc syscall function, but to
 * simplify checking for critical regions, this macro hard-codes its syscall
 * number and operation
 */
#define vma_close(addr) \
    ({register uint64_t __ax asm ("rax") = SYS_vma_protect; \
      register uint64_t __di asm ("rdi") = (uint64_t) (addr); \
      register uint64_t __si asm ("rsi") = VMA_CLOSE; \
      asm volatile ("syscall" \
                    : "+a" (__ax), "+D" (__di), "+S" (__si) \
                    : \
                    : "cc", "rdx", "rcx", "r8", "r9", "r10", "r11"); \
      if (__builtin_expect(__ax > -4096UL, 0)) { \
          errno = -__ax; \
          __ax = -1; \
      } \
      (int) __ax; \
    })

/*
 * like global_label, vma_open should only be used in functions marked as
 * _label_safe and should never repeat names
 *
 * like global_addr, vma_add_addr refers to such labels
 */
#define vma_open(addr, name) \
    ({register uint64_t __ax asm ("rax") = SYS_vma_protect; \
      register uint64_t __di asm ("rdi") = (uint64_t) (addr); \
      register uint64_t __si asm ("rsi") = VMA_OPEN; \
      asm volatile ("syscall\n" \
                    LABEL_PRE name ":" \
                    : "+a" (__ax), "+D" (__di), "+S" (__si) \
                    : \
                    : "cc", "rdx", "rcx", "r8", "r9", "r10", "r11"); \
      if (__builtin_expect(__ax > -4096UL, 0)) { \
          errno = -__ax; \
          __ax = -1; \
      } \
      (int) __ax; \
    })

/*
 * vma_add_addr could certainly also be implemented via the libc syscall,
 * but this special case (adding a vma_open address) should be by far the most
 * common, so it's a handy abbreviation
 */
#define vma_add_addr(addr, name) \
    ({register uint64_t __ax asm ("rax") = SYS_vma_protect; \
      register uint64_t __di asm ("rdi") = (uint64_t) (addr); \
      register uint64_t __si asm ("rsi") = VMA_ADD_ADDR; \
      asm volatile ("lea " LABEL_PRE name "(%%rip), %%rdx\n\t" \
                    "syscall" \
                    : "+a" (__ax), "+D" (__di), "+S" (__si) \
                    : \
                    : "cc", "rdx", "rcx", "r8", "r9", "r10", "r11"); \
      if (__builtin_expect(__ax > -4096UL, 0)) { \
          errno = -__ax; \
          __ax = -1; \
      } \
      (int) __ax; \
    })

#endif /* VMA_PROT_DISABLE */

#endif /* VMA_PROTECT_H */
