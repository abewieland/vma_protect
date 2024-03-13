#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

/* Some essential kernel constants needed by userspace */

#define MAP_PROTECT     0x400000
#define SYS_vma_protect 451
#define PAGESIZE        0x1000

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

/*
 * vma_open and global_label should only be used in functions marked as
 * _label_safe and should never repeat names, since they define labels
 * at the assembly local scope (which nonetheless cannot repeat)
 *
 * vma_add_addr and global_addr refer to such labels; as such they must
 * only be used on names given to vma_open or global_label
 */

/* Make the labels a little unique to avoid gcc */
#define LABEL_PRE ".L_user_def_"

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

#define global_label(name) asm (LABEL_PRE name ":")
#define global_addr(name) \
    ({void* __addr; \
      asm ("lea " LABEL_PRE name "(%%rip), %0" : "=r" (__addr)); \
      __addr; \
    })
