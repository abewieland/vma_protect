#define _GNU_SOURCE /* for mremap */
#include "vma_protect.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <fcntl.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>

#define PAGESIZE 0x1000

volatile int segv_code;
sigjmp_buf segv_buf;

extern uint8_t _init[];
extern uint8_t __etext[];

void segv_handler(int sig, siginfo_t* info, void* ucontext) {
    (void) sig, (void) ucontext;
    segv_code = info->si_code;
    siglongjmp(segv_buf, 1);
}

const char* segv_code_str(int code) {
    switch(code) {
        case SEGV_MAPERR:
            return "Address not mapped to object.";
        case SEGV_ACCERR:
            return "Invalid permissions for mapped object.";
        case SEGV_BNDERR:
            return "Failed address bound checks.";
        case SEGV_PKUERR:
            return "Access was denied by memory protection keys.";
        default:
            return "Unknown.";
    }
}

#define segv_guard \
    do { \
        if (sigsetjmp(segv_buf, 1)) { \
            fprintf(stderr, "Segfault caught at %s:%d; reason: %s\n", \
                    __FILE__, __LINE__ + 1, segv_code_str(segv_code)); \
            return -1; \
        } \
    } while (0)

/* Test individual critical region functions */
int write_helper(void* dst) {
    segv_guard;
    strcpy(dst, "This is a very secret string");
    return 0;
}

int __vma_prot write_secret(void* prot) {
    int r = vma_open("write_vma", prot);
    if (r < 0) {
        perror("vma_protect: open");
    } else {
        r = write_helper(prot);
    }
    /* Very unlikely that vma_close will fail, but catch it anyway */
    if (vma_close(prot) < 0) {
        perror("vma_protect: close");
        return -1;
    }
    return r;
}

int read_helper(void* dst, void* src) {
    segv_guard;
    strcpy(dst, src);
    return 0;
}

int __vma_prot read_secret(void* dst, void* prot) {
    int r = vma_open("read_vma", prot);
    if (r < 0) {
        perror("vma_protect: open");
    } else {
        r = read_helper(dst, prot);
    }
    if (vma_close(prot) < 0) {
        perror("vma_protect: close");
        return -1;
    }
    return r;
}

/* Just mov %edi, %eax; ret */
const char asm_code[] = {0x89, 0xf8, 0xc3};

int exec_helper(void* dst) {
    segv_guard;
    memcpy(dst, asm_code, sizeof(asm_code));
    int r = mprotect(dst, PAGESIZE * 4, PROT_READ | PROT_EXEC);
    if (r < 0) {
        perror("mprotect: exec");
        return r;
    }
    int (*fptr) (int) = dst;
    segv_guard;
    r = fptr(42);
    if (r != 42) {
        fprintf(stderr, "Expected value 42, got %d\n", r);
        return -1;
    }
    r = mprotect(dst, PAGESIZE * 4, PROT_READ | PROT_WRITE);
    if (r < 0) perror("mprotect: write");
    return r;
}

int __vma_prot exec_secret(void* prot) {
    int r = vma_open("exec_vma", prot);
    if (r < 0) {
        perror("vma_protect: open");
    } else {
        r = exec_helper(prot);
    }
    if (vma_close(prot) < 0) {
        perror("vma_protect: close");
        return -1;
    }
    return r;
}

/* Switch statements are also certainly possible */
int __vma_prot dispatch_secret(int action, void* prot, char* buf) {
    int r = vma_open("dispatch_vma", prot);
    if (r < 0) {
        perror("vma_protect: open");
    } else {
        switch (action) {
            case 0:
                r = write_helper(prot);
                break;
            case 1:
                r = read_helper(buf, prot);
                break;
            case 2:
                r = exec_helper(prot);
                break;
            default:
                fprintf(stderr, "Unknown action %d\n", action);
                r = -1;
                break;
        }
    }
    if (vma_close(prot) < 0) {
        perror("vma_protect: close");
        return -1;
    }
    return r;
}

void* nothing(void* arg) {
    printf("Thread %d running...\n", gettid());
    for (size_t i = 0; i < 10000000000UL; ++i) {
        asm("");
    }
    printf("Thread %d done\n", gettid());
    return arg;
}

int main(void) {
    char buf[PAGESIZE];

    /*
     * A bit of a hack, but we know our .text section will end up in the same
     * segment as .init, which always starts it (for gcc and GNU ld, at least);
     * __etext need not be a page multiple off of _init, but that doesn't really
     * matter here anyway
     */
    char* seg_start = (void*) &_init;
    char* seg_end = (void*) &__etext;
    size_t seg_len = seg_end - seg_start;

    printf("Setting signal handler...\n");
    struct sigaction s;
    s.sa_sigaction = segv_handler;
    sigemptyset(&s.sa_mask);
    s.sa_flags = SA_SIGINFO;
    int r = sigaction(SIGSEGV, &s, NULL);
    if (r < 0) {
        perror("sigaction");
        return 1;
    }

    /* Ensure threading works fine */
    printf("Main thread: %d\n", gettid());
    pthread_t t;
    r = pthread_create(&t, NULL, nothing, NULL);
    if (r) {
        errno = r;
        perror("create thread");
        return 1;
    }
    r = pthread_join(t, NULL);
    if (r) {
        errno = r;
        perror("join thread");
        return 1;
    }
    printf("Main thread back (%d)\n", gettid());

    /* if MAP_PROTECT is provided, it must be a private anonymous mapping */
    printf("Attempting shared protected mapping...\n");
    char* p = mmap(NULL, PAGESIZE, PROT_NONE,
                   MAP_ANONYMOUS | MAP_SHARED | MAP_PROTECT, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }
    /* Ensure it's due to MAP_PROTECT */
    char* q = mmap(NULL, PAGESIZE, PROT_NONE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (q == MAP_FAILED) {
        perror("mmap reference");
        return 1;
    }
    r = munmap(q, PAGESIZE);
    if (r < 0) {
        perror("munmap reference");
        return 1;
    }

    /* The same, with a file */
    printf("Failed as expected; attempting file-based mapping...\n");
    int fd = open("/dev/zero", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/zero");
        return 1;
    }
    p = mmap(NULL, PAGESIZE, PROT_READ, MAP_PRIVATE | MAP_PROTECT, fd, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }
    q = mmap(NULL, PAGESIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (q == MAP_FAILED) {
        perror("mmap reference");
        return 1;
    }
    r = munmap(q, PAGESIZE);
    if (r < 0) {
        perror("munmap reference");
        return 1;
    }
    close(fd);

    /* Now, correct setup */
    printf("Failed as expected; attempting correct mapping...\n");
    p = mmap(NULL, PAGESIZE * 4, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_PROTECT, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    printf("Four page mapping succeeded, mapped [%p,%p) with RW permissions\n"
           "Adding critical regions...\n", p, p + 4 * PAGESIZE);
    r = syscall(SYS_vma_protect, p, VMA_ADD_ADDR, global_addr("write_vma"));
    if (r < 0) {
        perror("vma_protect: add_addr");
        return 1;
    }
    printf("Successfully added critical region for write address (%p)\n",
           global_addr("write_vma"));
    r = syscall(SYS_vma_protect, p, VMA_ADD_ADDR, global_addr("read_vma"));
    if (r < 0) {
        perror("vma_protect: add_addr");
        return 1;
    }
    printf("Successfully added critical region for read address (%p)\n",
           global_addr("read_vma"));
    r = syscall(SYS_vma_protect, p, VMA_ADD_ADDR, global_addr("exec_vma"));
    if (r < 0) {
        perror("vma_protect: add_addr");
        return 1;
    }
    printf("Successfully added critical region for exec address (%p)\n",
           global_addr("exec_vma"));
    r = syscall(SYS_vma_protect, p, VMA_ADD_ADDR, global_addr("dispatch_vma"));
    if (r < 0) {
        perror("vma_protect: add_addr");
        return 1;
    }
    printf("Successfully added critical region for dispatch address (%p)\n"
           "Attempting double open...\n", global_addr("dispatch_vma"));
    r = vma_open("temp1", p);
    if (r < 0) {
        perror("vma_protect: open");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }
    printf("Failed as expected; attempting to add protected region...\n");
    r = syscall(SYS_vma_protect, p, VMA_ADD_ADDR, p);
    if (r < 0) {
        perror("vma_protect: add_addr");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }
    printf("Failed as expected; attempting to add writable region...\n");
    q = mmap(NULL, PAGESIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (q == MAP_FAILED) {
        perror("mmap reference");
        return 1;
    }
    /* Fill with hlt; we won't actually execute this page */
    memset(q, 0xf4, PAGESIZE);
    r = syscall(SYS_vma_protect, p, VMA_ADD_ADDR, q);
    if (r < 0) {
        perror("vma_protect: add_addr");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }
    printf("Failed as expected; adding as second valid code mapping...\n");
    r = mprotect(q, PAGESIZE, PROT_READ | PROT_EXEC);
    if (r < 0) {
        perror("mprotect: exec");
        return 1;
    }
    r = syscall(SYS_vma_protect, p, VMA_ADD_ADDR, q);
    if (r < 0) {
        perror("vma_protect: add_addr");
        return 1;
    }
    printf("Succeeded; attempting seal...\n");
    r = vma_close(p);
    if (r < 0) {
        perror("vma_protect: close");
        return 1;
    }

    /* Read, write, and execute in the region, with and without opening it */
    printf("Successfully sealed protected region; attempting write...\n");
    r = write_secret(p);
    if (r < 0) return 1;
    printf("Write successful; attempting read...\n");
    r = read_secret(buf, p);
    if (r < 0) return 1;
    printf("Read successful (got '%s'); attempting exec...\n", buf);
    r = exec_secret(p);
    if (r < 0) return 1;
    printf("Exec successful; attempting same via dispatch...\n");
    r = dispatch_secret(0, p, buf);
    if (r < 0) return 1;
    r = dispatch_secret(1, p, buf);
    if (r < 0) return 1;
    r = dispatch_secret(2, p, buf);
    if (r < 0) return 1;
    printf("Dispatches successful (got '%s' for read); attempting failed write...\n", buf);
    r = write_helper(p);
    if (!r) {
        fprintf(stderr, "Expected segfault\n");
        return 1;
    }
    printf("Failed as expected; attempting failed read...\n");
    r = read_helper(p, buf);
    if (!r) {
        fprintf(stderr, "Expected segfault\n");
        return 1;
    }
    printf("Failed as expected; attempting failed exec...\n");
    r = exec_helper(p);
    if (!r) {
        fprintf(stderr, "Expected segfault\n");
        return 1;
    }

    /* mprotect */
    printf("Failed as expected; attempting various failed mprotects...\n");
    r = mprotect(p, 4 * PAGESIZE, PROT_READ | PROT_WRITE);
    if (r < 0) {
        perror("mprotect: read/write");
    } else {
        fprintf(stderr, "Expected EACCESS\n");
        return 1;
    }
    r = mprotect(p, PAGESIZE, PROT_WRITE);
    if (r < 0) {
        perror("mprotect: start write");
    } else {
        fprintf(stderr, "Expected EACCESS\n");
        return 1;
    }
    r = mprotect(p + PAGESIZE, PAGESIZE * 3, PROT_READ);
    if (r < 0) {
        perror("mprotect: offset read");
    } else {
        fprintf(stderr, "Expected EACCESS\n");
        return 1;
    }
    /* We can't make the critical regions writable, but the rest is fine */
    r = mprotect(seg_start, seg_len, PROT_WRITE | PROT_EXEC);
    if (r < 0) {
        perror("mprotect: code write/exec");
    } else {
        fprintf(stderr, "Expected EACCESS\n");
        return 1;
    }
    r = mprotect(seg_start, seg_len, PROT_EXEC);
    if (r < 0) {
        perror("mprotect: reference");
        return 1;
    }
    r = mprotect(seg_start, seg_len, PROT_READ | PROT_EXEC);
    if (r < 0) {
        perror("mprotect: reference");
        return 1;
    }
    r = mprotect(q, PAGESIZE, PROT_WRITE);
    if (r < 0) {
        perror("mprotect: code write");
    } else {
        fprintf(stderr, "Expected EACCESS\n");
        return 1;
    }
    r = mprotect(q, PAGESIZE, PROT_NONE);
    if (r < 0) {
        perror("mprotect: reference");
        return 1;
    }
    r = mprotect(q, PAGESIZE, PROT_READ | PROT_EXEC);
    if (r < 0) {
        perror("mprotect: reference");
        return 1;
    }

    /* Obviously we can't write to them directly, either */
    printf("All failed as expected; attempting to write to code locations...\n");
    r = write_helper(seg_start);
    if (!r) {
        fprintf(stderr, "Expected segfault\n");
        return 1;
    }
    r = write_helper(q);
    if (!r) {
        fprintf(stderr, "Expected segfault\n");
        return 1;
    }

    /* Nothing is valid when closed except open from the correct location */
    printf("Failed as expected; attempting to open in a random location...\n");
    r = vma_open("temp2", p);
    if (r < 0) {
        perror("vma_protect: open");
    } else {
        fprintf(stderr, "Expected EFAULT\n");
        return 1;
    }
    printf("Failed as expected; attempting to double close...\n");
    r = vma_close(p);
    if (r < 0) {
        perror("vma_protect: close");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }
    printf("Failed as expected; attempting to add address...\n");
    r = syscall(SYS_vma_protect, p, VMA_ADD_ADDR, NULL);
    if (r < 0) {
        perror("vma_protect: add_addr");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }

    /*
     * unmapping: only unmapping the protected region is valid, not any part of
     * it, nor its code regions
     */
    printf("Failed as expected; attempting to unmap part of region...\n");
    r = munmap(p, PAGESIZE);
    if (r < 0) {
        perror("munmap");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }
    printf("Failed as expected; attempting to unmap part of code region...\n");
    r = munmap(seg_start, PAGESIZE);
    if (r < 0) {
        perror("munmap");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }
    printf("Failed as expected; attempting to unmap entire code region...\n");
    r = munmap(q, PAGESIZE);
    if (r < 0) {
        perror("munmap");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }

    /* mlock is fine (just a nop) */
    printf("Failed as expected; attempting to mlock...\n");
    r = mlock(p, PAGESIZE);
    if (r < 0) {
        perror("mlock");
        return 1;
    }
    r = mlock(p, 4 * PAGESIZE);
    if (r < 0) {
        perror("mlock");
        return 1;
    }

    /* remap: basically never allowed */
    printf("Succeeded; attempting to remap protected region...\n");
    char* rp = mremap(p, 4 * PAGESIZE, 8 * PAGESIZE, MREMAP_MAYMOVE);
    if (rp == MAP_FAILED) {
        perror("mremap");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }
    printf("Failed as expected; attempting with different flags...\n");
    rp = mremap(p, 4 * PAGESIZE, 2 * PAGESIZE, MREMAP_FIXED | MREMAP_MAYMOVE,
                p + PAGESIZE);
    if (rp == MAP_FAILED) {
        perror("mremap");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }
    printf("Failed as expected; attempting to shrink...\n");
    rp = mremap(p, 4 * PAGESIZE, 2 * PAGESIZE, 0);
    if (rp == MAP_FAILED) {
        perror("mremap");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }
    printf("Failed as expected; attempting to remap code regions...\n");
    rp = mremap(seg_start, PAGESIZE, 4 * PAGESIZE, MREMAP_MAYMOVE);
    if (rp == MAP_FAILED) {
        perror("mremap");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }

    /* No new threads while a protected region is active */
    printf("Failed as expected; attempting to spawn threads...\n");
    r = pthread_create(&t, NULL, nothing, NULL);
    if (r) {
        errno = r;
        perror("create thread");
    } else {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    }

    /* No forks, either */
    printf("Failed as expected; attempting to fork...\n");
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
    } else if (pid) {
        fprintf(stderr, "Expected EINVAL\n");
        return 1;
    } else {
        return 1;
    }

    /* Unmap */
    printf("Failed as expected; cleaning up...\n");
    r = munmap(p, 4 * PAGESIZE);
    if (r < 0) {
        perror("munmap");
        return 1;
    }
    r = munmap(q, PAGESIZE);
    if (r < 0) {
        perror("munmap");
        return 1;
    }

    /* Now threads and forking should be back on the table! */
    printf("Unmaps succeeded; creating thread...\n");
    r = pthread_create(&t, NULL, nothing, NULL);
    if (r) {
        errno = r;
        perror("create thread");
        return 1;
    }
    r = pthread_join(t, NULL);
    if (r) {
        errno = r;
        perror("join thread");
        return 1;
    }
    printf("Thread succeeded; forking (child should segfault)...\n");
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (!pid) {
        r = write_helper(p);
        if (!r) {
            fprintf(stderr, "Expected segfault (missing area)\n");
        }
        _exit(0);
    }
    waitpid(pid, NULL, 0);

    printf("All complete!\n");
    return 0;
}
