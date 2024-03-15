/* for mremap (though also helps with mkstemp and ftruncate) */
#define _GNU_SOURCE
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

extern uint8_t _init[];
extern uint8_t __etext[];
char* seg_start;
char* seg_end;
size_t seg_len;

/* Handle segfaults */
volatile int segv_code;
sigjmp_buf segv_buf;

void segv_handler(int sig, siginfo_t* info, void* ucontext) {
    (void) sig, (void) ucontext;
    segv_code = info->si_code;
    siglongjmp(segv_buf, 1);
}

/* And our own signals */
volatile int usr1_received;

void usr1_handler(int sig) {
    (void) sig;
    usr1_received = 1;
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

#define fpr_id(f, fmt, ...) \
    fprintf(f, "pid %d tid %d: " fmt, getpid(), gettid(), ##__VA_ARGS__)

#define perr_id(str) fpr_id(stderr, str ": %m\n")

#define pr_id(...) fpr_id(stdout, __VA_ARGS__)

#define segv_guard \
    do { \
        if (sigsetjmp(segv_buf, 1)) { \
            fpr_id(stderr, "Segfault caught at %s:%d with reason: %s\n", \
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

int _label_safe write_secret(void* prot) {
    int r = vma_open(prot, "write");
    if (r < 0) {
        perr_id("vma_protect: open");
    } else {
        r = write_helper(prot);
    }
    /* Very unlikely that vma_close will fail, but catch it anyway */
    if (vma_close(prot) < 0) {
        perr_id("vma_protect: close");
        return -1;
    }
    return r;
}

int read_helper(void* dst, void* src) {
    segv_guard;
    strcpy(dst, src);
    return 0;
}

int _label_safe read_secret(void* dst, void* prot) {
    int r = vma_open(prot, "read");
    if (r < 0) {
        perr_id("vma_protect: open");
    } else {
        r = read_helper(dst, prot);
    }
    if (vma_close(prot) < 0) {
        perr_id("vma_protect: close");
        return -1;
    }
    return r;
}

/* Just mov %edi, %eax; ret */
const char asm_code[] = {0x89, 0xf8, 0xc3};

int exec_helper(void* dst, size_t len) {
    segv_guard;
    memcpy(dst, asm_code, sizeof(asm_code));
    int r = mprotect(dst, len, PROT_READ | PROT_EXEC);
    if (r < 0) {
        perr_id("mprotect: exec");
        return r;
    }
    int (*fptr) (int) = dst;
    segv_guard;
    r = fptr(42);
    if (r != 42) {
        fpr_id(stderr, "Expected value 42, got %d\n", r);
        return -1;
    }
    r = mprotect(dst, len, PROT_READ | PROT_WRITE);
    if (r < 0) perr_id("mprotect: write");
    return r;
}

int _label_safe exec_secret(void* prot, size_t len) {
    int r = vma_open(prot, "exec");
    if (r < 0) {
        perr_id("vma_protect: open");
    } else {
        r = exec_helper(prot, len);
    }
    if (vma_close(prot) < 0) {
        perr_id("vma_protect: close");
        return -1;
    }
    return r;
}

/* Switch statements are also certainly possible */
int _label_safe dispatch_secret(int action, void* prot, char* buf, size_t len) {
    int r = vma_open(prot, "dispatch");
    if (r < 0) {
        perr_id("vma_protect: open");
    } else {
        switch (action) {
            case 0:
                r = write_helper(prot);
                break;
            case 1:
                r = read_helper(buf, prot);
                break;
            case 2:
                r = exec_helper(prot, len);
                break;
            default:
                fpr_id(stderr, "Unknown action %d\n", action);
                r = -1;
                break;
        }
    }
    if (vma_close(prot) < 0) {
        perr_id("vma_protect: close");
        return -1;
    }
    return r;
}

int get_signal(void) {
    usr1_received = 0;
    raise(SIGUSR1);
    return usr1_received;
}

int _label_safe test_signal(void* prot) {
    int r = vma_open(prot, "signal");
    if (r < 0) {
        perr_id("vma_protect: open");
    } else {
        r = 0;
        if (get_signal()) {
            r = -1;
            fpr_id(stderr, "Received signal in critical region\n");
        }
    }
    if (vma_close(prot) < 0) {
        perr_id("vma_protect: close");
        return -1;
    }
    return r;
}

/* A useless function for a thread to run */
void* nothing(void* arg) {
    pr_id("Doing nothing...\n");
    for (size_t i = 0; i < 10000000000UL; ++i) {
        asm(""); /* Prevent loop optimizations */
    }
    pr_id("Nothing done\n");
    return arg;
}

/* Run a number of tests against a protected mapping */
int test_mmap(char** prot, char** code, size_t len, int prot_bits, int flags, int fd) {
    char buf[PAGESIZE];

    *prot = mmap(NULL, len, prot_bits, flags, fd, 0);
    if (*prot == MAP_FAILED) {
        perr_id("mmap");
        return 1;
    }
    pr_id("Mapping succeeded at [%p,%p); adding critical regions...\n",
          *prot, *prot + len);
    int r = vma_add_addr(*prot, "write");
    if (r < 0) {
        perr_id("vma_protect: add_addr");
        return 1;
    }
    pr_id("Successfully added critical region for write at %p\n",
          global_addr("write"));
    r = vma_add_addr(*prot, "read");
    if (r < 0) {
        perr_id("vma_protect: add_addr");
        return 1;
    }
    pr_id("Successfully added critical region for read at %p\n",
          global_addr("read"));
    r = vma_add_addr(*prot, "exec");
    if (r < 0) {
        perr_id("vma_protect: add_addr");
        return 1;
    }
    pr_id("Successfully added critical region for exec at %p\n",
          global_addr("exec"));
    r = vma_add_addr(*prot, "dispatch");
    if (r < 0) {
        perr_id("vma_protect: add_addr");
        return 1;
    }
    pr_id("Successfully added critical region for dispatch at %p\n",
          global_addr("dispatch"));
    r = vma_add_addr(*prot, "signal");
    if (r < 0) {
        perr_id("vma_protect: add_addr");
        return 1;
    }
    pr_id("Successfully added critical region for signal at %p\n",
          global_addr("signal"));
    pr_id("Attempting double open...\n");
    r = vma_open(*prot, "temp1");
    if (r < 0) {
        perr_id("vma_protect: open");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }
    pr_id("Failed as expected; attempting to add protected region...\n");
    r = syscall(SYS_vma_protect, *prot, VMA_ADD_ADDR, *prot);
    if (r < 0) {
        perr_id("vma_protect: add_addr");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }
    pr_id("Failed as expected; attempting to add writable region...\n");
    *code = mmap(NULL, PAGESIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (*code == MAP_FAILED) {
        perr_id("mmap code page");
        return 1;
    }
    /* Fill with hlt; we won't actually execute this page */
    memset(*code, 0xf4, PAGESIZE);
    r = syscall(SYS_vma_protect, *prot, VMA_ADD_ADDR, *code);
    if (r < 0) {
        perr_id("vma_protect: add_addr");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }
    pr_id("Failed as expected; adding as second valid code mapping...\n");
    r = mprotect(*code, PAGESIZE, PROT_READ | PROT_EXEC);
    if (r < 0) {
        perr_id("mprotect: exec");
        return 1;
    }
    r = syscall(SYS_vma_protect, *prot, VMA_ADD_ADDR, *code);
    if (r < 0) {
        perr_id("vma_protect: add_addr");
        return 1;
    }
    pr_id("Succeeded; attempting mlock...\n");
    r = mlock(*prot, len);
    if (r < 0) {
        perr_id("mlock");
        return 1;
    }
    r = munlock(*prot, len);
    if (r < 0) {
        perr_id("munlock");
        return 1;
    }
    pr_id("Succeeded; attempting seal...\n");
    r = vma_close(*prot);
    if (r < 0) {
        perr_id("vma_protect: close");
        return 1;
    }

    /* mlock should fail if closed */
    pr_id("Succeeded; attempting mlock...\n");
    r = mlock(*prot, len);
    if (r < 0) {
        perr_id("mlock");
    } else {
        fpr_id(stderr, "Expected ENOMEM\n");
        return 1;
    }
    /* But munlock will succeed, because they weren't locked in the first place */
    pr_id("Failed as expected; attempting munlock...\n");
    r = munlock(*prot, len);
    if (r < 0) {
        perr_id("munlock");
        return 1;
    }

    /* Read, write, and execute in the region, with and without opening it */
    pr_id("Succeeded; attempting write...\n");
    r = write_secret(*prot);
    if (r < 0) return 1;
    pr_id("Write successful; attempting read...\n");
    r = read_secret(buf, *prot);
    if (r < 0) return 1;
    pr_id("Read successful (got '%s'); attempting exec...\n", buf);
    r = exec_secret(*prot, len);
    if (r < 0) return 1;
    pr_id("Exec successful; attempting same via dispatch...\n");
    r = dispatch_secret(0, *prot, buf, len);
    if (r < 0) return 1;
    r = dispatch_secret(1, *prot, buf, len);
    if (r < 0) return 1;
    r = dispatch_secret(2, *prot, buf, len);
    if (r < 0) return 1;
    pr_id("Dispatches successful (got '%s' for read); attempting signal...\n", buf);
    r = test_signal(*prot);
    if (r < 0) return 1;
    pr_id("Signal masking succeeded; attempting failed write...\n");
    r = write_helper(*prot);
    if (!r) {
        fpr_id(stderr, "Expected segfault\n");
        return 1;
    }
    pr_id("Failed as expected; attempting failed read...\n");
    r = read_helper(buf, *prot);
    if (!r) {
        fpr_id(stderr, "Expected segfault\n");
        return 1;
    }
    pr_id("Failed as expected; attempting failed exec...\n");
    r = exec_helper(*prot, len);
    if (!r) {
        fpr_id(stderr, "Expected segfault\n");
        return 1;
    }

    /* mprotect */
    pr_id("Failed as expected; attempting various failed mprotects...\n");
    r = mprotect(*prot, len, PROT_READ | PROT_WRITE);
    if (r < 0) {
        perr_id("mprotect: read/write");
    } else {
        fpr_id(stderr, "Expected EACCESS\n");
        return 1;
    }
    r = mprotect(*prot, PAGESIZE, PROT_WRITE);
    if (r < 0) {
        perr_id("mprotect: start write");
    } else {
        fpr_id(stderr, "Expected EACCESS\n");
        return 1;
    }
    r = mprotect(*prot + PAGESIZE, len - PAGESIZE, PROT_READ);
    if (r < 0) {
        perr_id("mprotect: offset read");
    } else {
        fpr_id(stderr, "Expected EACCESS\n");
        return 1;
    }
    /* We can't make the critical regions writable, but the rest is fine */
    r = mprotect(seg_start, seg_len, PROT_WRITE | PROT_EXEC);
    if (r < 0) {
        perr_id("mprotect: code write/exec");
    } else {
        fpr_id(stderr, "Expected EACCESS\n");
        return 1;
    }
    r = mprotect(seg_start, seg_len, PROT_EXEC);
    if (r < 0) {
        perr_id("mprotect: reference");
        return 1;
    }
    r = mprotect(seg_start, seg_len, PROT_READ | PROT_EXEC);
    if (r < 0) {
        perr_id("mprotect: reference");
        return 1;
    }
    r = mprotect(*code, PAGESIZE, PROT_WRITE);
    if (r < 0) {
        perr_id("mprotect: code write");
    } else {
        fpr_id(stderr, "Expected EACCESS\n");
        return 1;
    }
    r = mprotect(*code, PAGESIZE, PROT_NONE);
    if (r < 0) {
        perr_id("mprotect: reference");
        return 1;
    }
    r = mprotect(*code, PAGESIZE, PROT_READ | PROT_EXEC);
    if (r < 0) {
        perr_id("mprotect: reference");
        return 1;
    }

    /* Obviously we can't write to them directly, either */
    pr_id("All failed as expected; attempting to write to code locations...\n");
    r = write_helper(seg_start);
    if (!r) {
        fpr_id(stderr, "Expected segfault\n");
        return 1;
    }
    r = write_helper(*code);
    if (!r) {
        fpr_id(stderr, "Expected segfault\n");
        return 1;
    }

    /* Nothing is valid when closed except open from the correct location */
    pr_id("Failed as expected; attempting to open in a random location...\n");
    r = vma_open(*prot, "temp2");
    if (r < 0) {
        perr_id("vma_protect: open");
    } else {
        fpr_id(stderr, "Expected EFAULT\n");
        return 1;
    }
    pr_id("Failed as expected; attempting to double close...\n");
    r = vma_close(*prot);
    if (r < 0) {
        perr_id("vma_protect: close");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }
    pr_id("Failed as expected; attempting to add address...\n");
    r = vma_add_addr(*prot, "temp2");
    if (r < 0) {
        perr_id("vma_protect: add_addr");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }

    /*
     * unmapping: only unmapping the protected region is valid, not any part of
     * it, nor its code regions
     */
    pr_id("Failed as expected; attempting to unmap part of region...\n");
    r = munmap(*prot, PAGESIZE);
    if (r < 0) {
        perr_id("munmap");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }
    pr_id("Failed as expected; attempting to unmap part of code region...\n");
    r = munmap(seg_start, PAGESIZE);
    if (r < 0) {
        perr_id("munmap");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }
    pr_id("Failed as expected; attempting to unmap entire code region...\n");
    r = munmap(*code, PAGESIZE);
    if (r < 0) {
        perr_id("munmap");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }

    /* remap: basically never allowed */
    pr_id("Failed as expected; attempting to remap protected region (grow)...\n");
    char* rp = mremap(*prot, len, len * 2, MREMAP_MAYMOVE);
    if (rp == MAP_FAILED) {
        perr_id("mremap");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }
    pr_id("Failed as expected; attempting to move...\n");
    rp = mremap(*prot, len, len, MREMAP_FIXED | MREMAP_MAYMOVE, *prot + PAGESIZE);
    if (rp == MAP_FAILED) {
        perr_id("mremap");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }
    pr_id("Failed as expected; attempting to shrink...\n");
    rp = mremap(*prot, len, len, 0);
    if (rp == MAP_FAILED) {
        perr_id("mremap");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }
    pr_id("Failed as expected; attempting to remap code regions...\n");
    rp = mremap(*code, PAGESIZE, 4 * PAGESIZE, MREMAP_MAYMOVE);
    if (rp == MAP_FAILED) {
        perr_id("mremap");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }
    rp = mremap(seg_start, seg_len, 2 * seg_len, MREMAP_MAYMOVE);
    if (rp == MAP_FAILED) {
        perr_id("mremap");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }
    pr_id("Failed as expected\n");
    return 0;
}

int main(void) {
    /*
     * A bit of a hack, but we know our .text section will end up in the same
     * segment as _init, which always starts it (for gcc and GNU ld, at least);
     * __etext need not be a page multiple off of _init, but that doesn't really
     * matter here anyway
     */
    seg_start = (void*) &_init;
    seg_end = (void*) &__etext;
    seg_len = seg_end - seg_start;

    pr_id("Setting signal handlers...\n");
    struct sigaction s;
    sigemptyset(&s.sa_mask);
    s.sa_flags = SA_SIGINFO;
    s.sa_sigaction = segv_handler;
    int r = sigaction(SIGSEGV, &s, NULL);
    if (r < 0) {
        perr_id("sigaction: segv");
        return 1;
    }
    s.sa_flags = 0;
    s.sa_handler = usr1_handler;
    r = sigaction(SIGUSR1, &s, NULL);
    if (r < 0) {
        perr_id("sigaction: usr1");
        return 1;
    }

    /* Ensure we can get SIGUSR1 */
    pr_id("Checking if we can receive signal...\n");
    if (!get_signal()) {
        fpr_id(stderr, "Couldn't catch SIGUSR1\n");
        return 1;
    }

    /* Ensure threading works fine */
    pr_id("Attempting to spawn threads...\n");
    pthread_t t;
    r = pthread_create(&t, NULL, nothing, NULL);
    if (r) {
        errno = r;
        perr_id("create thread");
        return 1;
    }
    r = pthread_join(t, NULL);
    if (r) {
        errno = r;
        perr_id("join thread");
        return 1;
    }
    pr_id("Thread done\n");

    char *prot1, *prot2, *code1, *code2;
    pr_id("Attempting 4-page anonymous private mapping...\n");
    r = test_mmap(&prot1, &code1, 4 * PAGESIZE, PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_PRIVATE | MAP_PROTECT, -1);
    if (r) return 1;

    /* No new threads while a protected region is active */
    pr_id("Attempting to spawn threads...\n");
    r = pthread_create(&t, NULL, nothing, NULL);
    if (r) {
        errno = r;
        perr_id("create thread");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }

    /* No forks, either */
    pr_id("Failed as expected; attempting to fork...\n");
    pid_t pid = fork();
    if (pid < 0) {
        perr_id("fork");
    } else if (pid) {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    } else {
        return 1;
    }
    pr_id("Failed as expected\n");

    pr_id("Attempting 8-page file-backed mapping...\n");
    char tmpname[14] = "vma_tmpXXXXXX";
    int fd = mkstemp(tmpname);
    if (fd < 0) {
        perr_id("mkstemp");
        return 1;
    }
    r = ftruncate(fd, 8 * PAGESIZE);
    if (r < 0) {
        perr_id("ftruncate");
        return 1;
    }
    r = test_mmap(&prot2, &code2, 8 * PAGESIZE, PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_PROTECT, fd);
    if (r) return 1;
    r = close(fd);
    if (r < 0) {
        perr_id("close");
        return 1;
    }
    r = unlink(tmpname);
    if (r < 0) {
        perr_id("unlink");
        return 1;
    }

    /* Again, no threads or forks */
    pr_id("Attempting to spawn threads...\n");
    r = pthread_create(&t, NULL, nothing, NULL);
    if (r) {
        errno = r;
        perr_id("create thread");
    } else {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    }
    pr_id("Failed as expected; attempting to fork...\n");
    pid = fork();
    if (pid < 0) {
        perr_id("fork");
    } else if (pid) {
        fpr_id(stderr, "Expected EINVAL\n");
        return 1;
    } else {
        return 1;
    }

    /* Unmap */
    pr_id("Failed as expected; cleaning up...\n");
    r = munmap(prot1, 4 * PAGESIZE);
    if (r < 0) {
        perr_id("munmap");
        return 1;
    }
    r = munmap(prot2, 8 * PAGESIZE);
    if (r < 0) {
        perr_id("munmap");
        return 1;
    }
    r = munmap(code1, PAGESIZE);
    if (r < 0) {
        perr_id("munmap");
        return 1;
    }
    r = munmap(code2, PAGESIZE);
    if (r < 0) {
        perr_id("munmap");
        return 1;
    }

    /* Now threads and forking should be back on the table! */
    pr_id("Unmaps succeeded; creating thread...\n");
    r = pthread_create(&t, NULL, nothing, NULL);
    if (r) {
        errno = r;
        perr_id("create thread");
        return 1;
    }
    r = pthread_join(t, NULL);
    if (r) {
        errno = r;
        perr_id("join thread");
        return 1;
    }
    pr_id("Thread succeeded; forking (child should segfault)...\n");
    pid = fork();
    if (pid < 0) {
        perr_id("fork");
        return 1;
    } else if (!pid) {
        r = write_helper(prot1);
        if (!r) {
            fpr_id(stderr, "Expected segfault (missing area)\n");
        }
        _exit(0);
    }
    waitpid(pid, NULL, 0);

    pr_id("All complete!\n");
    return 0;
}
