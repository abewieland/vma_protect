#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "pass.h"

#ifndef CRYPT_DYN_CALL
/* An internal header to libcrypt; definitely not its intended use... */
#define HAVE_CONFIG_H
#include <lib/alg-yescrypt.h>
#endif

struct pass_data {
    char* p;
    size_t len;
    struct crypt_data* d;
};

struct pass_data* pass_init(void) {
    struct pass_data* d = malloc(sizeof *d);
    if (!d) return d;
    int fd = open(SHADOW, O_RDWR);
    if (fd < 0) goto free;
    struct stat s;
    int r = fstat(fd, &s);
    if (r < 0) {
        close(fd);
        goto free;
    }
    /*
     * Hack here - allocate one extra byte, which will be zeroed out per mmap
     * spec; that ensures strings are null-terminated
     */
    d->len = s.st_size + 1;
    d->p = mmap(NULL, d->len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_PROTECT, fd, 0);
    close(fd);
    if (d->p == MAP_FAILED) goto free;

    r = vma_add_addr(d->p, "check_pass");
    if (r < 0) goto unmap;
    r = vma_add_addr(d->p, "change_pass");
    if (r < 0) goto unmap;
    r = vma_close(d->p);
    if (r < 0) goto unmap;
    d->d = malloc(sizeof *d->d);
    if (d->d) return d;

unmap:
    r = errno;
    if (munmap(d->p, d->len) < 0) goto free;
    errno = r;
free:
    free(d);
    return NULL;
}

int pass_fini(struct pass_data* d) {
    free(d->d);
    int r = munmap(d->p, d->len);
    free(d);
    return r;
}

int _label_safe pass_check(struct pass_data* d, const char* name, const char* pass) {
    /*
     * Compute these outside first, to segfault if a pointer to the protected
     * region is passed
     */
    volatile size_t nlen_o = strlen(name);
    volatile size_t plen_o = strlen(pass);
    int r = vma_open(d->p, "check_pass");
    if (r < 0) goto out;
    r = -1;

    /*
     * But check them again inside; these are declared non-volatile to aid in
     * compiler optimizations while in the critical region
     */
    size_t nlen = strlen(name);
    size_t plen = strlen(pass);
    if (nlen != nlen_o || plen != plen_o) {
        errno = EFAULT;
        goto out;
    }

    const char* s = d->p;
    for (const char* colon = strchr(s, ':'); colon; colon = strchr(s, ':')) {
        if ((size_t) (colon - s) == nlen && !(strncmp(s, name, nlen))) {
            void* res;
            s = colon + 1;
            colon = strchr(s, ':');
            memset(d->d, 0, sizeof *d->d);
            memcpy(d->d->setting, s, min((size_t) (colon - s), CRYPT_OUTPUT_SIZE - 1));
            memcpy(d->d->input, pass, min(plen, CRYPT_MAX_PASSPHRASE_SIZE - 1));
            /*
             * Errors from crypt are treated as non-matches (as they include
             * issues like locked accounts and similar)
             */
#ifdef CRYPT_DYN_CALL
            res = crypt_rn(d->d->input, d->d->setting, d->d, sizeof *d->d);
#else
            yescrypt_local_t l;
            yescrypt_init_local(&l);
            res = yescrypt_r(NULL, &l, (uint8_t*) d->d->input, strlen(d->d->input),
                             (uint8_t*) d->d->setting, NULL, (uint8_t*) d->d->output,
                             sizeof d->d->output);
            yescrypt_free_local(&l);
#endif
            r = res && !memcmp(d->d->output, d->d->setting, CRYPT_OUTPUT_SIZE);
            explicit_bzero(d->d, sizeof *d->d);
            goto out;
        }
        s = strchr(s, '\n');
        if (!s) break;
        ++s;
    }
    r = 0;

out:
    vma_close(d->p);
    return r;
}

int _label_safe pass_change(struct pass_data* d, const char* name,
                            const char* oldpass, const char* newpass) {
    volatile size_t nlen_o = strlen(name);
    volatile size_t oplen_o = strlen(oldpass);
    volatile size_t nplen_o = strlen(newpass);
    int r = vma_open(d->p, "change_pass");
    if (r < 0) goto out;
    r = -1;

    size_t nlen = strlen(name);
    size_t oplen = strlen(oldpass);
    size_t nplen = strlen(newpass);
    if (nlen != nlen_o || oplen != oplen_o || nplen != nplen_o) {
        errno = EFAULT;
        goto out;
    }


    char* s = d->p;
    for (char* colon = strchr(s, ':'); colon; colon = strchr(s, ':')) {
        if ((size_t) (colon - s) == nlen && !(strncmp(s, name, nlen))) {
            void* res;
            s = colon + 1;
            colon = strchr(s, ':');
            /* First check the old password */
            memset(d->d, 0, sizeof *d->d);
            memcpy(d->d->setting, s, min((size_t) (colon - s), CRYPT_OUTPUT_SIZE - 1));
            memcpy(d->d->input, oldpass, min(oplen, CRYPT_MAX_PASSPHRASE_SIZE - 1));
#ifdef CRYPT_DYN_CALL
            res = crypt_rn(d->d->input, d->d->setting, d->d, sizeof *d->d);
#else
            yescrypt_local_t l;
            yescrypt_init_local(&l);
            res = yescrypt_r(NULL, &l, (uint8_t*) d->d->input, strlen(d->d->input),
                             (uint8_t*) d->d->setting, NULL, (uint8_t*) d->d->output,
                             sizeof d->d->output);
#endif
            if (!res || memcmp(d->d->output, d->d->setting, CRYPT_OUTPUT_SIZE)) {
                errno = EPERM;
                goto out;
            }
            /* Ok, the old password is fine, compute the new hash */
            memset(d->d, 0, sizeof *d->d);
            memcpy(d->d->setting, s, min((size_t) (colon - s), CRYPT_OUTPUT_SIZE - 1));
            memcpy(d->d->input, newpass, min(nplen, CRYPT_MAX_PASSPHRASE_SIZE - 1));
#ifdef CRYPT_DYN_CALL
            res = crypt_rn(d->d->input, d->d->setting, d->d, sizeof *d->d);
#else
            res = yescrypt_r(NULL, &l, (uint8_t*) d->d->input, strlen(d->d->input),
                             (uint8_t*) d->d->setting, NULL, (uint8_t*) d->d->output,
                             sizeof d->d->output);
            yescrypt_free_local(&l);
#endif
            if (!res) {
                explicit_bzero(d->d, sizeof *d->d);
                goto out;
            }
            if (strlen(d->d->output) != strlen(d->d->setting)) {
                explicit_bzero(d->d, sizeof *d->d);
                errno = EINVAL;
                goto out;
            }
            memcpy(s, d->d->output, strlen(d->d->output));

            explicit_bzero(d->d, sizeof *d->d);
            r = 0;
            goto out;
        }
        s = strchr(s, '\n');
        if (!s) break;
        ++s;
    }
    errno = EPERM;
    r = -1;

out:
    vma_close(d->p);
    return r;
}

const char* get_passwd(size_t* sz) {
    int fd = open(PASSWD, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat s;
    int r = fstat(fd, &s);
    if (r < 0) {
        close(fd);
        return NULL;
    }
    if (!S_ISREG(s.st_mode)) {
        close(fd);
        errno = EINVAL;
        return NULL;
    }
    /* Same hack as above */
    const char* p = mmap(NULL, s.st_size + 1, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return NULL;
    *sz = s.st_size + 1;
    return p;
}

int put_passwd(const char* file, size_t sz) {
    return munmap((char*) file, sz);
}

uid_t name_to_uid(const char* file, const char* name) {
    size_t nlen = strlen(name);
    for (const char* colon = strchr(file, ':'); colon; colon = strchr(file, ':')) {
        if ((size_t) (colon - file) == nlen && !(strncmp(file, name, nlen))) {
            file = strchr(colon + 1, ':') + 1;
            return strtoul(file, NULL, 10);
        }
        file = strchr(file, '\n');
        if (!file) break;
        ++file;
    }
    return 0;
}

char* uid_to_name(const char* file, uid_t uid) {
    for (const char* colon = strchr(file, ':'); colon; colon = strchr(file, ':')) {
        const char* us = strchr(colon + 1, ':') + 1;
        if (strtoul(us, NULL, 10) == uid) {
            size_t len = colon - file;
            char* ret = malloc(len + 1);
            memcpy(ret, file, len);
            ret[len] = 0;
            return ret;
        }
        file = strchr(file, '\n');
        if (!file) break;
        ++file;
    }
    return NULL;
}

int drop_priv(void) {
    size_t sz;
    const char* passwd = get_passwd(&sz);
    if (!passwd) return -1;

    uid_t nobody = name_to_uid(passwd, "nobody");
    if (!nobody) {
        if (put_passwd(passwd, sz) < 0) return -1;
        errno = ENOENT;
        return -1;
    }

    if (put_passwd(passwd, sz) < 0) return -1;
    if (setresgid(nobody, nobody, nobody) < 0) return -1;
    if (setresuid(nobody, nobody, nobody) < 0) return -1;

    return 0;
}
