#define _GNU_SOURCE
#include "vma_protect.h"

#include <sys/stat.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef CRYPT_DYN_CALL
#include <crypt.h>
#else
/* An internal header to libcrypt; definitely not its intended use... */
#define HAVE_CONFIG_H
#include <lib/alg-yescrypt.h>
#endif

#define SHADOW "foo"
#define PASSWD "/etc/passwd"

/* === PASS API === */
/*
 * These simple functions (or others like them) could easily be integrated into
 * a larger (potentially unsafe) program, but they have the guarantee that even
 * if an adversary obtains arbitrary code execution, the shadow file is never
 * leaked (this is true even without seccomp filtering in this case, since root
 * capabilities are dropped before accepting input and shadow is only readable
 * by root)
 */

struct pass_data {
    char* p;
    size_t len;
    struct crypt_data* d;
};

/*
 * Initializes the protected mapping, placing it in d; returns 0 on success,
 * -1 on failure, placing an error code in errno
 */
int pass_init(struct pass_data* d) {
    int fd = open(SHADOW, O_RDWR);
    if (fd < 0) return -1;
    struct stat s;
    int r = fstat(fd, &s);
    if (r < 0) {
        close(fd);
        return -1;
    }
    /*
     * Hack here - allocate one extra byte, which will be zeroed out per mmap
     * spec; that ensures strings are null-terminated
     */
    d->len = s.st_size + 1;
    d->p = mmap(NULL, d->len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_PROTECT, fd, 0);
    close(fd);
    if (d->p == MAP_FAILED) return -1;

    r = vma_add_addr(d->p, "check_pass");
    if (r < 0) goto unmap;
    r = vma_add_addr(d->p, "change_pass");
    if (r < 0) goto unmap;
    r = vma_close(d->p);
    if (r < 0) goto unmap;
    d->d = malloc(sizeof *d->d);
    if (d->d) return 0;

unmap:
    r = errno;
    if (munmap(d->p, d->len) < 0) return -1;
    errno = r;
    return -1;
}

/*
 * Cleans up the protected mapping; returns 0 on success, -1 on failure,
 * placing an error code in errno
 */
int pass_fini(struct pass_data* d) {
    free(d->d);
    return munmap(d->p, d->len);
}

/*
 * Tests whether this user-password combo is valid; returns 1 if yes, 0 if no,
 * and -1 on error, placing an error code in errno
 */
int _label_safe pass_check(struct pass_data* d, const char* name, const char* pass) {
    int r = vma_open(d->p, "check_pass");
    if (r < 0) goto out;
    r = 0;

    size_t nlen = strlen(name);
    size_t plen = strlen(pass);
    const char* s = d->p;
    for (const char* colon = strchr(s, ':'); colon; colon = strchr(s, ':')) {
        if ((size_t) (colon - s) == nlen && !(strncmp(s, name, nlen))) {
            s = colon + 1;
            colon = strchr(s, ':');
            memset(d->d, 0, sizeof *d->d);
            memcpy(d->d->setting, s, min((size_t) (colon - s), CRYPT_OUTPUT_SIZE - 1));
            memcpy(d->d->input, pass, min(plen, CRYPT_MAX_PASSPHRASE_SIZE - 1));
            /*
             * Errors from crypt are just treated as non-matches (this includes
             * issues like locked accounts and similar)
             */
#ifdef CRYPT_DYN_CALL
            void* res = crypt_rn(d->d->input, d->d->setting, d->d, sizeof *d->d);
#else
            yescrypt_local_t l;
            if (yescrypt_init_local(&l)) goto out;
            void* res =
                yescrypt_r(NULL, &l, (uint8_t*) d->d->input, strlen(d->d->input),
                           (uint8_t*) d->d->setting, NULL, (uint8_t*) d->d->output,
                           sizeof d->d->output);
            if (yescrypt_free_local(&l)) goto out;
#endif
            if (!res) goto out;
            r = !memcmp(d->d->output, d->d->setting, CRYPT_OUTPUT_SIZE);
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

/*
 * Changes a user password; returns 0 on success, -1 on error, placing an error
 * code in errno
 */
int _label_safe pass_change(struct pass_data* d, const char* name,
                            const char* oldpass, const char* newpass) {
    int r = vma_open(d->p, "change_pass");
    if (r < 0) goto out;
    r = -1;
    (void) d, (void) name, (void) oldpass, (void) newpass;

    r = 0;

out:
    vma_close(d->p);
    return r;
}

/* === OTHER UTILITIES === */

/*
 * Assuming file is a null-terminated well-formed string representation
 * of /etc/passwd, returns the UID associated with name if found,
 * 0 otherwise (root also returns 0 if found, but is always UID 0).
 */
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

/*
 * Go the other direction, returning a null-terminated string allocated by
 * malloc if uid was found, NULL otherwise
 */
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

/*
 * It wouldn't be hard to modify this program to also allow root to change
 * anyone's password, but that would require the program to remain as root
 * longer (albeit just for a single user input, the password itself). For the
 * sake of demonstrating the pass API above, I've gone with simpler functionality
 */
int main(int argc, char** argv) {
    if (argc > 2) {
        fprintf(stderr, "usage: %s [LOGIN]\n"
                        "    if no LOGIN, use current user\n", argv[0]);
        return 1;
    }

    int fd = open(PASSWD, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open " PASSWD ": %m\n");
        return 2;
    }
    struct stat s;
    int r = fstat(fd, &s);
    if (r < 0) {
        fprintf(stderr, "stat " PASSWD ": %m\n");
        return 2;
    }
    if (!S_ISREG(s.st_mode)) {
        fprintf(stderr, PASSWD ": expected normal file\n");
        return 2;
    }
    char* passwd = mmap(NULL, s.st_size + 1, PROT_READ, MAP_PRIVATE, fd, 0);
    if (passwd == MAP_FAILED) {
        fprintf(stderr, "mmap " PASSWD ": %m\n");
        return 2;
    }
    close(fd);

    uid_t nobody = name_to_uid(passwd, "nobody");
    if (!nobody) {
        fprintf(stderr, PASSWD ": couldn't find nobody user\n");
        return 2;
    }

    char* user = uid_to_name(passwd, getuid());
    if (!user) {
        fprintf(stderr, PASSWD ": couldn't find current user\n");
        return 2;
    }
    r = munmap(passwd, s.st_size + 1);
    if (r < 0) {
        fprintf(stderr, "munmap " PASSWD ": %m\n");
        return 2;
    }

    struct pass_data d;
    r = pass_init(&d);
    if (r < 0) {
        fprintf(stderr, "cannot initialize pass api: %m\n");
        return 2;
    }

    r = setresgid(nobody, nobody, nobody);
    if (r < 0) {
        fprintf(stderr, "cannot set GID: %m\n");
        return 2;
    }
    r = setresuid(nobody, nobody, nobody);
    if (r < 0) {
        fprintf(stderr, "cannot set UID: %m\n");
        return 2;
    }

    printf("Checking john with \"john\"...\n");
    r = pass_check(&d, "john", "john");
    if (r < 0) {
        fprintf(stderr, "error checking password: %m\n");
        return 2;
    } else if (!r) {
        printf("invalid password\n");
    } else {
        printf("valid password\n");
    }

    printf("Checking john with \"abe\"...\n");
    r = pass_check(&d, "john", "abe");
    if (r < 0) {
        fprintf(stderr, "error checking password: %m\n");
        return 2;
    } else if (!r) {
        printf("invalid password\n");
    } else {
        printf("valid password\n");
    }

    printf("Checking bad user \"blah\"...\n");
    r = pass_check(&d, "blah", "blah");
    if (r < 0) {
        fprintf(stderr, "error checking password: %m\n");
        return 2;
    } else if (!r) {
        printf("invalid password\n");
    } else {
        printf("valid password\n");
    }

    printf("Checking root user (password locked)...\n");
    r = pass_check(&d, "root", "root");
    if (r < 0) {
        fprintf(stderr, "error checking password: %m\n");
        return 2;
    } else if (!r) {
        printf("invalid password\n");
    } else {
        printf("valid password\n");
    }

    free(user);
    return 0;
}
