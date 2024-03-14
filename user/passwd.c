#define _GNU_SOURCE
#include "vma_protect.h"

#include <sys/stat.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define SHADOW "foo"
#define PASSWD "/etc/passwd"
#include "pass.h"

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
 * sake of demonstrating the pass API, I've gone with simpler functionality
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

    struct pass_data* d = pass_init();
    if (!d) {
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
    r = pass_check(d, "john", "john");
    if (r < 0) {
        fprintf(stderr, "error checking password: %m\n");
        return 2;
    } else if (!r) {
        printf("invalid password\n");
    } else {
        printf("valid password\n");
    }

    printf("Checking john with \"abe\"...\n");
    r = pass_check(d, "john", "abe");
    if (r < 0) {
        fprintf(stderr, "error checking password: %m\n");
        return 2;
    } else if (!r) {
        printf("invalid password\n");
    } else {
        printf("valid password\n");
    }

    printf("Checking bad user \"blah\"...\n");
    r = pass_check(d, "blah", "blah");
    if (r < 0) {
        fprintf(stderr, "error checking password: %m\n");
        return 2;
    } else if (!r) {
        printf("invalid password\n");
    } else {
        printf("valid password\n");
    }

    printf("Checking root user (password locked)...\n");
    r = pass_check(d, "root", "root");
    if (r < 0) {
        fprintf(stderr, "error checking password: %m\n");
        return 2;
    } else if (!r) {
        printf("invalid password\n");
    } else {
        printf("valid password\n");
    }

    r = pass_fini(d);
    if (r < 0) {
        fprintf(stderr, "could not finish pass api: %m\n");
        return 2;
    }

    free(user);
    return 0;
}
