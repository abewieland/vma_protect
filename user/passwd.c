#define _GNU_SOURCE /* for setresuid, setresgid */
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pass.h"

/* Read a password from stdin, hiding the characters */
int read_pass(const char* prompt, char* buf, size_t len) {
    struct termios t;
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) return -1;
    int r = tcgetattr(fd, &t);
    if (r < 0) goto close;
    t.c_lflag &= ~ECHO;
    r = tcsetattr(fd, TCSANOW, &t);
    if (r < 0) goto close;
    printf("%s", prompt);
    fflush(stdout);
    fgets(buf, len, stdin);
    size_t plen = strlen(buf);
    t.c_lflag |= ECHO;
    r = tcsetattr(fd, TCSANOW, &t);
    if (r < 0) goto close;
    close(fd);
    printf("\n");
    if (buf[plen - 1] == '\n') {
        buf[plen - 1] = 0;
    } else {
        printf("Warning: maximum password length exceeded; truncating...\n");
    }
    return 0;

close:
    r = errno;
    close(fd);
    errno = r;
    return -1;
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

    size_t sz;
    const char* passwd = get_passwd(&sz);
    if (!passwd) {
        fprintf(stderr, PASSWD ": cannot open or map: %m\n");
        return 2;
    }

    uid_t nobody = name_to_uid(passwd, "nobody");
    if (!nobody) {
        fprintf(stderr, PASSWD ": cannot find nobody user\n");
        return 2;
    }

    char* user = uid_to_name(passwd, getuid());
    if (!user) {
        fprintf(stderr, PASSWD ": cannot find current user\n");
        return 2;
    }
    int r = put_passwd(passwd, sz);
    if (r < 0) {
        fprintf(stderr, PASSWD ": cannot unmap: %m\n");
        return 2;
    }

    struct pass_data* d = pass_init();
    if (!d) {
        fprintf(stderr, "Cannot initialize pass api: %m\n");
        return 2;
    }

    r = setresgid(nobody, nobody, nobody);
    if (r < 0) {
        fprintf(stderr, "Cannot set GID: %m\n");
        return 2;
    }
    r = setresuid(nobody, nobody, nobody);
    if (r < 0) {
        fprintf(stderr, "Cannot set UID: %m\n");
        return 2;
    }

    char oldp[CRYPT_MAX_PASSPHRASE_SIZE];
    char newp[CRYPT_MAX_PASSPHRASE_SIZE];
    char newp2[CRYPT_MAX_PASSPHRASE_SIZE];

    printf("Changing password for %s.\n", user);
    r = read_pass("Current password: ", oldp, sizeof oldp);
    if (r < 0) {
        fprintf(stderr, "Cannot read password: %m\n");
        return 2;
    }

    r = pass_check(d, user, oldp);
    if (r < 0) {
        fprintf(stderr, "Cannot verify password: %m\n");
        return 2;
    } else if (!r) {
        fprintf(stderr, "Incorrect password\n");
        return 1;
    }

    r = read_pass("New password: ", newp, sizeof newp);
    if (r < 0) {
        fprintf(stderr, "Cannot read password: %m\n");
        return 2;
    }
    r = read_pass("Retype new password: ", newp2, sizeof newp2);
    if (r < 0) {
        fprintf(stderr, "Cannot read password: %m\n");
        return 2;
    }

    if (strcmp(newp, newp2)) {
        fprintf(stderr, "Passwords do not match\n");
        return 1;
    }

    r = pass_change(d, user, oldp, newp);
    if (r < 0) {
        fprintf(stderr, "Cannot change password: %m\n");
        return 2;
    }

    printf("Password changed successfully\n");

    r = pass_fini(d);
    if (r < 0) {
        fprintf(stderr, "Cannot finish pass api: %m\n");
        return 2;
    }

    free(user);
    return 0;
}
