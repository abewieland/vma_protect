#include <stdio.h>
#include <stdlib.h>

#include "pass.h"

int check(struct pass_data* d, const char* name, const char* pass, int expect) {
    printf("Checking user %s with pass %s...\n", name, pass);
    int r = pass_check(d, name, pass);
    if (r < 0) {
        perror("Check failed");
        return -1;
    } else if (!r) {
        if (expect) {
            fprintf(stderr, "Invalid password - expected valid\n");
            return -1;
        } else {
            printf("Invalid password, as expected\n");
            return 0;
        }
    } else {
        if (!expect) {
            fprintf(stderr, "Valid password - expected invalid\n");
            return -1;
        } else {
            printf("Valid password, as expected\n");
            return 0;
        }
    }
}

int change(struct pass_data* d, const char* name, const char* oldpass,
           const char* newpass, int expect) {
    printf("Attempting to change user %s password from %s to %s...\n", name, oldpass, newpass);
    int r = pass_change(d, name, oldpass, newpass);
    if (!r) {
        if (expect) {
            printf("Succeeded, as expected\n");
            return 0;
        } else {
            fprintf(stderr, "Succeeded, but expected to fail\n");
            return -1;
        }
    } else {
        if (expect) {
            perror("Failed, but expected to succeed");
            return -1;
        } else {
            printf("Failed, as expected: %m\n");
            return 0;
        }
    }
}

int main(void) {
    /*
     * Just some simple tests - expects tom, dick, and harry with the same
     * passwords on entry, leaves with passwords foo, bar, and baz, respectively
     */
    struct pass_data* d = pass_init();
    if (!d) {
        perror("Cannot initialize pass api");
        return 1;
    }

    int r = drop_priv();
    if (r < 0) {
        perror("Cannot drop priveleges");
        return 1;
    }

    if (check(d, "tom", "tom", 1)) return 1;
    if (check(d, "dick", "dick", 1)) return 1;
    if (check(d, "harry", "harry", 1)) return 1;
    if (check(d, "tom", "dick", 0)) return 1;
    if (check(d, "tom", "harry", 0)) return 1;
    if (check(d, "dick", "tom", 0)) return 1;
    if (check(d, "dick", "harry", 0)) return 1;
    if (check(d, "harry", "tom", 0)) return 1;
    if (check(d, "harry", "dick", 0)) return 1;
    if (check(d, "tom", "foo", 0)) return 1;
    if (check(d, "tom", "bar", 0)) return 1;
    if (check(d, "tom", "baz", 0)) return 1;
    if (check(d, "foo", "foo", 0)) return 1;
    if (check(d, "bar", "foo", 0)) return 1;
    if (check(d, "baz", "foo", 0)) return 1;
    if (check(d, "baz", "tom", 0)) return 1;
    if (check(d, "baz", "dick", 0)) return 1;
    if (check(d, "baz", "harry", 0)) return 1;
    if (check(d, "root", "root", 0)) return 1;
    if (check(d, "root", "tom", 0)) return 1;
    if (check(d, "root", "dick", 0)) return 1;
    if (check(d, "root", "harry", 0)) return 1;
    if (check(d, "", "harry", 0)) return 1;
    if (check(d, "root", "", 0)) return 1;
    if (check(d, "tom", "", 0)) return 1;

    if (change(d, "tom", "tom", "dick", 1)) return 1;
    if (check(d, "tom", "tom", 0)) return 1;
    if (check(d, "tom", "dick", 1)) return 1;
    if (change(d, "tom", "dick", "harry", 1)) return 1;
    if (check(d, "tom", "dick", 0)) return 1;
    if (check(d, "tom", "harry", 1)) return 1;
    if (change(d, "tom", "harry", "foo", 1)) return 1;
    if (check(d, "tom", "harry", 0)) return 1;
    if (check(d, "tom", "foo", 1)) return 1;
    if (change(d, "dick", "harry", "foo", 0)) return 1;
    if (change(d, "dick", "foo", "bar", 0)) return 1;
    if (change(d, "dick", "dick", "bar", 1)) return 1;
    if (check(d, "dick", "dick", 0)) return 1;
    if (check(d, "dick", "bar", 1)) return 1;
    if (change(d, "bar", "dick", "bar", 0)) return 1;
    if (change(d, "bar", "", "baz", 0)) return 1;
    if (change(d, "bar", "foo", "harry", 0)) return 1;
    if (change(d, "harry", "harry", "baz", 1)) return 1;
    if (check(d, "harry", "harry", 0)) return 1;
    if (check(d, "harry", "baz", 1)) return 1;

    r = pass_fini(d);
    if (r < 0) {
        perror("Cannot finish pass api");
        return 1;
    }

    printf("All complete!\n");

    return 0;
}
