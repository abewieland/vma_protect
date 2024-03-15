#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pass.h"

const char* user;
struct pass_data* d;

void try_pass(const char* pass) {
    if (pass_check(d, user, pass) > 0) {
        printf("Password found! User %s, pass %s\n", user, pass);
        exit(0);
    }
}

void iter(char* s, size_t depth, size_t max_depth, void (*f) (const char*)) {
    if (depth == max_depth) {
        f(s);
    } else {
        for (int c = '!'; c <= '~'; ++c) {
            s[depth] = c;
            iter(s, depth + 1, max_depth, f);
        }
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr,
                "usage: %s [LOGIN]\n"
                "    attempts to crack password for LOGIN (very slowly)\n",
                argv[0]);
        return 1;
    }
    user = argv[1];

    d = pass_init();
    if (!d) {
        perror("Cannot initialize pass api");
        return 1;
    }

    int r = drop_priv();
    if (r < 0) {
        perror("Cannot drop priveleges");
        return 1;
    }

    char pass[256];
    for (size_t i = 1; i <= sizeof pass; ++i) {
        memset(pass, 0, sizeof pass);
        iter(pass, 0, i, try_pass);
    }

    r = pass_fini(d);
    if (r < 0) {
        perror("Cannot finish pass api");
        return 1;
    }

    printf("All passwords (of printable ASCII) up to 256 bytes long tried, none succeeded\n");

    return 0;
}
