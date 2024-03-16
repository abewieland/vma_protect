#include "vma_protect.h"

#include <time.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * A toy example of some "sensitive" data, along with some functions which only
 * return aggregate results, to show how some applications can very readily be
 * converted (and how simpler, smaller computations may have larger overhead)
 */

#define MAX_STR_LEN 64

struct data {
    char str[MAX_STR_LEN];
    double x;
    double y;
    unsigned z;
};

double _x_mean(struct data* a, size_t len) {
    double acc = 0;
    for (size_t i = 0; i < len; ++i) {
        acc += a[i].x;
    }
    return acc / len;
}

double _y_mean(struct data* a, size_t len) {
    double acc = 0;
    for (size_t i = 0; i < len; ++i) {
        acc += a[i].y;
    }
    return acc / len;
}

unsigned _z_mean(struct data* a, size_t len) {
    unsigned long acc = 0;
    for (size_t i = 0; i < len; ++i) {
        acc += a[i].z;
    }
    return acc / len;
}

double _label_safe x_mean(struct data* a, size_t len) {
    double res = 0;
    int r = vma_open(a, "x_mean");
    if (!r) {
        res = _x_mean(a, len);
    }
    vma_close(a);
    return res;
}

double _label_safe y_mean(struct data* a, size_t len) {
    double res = 0;
    int r = vma_open(a, "y_mean");
    if (!r) {
        res = _y_mean(a, len);
    }
    vma_close(a);
    return res;
}

unsigned _label_safe z_mean(struct data* a, size_t len) {
    unsigned res = 0;
    int r = vma_open(a, "z_mean");
    if (!r) {
        res = _z_mean(a, len);
    }
    vma_close(a);
    return res;
}

int _label_safe xy_regression(struct data* a, size_t len, double* slope, double* intercept) {
    int r = vma_open(a, "xy_regression");
    if (r < 0) goto out;
    double x = _x_mean(a, len);
    double y = _y_mean(a, len);
    double prod_acc = 0;
    double x_acc = 0;
    for (size_t i = 0; i < len; ++i) {
        double xdiff = a[i].x - x;
        prod_acc += xdiff * (a[i].y - y);
        x_acc += xdiff * xdiff;
    }
    if (!x_acc) {
        /* All of our data have the same x value; just return 0 in both */
        *slope = 0;
        *intercept = 0;
    } else {
        *slope = prod_acc / x_acc;
        *intercept = y - (*slope * x);
    }
    r = 0;
out:
    vma_close(a);
    return r;
}

size_t _label_safe count_str(struct data* a, size_t len, const char* s) {
    int r = vma_open(a, "count_str");
    size_t res = 0;
    if (r < 0) goto out;
    for (size_t i = 0; i < len; ++i) {
        res += !strncmp(a[i].str, s, MAX_STR_LEN);
    }
out:
    vma_close(a);
    return res;
}

int _label_safe longer(struct data* a, size_t len) {
    int r = vma_open(a, "longer");
    if (r < 0) goto out;
    r = 0;
    double acc = 0;
    for (size_t i = 0; i < 1000UL; ++i) {
        for (size_t j = 0; j < len; ++j) {
            acc += a[j].x * a[j].y * a[j].z
                - a[j].z % (int) ((a[j].x * 100) - (a[j].z * 50));
            asm("" :: "rm" (acc));
        }
    }
out:
    vma_close(a);
    return r;
}

inline int genc(void) {
    return ((lrand48() >> 5) & 0x3f) + '0';
}

void gen_random(struct data* a, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        size_t n = lrand48() % MAX_STR_LEN;
        for (size_t j = 0; j < n; ++j)
            a[i].str[j] = genc();
        a[i].x = drand48();
        a[i].y = drand48();
        a[i].z = mrand48();
    }
}

void print_tdiff(const char* str, struct timespec* start, struct timespec* end) {
    long ds = (long) end->tv_sec - start->tv_sec;
    long dn = (long) end->tv_nsec - start->tv_nsec;
    if (dn < 0) {
        dn += 1000000000;
        ds -= 1;
    }
    printf("%s: %03ld.%03ld%03ld%03ld\n", str, ds, dn / 1000000,
           (dn / 1000) % 1000, dn % 1000);
}

int main(void) {
    struct timespec t1, t2, t3;
    clock_gettime(CLOCK_REALTIME, &t1);
    srand48((getpid() ^ t1.tv_sec) + t1.tv_nsec * getppid());

    size_t len = 0x5000;
    struct data* a = mmap(NULL, len * sizeof *a, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_PROTECT, -1, 0);
    if (a == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    int r = vma_add_addr(a, "x_mean");
    if (r < 0) {
        perror("vma_add_addr");
        return 1;
    }
    r = vma_add_addr(a, "y_mean");
    if (r < 0) {
        perror("vma_add_addr");
        return 1;
    }
    r = vma_add_addr(a, "y_mean");
    if (r < 0) {
        perror("vma_add_addr");
        return 1;
    }
    r = vma_add_addr(a, "z_mean");
    if (r < 0) {
        perror("vma_add_addr");
        return 1;
    }
    r = vma_add_addr(a, "xy_regression");
    if (r < 0) {
        perror("vma_add_addr");
        return 1;
    }
    r = vma_add_addr(a, "count_str");
    if (r < 0) {
        perror("vma_add_addr");
        return 1;
    }
    r = vma_add_addr(a, "longer");
    if (r < 0) {
        perror("vma_add_addr");
        return 1;
    }

    gen_random(a, len);

    r = vma_close(a);
    if (r < 0) {
        perror("vma_close");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    for (size_t i = 0; i < 50000UL; ++i) {
        double x, y;
        unsigned z;
        size_t c;
        x = x_mean(a, len);
        y = y_mean(a, len);
        z = z_mean(a, len);
        xy_regression(a, len, &x, &y);
        c = count_str(a, len, "foo");
        asm("" :: "rm" (x), "rm" (y), "rm" (z), "rm" (c));
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);
    for (size_t i = 0; i < 250UL; ++i) {
        int b = longer(a, len);
        asm("" :: "rm" (b));
    }
    clock_gettime(CLOCK_MONOTONIC, &t3);

    printf("Times are displayed out to the nanosecond, but don't really have that much precision\n");
    print_tdiff("Small critical region", &t1, &t2);
    print_tdiff("Large critical region", &t2, &t3);

    return 0;
}
