#ifndef PASS_H
#define PASS_H

#include <crypt.h>
#include "vma_protect.h"

/* Allow compile-time overloads of file locations */
#ifndef SHADOW
#define SHADOW "/etc/shadow"
#endif

#ifndef PASSWD
#define PASSWD "/etc/passwd"
#endif

/*
 * These simple functions (or others like them) could easily be integrated into
 * a larger (potentially unsafe) program, but they have the guarantee that even
 * if an adversary obtains arbitrary code execution, the shadow file is never
 * leaked. pass_init must be called as euid 0, but priveleges should be dropped
 * after calling it (if priveleges are correctly dropped before handling user
 * input, then /etc/shadow is safe even without seccomp filtering)
 */

struct pass_data;

/*
 * Allocates an initializes a protected mapping; returns the pointer on success,
 * (which should be passed to pass_fini), NULL on failure, placing an error code
 * in errno
 */
struct pass_data* pass_init(void);

/*
 * Cleans up the protected mapping; returns 0 on success, -1 on failure,
 * placing an error code in errno
 */
int pass_fini(struct pass_data* d);

/*
 * Tests whether this user-password combo is valid; returns 1 if yes, 0 if no,
 * and -1 on error, placing an error code in errno
 */
int _label_safe pass_check(struct pass_data* d, const char* name,
                           const char* pass);

/*
 * Changes a user password; returns 0 on success, -1 on error, placing an error
 * code in errno
 */
int _label_safe pass_change(struct pass_data* d, const char* name,
                            const char* oldpass, const char* newpass);

#endif /* PASS_H */
