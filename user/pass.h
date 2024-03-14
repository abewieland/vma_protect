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

/*
 * These next four functions are just for convenience; they don't don't use
 * vma_protect at all (since /etc/passwd is generally readable by all anyway)
 */

/*
 * Opens /etc/passwd for reading, as a convenience function; the string returned
 * is NULL-terminated and should be passed to put_passwd(), along with the set
 * sz; returns NULL on error, setting errno
 */
const char* get_passwd(size_t* sz);

/*
 * Clean up resources from get_passwd; returns 0 on success, -1 on failure
 * (setting errno as appropriate)
 */
int put_passwd(const char* file, size_t sz);

/*
 * With file as returned from get_passwd, return the UID associated with name
 * if found, 0 otherwise (root also returns 0 if found, but is always UID 0)
 */
uid_t name_to_uid(const char* file, const char* name);

/*
 * With file as returned from get_passwd, return a NULL-terminated string
 * (allocated with malloc) representing user UID if found, NULL otherwise;
 * if non-null, the caller should free the string after use
 */
char* uid_to_name(const char* file, uid_t uid);

/*
 * Finally, one more - if the user has no interest in looking up UIDs in
 * /etc/passwd, the following drops priveleges (by switching to user nobody);
 * returns 0 on success, -1 on failure with errno set
 */
int drop_priv(void);

#endif /* PASS_H */
