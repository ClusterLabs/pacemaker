/*
 * Copyright 2021-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <grp.h>

#include <cmocka.h>
#include "mock_private.h"

/* This file is only used when running "make check".  It is built into
 * libcrmcommon_test.a, not into libcrmcommon.so.  It is used to support
 * constructing mock versions of library functions for unit testing.
 *
 * HOW TO ADD A MOCKED FUNCTION:
 *
 * - In this file, declare a bool pcmk__mock_X variable, and define a __wrap_X
 *   function with the same prototype as the actual function that performs the
 *   desired behavior if pcmk__mock_X is true and calls __real_X otherwise.
 *   You can use cmocka's mock_type() and mock_ptr_type() to pass extra
 *   information to the mocked function (see existing examples for details).
 *
 * - In mock_private.h, add declarations for extern bool pcmk__mock_X and the
 *   __real_X and __wrap_X function prototypes.
 *
 * - In mk/tap.mk, add the function name to the WRAPPED variable.
 *
 * HOW TO USE A MOCKED FUNCTION:
 *
 * - #include "mock_private.h" in your test file.
 *
 * - Write your test cases using pcmk__mock_X and cmocka's will_return() as
 *   needed per the comments for the mocked function below. See existing test
 *   cases for examples.
 */

// LCOV_EXCL_START
/* calloc()
 *
 * If pcmk__mock_calloc is set to true, later calls to calloc() will return
 * NULL and must be preceded by:
 *
 *     expect_*(__wrap_calloc, nmemb[, ...]);
 *     expect_*(__wrap_calloc, size[, ...]);
 *
 * expect_* functions: https://api.cmocka.org/group__cmocka__param.html
 */

bool pcmk__mock_calloc = false;

void *
__wrap_calloc(size_t nmemb, size_t size)
{
    if (!pcmk__mock_calloc) {
        return __real_calloc(nmemb, size);
    }
    check_expected(nmemb);
    check_expected(size);
    return NULL;
}


/* getenv()
 *
 * If pcmk__mock_getenv is set to true, later calls to getenv() must be preceded
 * by:
 *
 *     expect_*(__wrap_getenv, name[, ...]);
 *     will_return(__wrap_getenv, return_value);
 *
 * expect_* functions: https://api.cmocka.org/group__cmocka__param.html
 */

bool pcmk__mock_getenv = false;

char *
__wrap_getenv(const char *name)
{
    if (!pcmk__mock_getenv) {
        return __real_getenv(name);
    }
    check_expected_ptr(name);
    return mock_ptr_type(char *);
}


/* getpid()
 *
 * If pcmk__mock_getpid is set to true, later calls to getpid() must be preceded
 * by:
 *
 *     will_return(__wrap_getpid, return_value);
 */

bool pcmk__mock_getpid = false;

pid_t
__wrap_getpid(void)
{
    return pcmk__mock_getpid? mock_type(pid_t) : __real_getpid();
}


/* setgrent(), getgrent() and endgrent()
 *
 * If pcmk__mock_grent is set to true, getgrent() will behave as if the only
 * groups on the system are:
 *
 * - grp0 (user0, user1)
 * - grp1 (user1)
 * - grp2 (user2, user1)
 */

bool pcmk__mock_grent = false;

// Index of group that will be returned next from getgrent()
static int group_idx = 0;

// Data used for testing
static const char* grp0_members[] = {
    "user0", "user1", NULL
};

static const char* grp1_members[] = {
    "user1", NULL
};

static const char* grp2_members[] = {
    "user2", "user1", NULL
};

/* An array of "groups" (a struct from grp.h)
 *
 * The members of the groups are initalized here to some testing data, casting
 * away the consts to make the compiler happy and simplify initialization. We
 * never actually change these variables during the test!
 *
 * string literal = const char* (cannot be changed b/c ? )
 *                  vs. char* (it's getting casted to this)
 */
static const int NUM_GROUPS = 3;
static struct group groups[] = {
    {(char*)"grp0", (char*)"", 0, (char**)grp0_members},
    {(char*)"grp1", (char*)"", 1, (char**)grp1_members},
    {(char*)"grp2", (char*)"", 2, (char**)grp2_members},
};

// This function resets the group_idx to 0.
void
__wrap_setgrent(void) {
    if (pcmk__mock_grent) {
        group_idx = 0;
    } else {
        __real_setgrent();
    }
}

/* This function returns the next group entry in the list of groups, or
 * NULL if there aren't any left.
 * group_idx is a global variable which keeps track of where you are in the list
 */
struct group *
__wrap_getgrent(void) {
    if (pcmk__mock_grent) {
        if (group_idx >= NUM_GROUPS) {
            return NULL;
        }
        return &groups[group_idx++];
    } else {
        return __real_getgrent();
    }
}

void
__wrap_endgrent(void) {
    if (!pcmk__mock_grent) {
        __real_endgrent();
    }
}


/* fopen()
 *
 * If pcmk__mock_fopen is set to true, later calls to fopen() must be
 * preceded by:
 *
 *     expect_*(__wrap_fopen, pathname[, ...]);
 *     expect_*(__wrap_fopen, mode[, ...]);
 *     will_return(__wrap_fopen, errno_to_set);
 *
 * expect_* functions: https://api.cmocka.org/group__cmocka__param.html
 */

bool pcmk__mock_fopen = false;

FILE *
__wrap_fopen(const char *pathname, const char *mode)
{
    if (pcmk__mock_fopen) {
        check_expected_ptr(pathname);
        check_expected_ptr(mode);
        errno = mock_type(int);

        if (errno != 0) {
            return NULL;
        } else {
            return __real_fopen(pathname, mode);
        }

    } else {
        return __real_fopen(pathname, mode);
    }
}


/* getpwnam_r()
 *
 * If pcmk__mock_getpwnam_r is set to true, later calls to getpwnam_r() must be
 * preceded by:
 *
 *     expect_*(__wrap_getpwnam_r, name[, ...]);
 *     expect_*(__wrap_getpwnam_r, pwd[, ...]);
 *     expect_*(__wrap_getpwnam_r, buf[, ...]);
 *     expect_*(__wrap_getpwnam_r, buflen[, ...]);
 *     expect_*(__wrap_getpwnam_r, result[, ...]);
 *     will_return(__wrap_getpwnam_r, return_value);
 *     will_return(__wrap_getpwnam_r, ptr_to_result_struct);
 *
 * expect_* functions: https://api.cmocka.org/group__cmocka__param.html
 */

bool pcmk__mock_getpwnam_r = false;

int
__wrap_getpwnam_r(const char *name, struct passwd *pwd, char *buf,
                  size_t buflen, struct passwd **result)
{
    if (pcmk__mock_getpwnam_r) {
        int retval = mock_type(int);

        check_expected_ptr(name);
        check_expected_ptr(pwd);
        check_expected_ptr(buf);
        check_expected(buflen);
        check_expected_ptr(result);
        *result = mock_ptr_type(struct passwd *);
        return retval;

    } else {
        return __real_getpwnam_r(name, pwd, buf, buflen, result);
    }
}

/*
 * If pcmk__mock_readlink is set to true, later calls to readlink() must be
 * preceded by:
 *
 *     expect_*(__wrap_readlink, path[, ...]);
 *     expect_*(__wrap_readlink, buf[, ...]);
 *     expect_*(__wrap_readlink, bufsize[, ...]);
 *     will_return(__wrap_readlink, errno_to_set);
 *     will_return(__wrap_readlink, link_contents);
 *
 * expect_* functions: https://api.cmocka.org/group__cmocka__param.html
 *
 * The mocked function will return 0 if errno_to_set is 0, and -1 otherwise.
 */

bool pcmk__mock_readlink = false;

ssize_t
__wrap_readlink(const char *restrict path, char *restrict buf,
                size_t bufsize)
{
    if (pcmk__mock_readlink) {
        const char *contents = NULL;

        check_expected_ptr(path);
        check_expected_ptr(buf);
        check_expected(bufsize);
        errno = mock_type(int);
        contents = mock_ptr_type(const char *);

        if (errno == 0) {
            strncpy(buf, contents, bufsize - 1);
            return strlen(contents);
        }
        return -1;

    } else {
        return __real_readlink(path, buf, bufsize);
    }
}


/* strdup()
 *
 * If pcmk__mock_strdup is set to true, later calls to strdup() will return
 * NULL and must be preceded by:
 *
 *     expect_*(__wrap_strdup, s[, ...]);
 *
 * expect_* functions: https://api.cmocka.org/group__cmocka__param.html
 */

bool pcmk__mock_strdup = false;

char *
__wrap_strdup(const char *s)
{
    if (!pcmk__mock_strdup) {
        return __real_strdup(s);
    }
    check_expected_ptr(s);
    return NULL;
}


/* uname()
 *
 * If pcmk__mock_uname is set to true, later calls to uname() must be preceded
 * by:
 *
 *     will_return(__wrap_uname, return_value);
 *     will_return(__wrap_uname, node_name_for_buf_parameter_to_uname);
 */

bool pcmk__mock_uname = false;

int
__wrap_uname(struct utsname *buf)
{
    if (pcmk__mock_uname) {
        int retval = mock_type(int);
        char *result = mock_ptr_type(char *);

        if (result != NULL) {
            strcpy(buf->nodename, result);
        }
        return retval;

    } else {
        return __real_uname(buf);
    }
}

// LCOV_EXCL_STOP
