/*
 * Copyright 2021-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>
#include <pwd.h>
#include <setjmp.h>                         // Required by cmocka.h
#include <stdarg.h>                         // Required by cmocka.h
#include <stdbool.h>                        // Required by cmocka.h
#include <stddef.h>                         // Required by cmocka.h
#include <stdint.h>                         // Required by cmocka.h
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>                      // pid_t, size_t
#include <sys/utsname.h>
#include <unistd.h>
#include <grp.h>

#include <cmocka.h>
#include <crm/common/unittest_internal.h>
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

/* abort()
 *
 * Always mock abort - there's no pcmk__mock_abort tuneable to control this.
 * Because abort calls _exit(), which doesn't run any of the things registered
 * with atexit(), coverage numbers do not get written out.  This most noticably
 * affects places where we are testing that things abort when they should.
 *
 * The solution is this wrapper that is always enabled when we are running
 * unit tests (mock.c does not get included for the regular libcrmcommon.so).
 * All it does is dump coverage data and call the real abort().
 */
_Noreturn void
__wrap_abort(void)
{
#if (PCMK__WITH_COVERAGE == 1)
    __gcov_dump();
#endif
    __real_abort();
}

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
    check_expected_uint(nmemb);
    check_expected_uint(size);
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


/* realloc()
 *
 * If pcmk__mock_realloc is set to true, later calls to realloc() will return
 * NULL and must be preceded by:
 *
 *     expect_*(__wrap_realloc, ptr[, ...]);
 *     expect_*(__wrap_realloc, size[, ...]);
 *
 * expect_* functions: https://api.cmocka.org/group__cmocka__param.html
 */

bool pcmk__mock_realloc = false;

void *
__wrap_realloc(void *ptr, size_t size)
{
    if (!pcmk__mock_realloc) {
        return __real_realloc(ptr, size);
    }
    check_expected_ptr(ptr);
    check_expected_uint(size);
    return NULL;
}


/* setenv()
 *
 * If pcmk__mock_setenv is set to true, later calls to setenv() must be preceded
 * by:
 *
 *     expect_*(__wrap_setenv, name[, ...]);
 *     expect_*(__wrap_setenv, value[, ...]);
 *     expect_*(__wrap_setenv, overwrite[, ...]);
 *     will_return(__wrap_setenv, errno_to_set);
 *
 * expect_* functions: https://api.cmocka.org/group__cmocka__param.html
 *
 * The mocked function will return 0 if errno_to_set is 0, and -1 otherwise.
 */
bool pcmk__mock_setenv = false;

int
__wrap_setenv(const char *name, const char *value, int overwrite)
{
    if (!pcmk__mock_setenv) {
        return __real_setenv(name, value, overwrite);
    }
    check_expected_ptr(name);
    check_expected_ptr(value);
    check_expected_int(overwrite);
    errno = mock_type(int);
    return (errno == 0)? 0 : -1;
}


/* unsetenv()
 *
 * If pcmk__mock_unsetenv is set to true, later calls to unsetenv() must be
 * preceded by:
 *
 *     expect_*(__wrap_unsetenv, name[, ...]);
 *     will_return(__wrap_setenv, errno_to_set);
 *
 * expect_* functions: https://api.cmocka.org/group__cmocka__param.html
 *
 * The mocked function will return 0 if errno_to_set is 0, and -1 otherwise.
 */
bool pcmk__mock_unsetenv = false;

int
__wrap_unsetenv(const char *name)
{
    if (!pcmk__mock_unsetenv) {
        return __real_unsetenv(name);
    }
    check_expected_ptr(name);
    errno = mock_type(int);
    return (errno == 0)? 0 : -1;
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


/* getgrnam()
 *
 * If pcmk__mock_getgrnam is set to true, getgrnam() will behave as if the only
 * groups on the system are:
 *
 * - grp0 (user0, user1)
 * - grp1 (user1)
 * - grp2 (user2, user1)
 */

bool pcmk__mock_getgrnam = false;

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
static struct group groups[] = {
    {(char*)"grp0", (char*)"", 0, (char**)grp0_members},
    {(char*)"grp1", (char*)"", 1, (char**)grp1_members},
    {(char*)"grp2", (char*)"", 2, (char**)grp2_members},
};

/* This function returns the group entry whose name matches the argument, or
 * NULL if no match is found.
 */
struct group *
__wrap_getgrnam(const char *name) {
    if (pcmk__mock_getgrnam) {
        for (int i = 0; i < PCMK__NELEM(groups); i++) {
            if (pcmk__str_eq(groups[i].gr_name, name, pcmk__str_none)) {
                return &groups[i];
            }
        }

        return NULL;

    } else {
        return __real_getgrnam(name);
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
 *
 * This has two mocked functions, since fopen() is sometimes actually fopen64().
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

#ifdef HAVE_FOPEN64
FILE *
__wrap_fopen64(const char *pathname, const char *mode)
{
    if (pcmk__mock_fopen) {
        check_expected_ptr(pathname);
        check_expected_ptr(mode);
        errno = mock_type(int);

        if (errno != 0) {
            return NULL;
        } else {
            return __real_fopen64(pathname, mode);
        }

    } else {
        return __real_fopen64(pathname, mode);
    }
}
#endif

/* getpwnam()
 *
 * If pcmk__mock_getpwnam is set to true, later calls to getpwnam() must be
 * preceded by:
 *
 *     expect_*(__wrap_getpwnam, name[, ...]);
 *     will_return(__wrap_getpwnam, errno_to_set);
 *     will_return(__wrap_getpwnam, ptr_to_result_struct);
 *
 * expect_* functions: https://api.cmocka.org/group__cmocka__param.html
 */

bool pcmk__mock_getpwnam = false;

struct passwd *
__wrap_getpwnam(const char *name)
{
    if (pcmk__mock_getpwnam) {
        check_expected_ptr(name);
        errno = mock_type(int);
        return mock_ptr_type(struct passwd *);

    } else {
        return __real_getpwnam(name);
    }
}

/*
 * If pcmk__mock_readlink is set to true, later calls to readlink() must be
 * preceded by:
 *
 *     expect_*(__wrap_readlink, path[, ...]);
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
        check_expected_uint(bufsize);
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

// LCOV_EXCL_STOP
