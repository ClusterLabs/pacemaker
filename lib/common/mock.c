/*
 * Copyright 2021-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <pwd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "mock_private.h"

/* This file is only used when running "make check".  It is built into
 * libcrmcommon_test.a, not into libcrmcommon.so.  It is used to support
 * constructing mock versions of library functions for unit testing.
 *
 * Each unit test will only ever want to use a mocked version of one or two
 * library functions.  However, we need to mark all the mocked functions as
 * wrapped (with -Wl,--wrap= in the LDFLAGS) in libcrmcommon_test.a so that
 * all those unit tests can share the same special test library.  The unit
 * test then defines its own wrapped function.  Because a unit test won't
 * define every single wrapped function, there will be undefined references
 * at link time.
 *
 * This file takes care of those undefined references.  It defines a
 * wrapped version of every function that simply calls the real libc
 * version.  These wrapped versions are defined with a weak attribute,
 * which means the unit tests can define another wrapped version for
 * unit testing that will override the version defined here.
 *
 * IN SUMMARY:
 *
 * - Define two functions for each function listed in WRAPPED in mock.mk.
 *   One function is a weakly defined __wrap_X function that just calls
 *   __real_X.
 * - Add a __real_X and __wrap_X function prototype for each function to
 *   mock_private.h.
 * - Each unit test defines its own __wrap_X for whatever function it's
 *   mocking that overrides the version here.
 */

void *__attribute__((weak))
__wrap_calloc(size_t nmemb, size_t size) {
    return __real_calloc(nmemb, size);
}

char *__attribute__((weak))
__wrap_getenv(const char *name) {
    return __real_getenv(name);
}

int __attribute__((weak))
__wrap_getpwnam_r(const char *name, struct passwd *pwd,
                  char *buf, size_t buflen, struct passwd **result) {
    return __real_getpwnam_r(name, pwd, buf, buflen, result);
}

int __attribute__((weak))
__wrap_uname(struct utsname *buf) {
    return __real_uname(buf);
}
