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
 * HOW TO ADD A MOCKED FUNCTION:
 *
 * - Define a __wrap_X function here below with the same prototype as the
 *   actual function and that just calls __real_X.
 * - Add a __real_X and __wrap_X function prototype to mock_private.h.
 * - Add the function name to the WRAPPED variable in Makefile.am.
 *
 * HOW TO USE A MOCKED FUNCTION:
 *
 * - In the Makefile.am for your new test, add:
 *
 *   your_fn_test_LDADD = $(top_builddir)/lib/common/libcrmcommon_test.la -lcmocka
 *   your_fn_test_LDFLAGS = -Wl,--wrap=X
 *
 *   You can use multiple wrapped functions by adding multiple -Wl
 *   arguments.
 * - #include "mock_private.h" in your test file.
 * - Add a __wrap_X function with the same prototype as the real function.
 * - Write your test cases, using will_return(), mock_type(), and
 *   mock_ptr_type() from cmocka.  See existing test cases for details.
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
