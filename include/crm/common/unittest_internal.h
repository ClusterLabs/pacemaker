/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>

#ifndef CRM_COMMON_UNITTEST_INTERNAL__H
#define CRM_COMMON_UNITTEST_INTERNAL__H

/* internal unit testing related utilities */

/*!
 * \internal
 * \brief Assert that a statement aborts through CRM_ASSERT().
 *
 * \param[in] stmt  Statement to execute; can be an expression.
 *
 * A cmocka-like assert macro for use in unit testing. This one verifies that a
 * statement aborts through CRM_ASSERT(), erroring out if that is not the case.
 *
 * This macro works by running the statement in a forked child process with core
 * dumps disabled (CRM_ASSERT() calls \c abort(), which will write out a core
 * dump). The parent waits for the child to exit and checks why. If the child
 * received a \c SIGABRT, the test passes. For all other cases, the test fails.
 *
 * \note If cmocka's expect_*() or will_return() macros are called along with
 *       pcmk__assert_asserts(), they must be called within a block that is
 *       passed as the \c stmt argument. That way, the values are added only to
 *       the child's queue. Otherwise, values added to the parent's queue will
 *       never be popped, and the test will fail.
 */
#define pcmk__assert_asserts(stmt) \
    do { \
        pid_t p = fork(); \
        if (p == 0) { \
            struct rlimit cores = { 0, 0 }; \
            setrlimit(RLIMIT_CORE, &cores); \
            stmt; \
            _exit(0); \
        } else if (p > 0) { \
            int wstatus = 0; \
            if (waitpid(p, &wstatus, 0) == -1) { \
                fail_msg("waitpid failed"); \
            } \
            if (!(WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGABRT)) { \
                fail_msg("statement terminated in child without asserting"); \
            } \
        } else { \
            fail_msg("unable to fork for assert test"); \
        } \
    } while (0);

/* Generate the main function of most unit test files.  Typically, group_setup
 * and group_teardown will be NULL.  The rest of the arguments are a list of
 * calls to cmocka_unit_test or cmocka_unit_test_setup_teardown to run the
 * individual unit tests.
 */
#define PCMK__UNIT_TEST(group_setup, group_teardown, ...) \
int \
main(int argc, char **argv) \
{ \
    const struct CMUnitTest t[] = { \
        __VA_ARGS__ \
    }; \
    cmocka_set_message_output(CM_OUTPUT_TAP); \
    return cmocka_run_group_tests(t, group_setup, group_teardown); \
}

#endif /* CRM_COMMON_UNITTEST_INTERNAL__H */
