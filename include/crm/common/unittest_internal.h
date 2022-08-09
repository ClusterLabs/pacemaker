/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <signal.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CRM_COMMON_UNITTEST_INTERNAL__H
#define CRM_COMMON_UNITTEST_INTERNAL__H

/* internal unit testing related utilities */

/* A cmocka-like assert macro for use in unit testing.  This one verifies that
 * an expression aborts through CRM_ASSERT, erroring out if that is not the case.
 *
 * This macro works by running the expression in a forked child process with core
 * dumps disabled (CRM_ASSERT calls abort(), which will write out a core dump).
 * The parent waits for the child to exit and checks why.  If the child received
 * a SIGABRT, the test passes.  For all other cases, the test fails.
 */
#define pcmk__assert_asserts(expr) \
    do { \
        pid_t p = fork(); \
        if (p == 0) { \
            struct rlimit cores = { 0, 0 }; \
            setrlimit(RLIMIT_CORE, &cores); \
            expr; \
            _exit(0); \
        } else if (p > 0) { \
            int wstatus = 0; \
            if (waitpid(p, &wstatus, 0) == -1) { \
                fail_msg("waitpid failed"); \
            } \
            if (!(WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGABRT)) { \
                fail_msg("expr terminated without asserting"); \
            } \
        } else { \
            fail_msg("unable to fork for assert test"); \
        } \
    } while (0);

#endif /* CRM_COMMON_UNITTEST_INTERNAL__H */
