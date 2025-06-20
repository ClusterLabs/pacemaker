/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_UNITTEST_INTERNAL__H
#define PCMK__CRM_COMMON_UNITTEST_INTERNAL__H

#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <setjmp.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>

#include <crm/common/xml.h>

#ifdef __cplusplus
extern "C" {
#endif

/* internal unit testing related utilities */

#if (PCMK__WITH_COVERAGE == 1)
/* This function isn't exposed anywhere.  The following prototype was taken from
 * /usr/lib/gcc/x86_64-redhat-linux/??/include/gcov.h
 */
extern void __gcov_dump(void);
#else
#define __gcov_dump()
#endif

/*!
 * \internal
 * \brief Assert that the XML output from an API function is valid
 *
 * \param[in] xml   The XML output of some public pacemaker API function
 *
 * Run the given XML through xmllint and attempt to validate it against the
 * api-result.rng schema file.  Assert if validation fails.
 *
 * \note PCMK_schema_directory needs to be set to the directory containing
 *       the built schema files before calling this function.  Typically,
 *       this will be done in Makefile.am.
 */
void pcmk__assert_validates(xmlNode *xml);

/*!
 * \internal
 * \brief Perform setup for a group of unit tests that will manipulate XML
 *
 * This function is suitable for being passed as the first argument to the
 * \c PCMK__UNIT_TEST macro.
 *
 * \param[in] state     The cmocka state object, currently unused by this
 *                      function
 */
int pcmk__xml_test_setup_group(void **state);

int pcmk__xml_test_teardown_group(void **state);

/*!
 * \internal
 * \brief Copy the given CIB file to a temporary file so it can be modified
 *        as part of doing unit tests, returning the full temporary file or
 *        \c NULL on error.
 *
 * This function should be called as part of the process of setting up any
 * single unit test that would access and modify a CIB.  That is, it should
 * be called from whatever function is the second argument to
 * cmocka_unit_test_setup_teardown.
 *
 * \param[in]   in_file     The filename of the input CIB file, which must
 *                          exist in the \c $PCMK_CTS_CLI_DIR directory.  This
 *                          should only be the filename, not the complete
 *                          path.
 */
char *pcmk__cib_test_copy_cib(const char *in_file);

/*!
 * \internal
 * \brief Clean up whatever was done by a previous call to
 *        \c pcmk__cib_test_copy_cib.
 *
 * This function should be called as part of the process of tearing down
 * any single unit test that accessed a CIB.  That is, it should be called
 * from whatever function is the third argument to
 * \c cmocka_unit_test_setup_teardown.
 *
 * \param[in]   out_path    The complete path to the temporary CIB location.
 *                          This is the return value of
 *                          \c pcmk__cib_test_copy_cib.
 */
void pcmk__cib_test_cleanup(char *out_path);

void pcmk__test_init_logging(const char *name, const char *filename);

/*!
 * \internal
 * \brief Assert that a statement aborts through pcmk__assert().
 *
 * \param[in] stmt  Statement to execute; can be an expression.
 *
 * A cmocka-like assert macro for use in unit testing. This one verifies that a
 * statement aborts through pcmk__assert(), erroring out if that is not the
 * case.
 *
 * This macro works by running the statement in a forked child process with core
 * dumps disabled (pcmk__assert() calls \c abort(), which will write out a core
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
            __gcov_dump(); \
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

/*!
 * \internal
 * \brief Assert that a statement aborts
 *
 * This is exactly the same as pcmk__assert_asserts (pcmk__assert() is
 * implemented with abort()), but given a different name for clarity.
 */
#define pcmk__assert_aborts(stmt) pcmk__assert_asserts(stmt)

/*!
 * \internal
 * \brief Assert that a statement exits with the expected exit status.
 *
 * \param[in] stmt  Statement to execute; can be an expression.
 * \param[in] rc    The expected exit status.
 *
 * This functions just like \c pcmk__assert_asserts, except that it tests for
 * an expected exit status.  Abnormal termination or incorrect exit status is
 * treated as a failure of the test.
 *
 * In the event that stmt does not exit at all, the special code \c CRM_EX_NONE
 * will be returned.  It is expected that this code is not used anywhere, thus
 * always causing an error.
 */
#define pcmk__assert_exits(rc, stmt) \
    do { \
        pid_t p = fork(); \
        if (p == 0) { \
            struct rlimit cores = { 0, 0 }; \
            setrlimit(RLIMIT_CORE, &cores); \
            stmt; \
            __gcov_dump(); \
            _exit(CRM_EX_NONE); \
        } else if (p > 0) { \
            int wstatus = 0; \
            if (waitpid(p, &wstatus, 0) == -1) { \
                fail_msg("waitpid failed"); \
            } \
            if (!WIFEXITED(wstatus)) { \
                fail_msg("statement terminated abnormally"); \
            } else if (WEXITSTATUS(wstatus) != rc) { \
                fail_msg("statement exited with %d, not expected %d", WEXITSTATUS(wstatus), rc); \
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

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_UNITTEST_INTERNAL__H
