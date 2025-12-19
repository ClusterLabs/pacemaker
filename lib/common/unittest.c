/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <stdlib.h>
#include <unistd.h>

#include <libxml/parser.h>                  // xmlCleanupParser()

// LCOV_EXCL_START

static bool fake_text_init_succeeds = true;

void
pcmk__assert_validates(xmlNode *xml)
{
    const char *schema_dir = NULL;
    char *cmd = NULL;
    gchar *out = NULL;
    gchar *err = NULL;
    gint status;
    GError *gerr = NULL;
    char *xmllint_input = pcmk__assert_asprintf("%s/test-xmllint.XXXXXX",
                                                pcmk__get_tmpdir());
    int fd;
    int rc;

    fd = mkstemp(xmllint_input);
    if (fd < 0) {
        fail_msg("Could not create temp file: %s", strerror(errno));
    }

    rc = pcmk__xml2fd(fd, xml);
    if (rc != pcmk_rc_ok) {
        unlink(xmllint_input);
        fail_msg("Could not write temp file: %s", pcmk_rc_str(rc));
    }

    close(fd);

    /* This should be set as part of AM_TESTS_ENVIRONMENT in Makefile.am. */
    schema_dir = getenv("PCMK_schema_directory");
    if (schema_dir == NULL) {
        unlink(xmllint_input);
        fail_msg("PCMK_schema_directory is not set in test environment");
    }

    cmd = pcmk__assert_asprintf("xmllint --relaxng %s/api/api-result.rng %s",
                                schema_dir, xmllint_input);

    if (!g_spawn_command_line_sync(cmd, &out, &err, &status, &gerr)) {
        unlink(xmllint_input);
        fail_msg("Error occurred when performing validation: %s", gerr->message);
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        unlink(xmllint_input);
        fail_msg("XML validation failed: %s\n%s\n", out, err);
    }

    free(cmd);
    g_free(out);
    g_free(err);
    unlink(xmllint_input);
    free(xmllint_input);
}

/*!
 * \internal
 * \brief Perform setup for a group of unit tests that manipulate XML
 *
 * This function is suitable for being passed as the first argument to the
 * \c PCMK__UNIT_TEST macro.
 *
 * \param[in] state  Ignored
 *
 * \return 0
 */
int
pcmk__xml_test_setup_group(void **state)
{
    pcmk__schema_init();
    return 0;
}

/*!
 * \internal
 * \brief Perform teardown for a group of unit tests that manipulate XML
 *
 * This function is suitable for being passed as the second argument to the
 * \c PCMK__UNIT_TEST macro.
 *
 * \param[in] state  Ignored
 *
 * \return 0
 */
int
pcmk__xml_test_teardown_group(void **state)
{
    pcmk__schema_cleanup();
    xmlCleanupParser();
    return 0;
}

char *
pcmk__cib_test_copy_cib(const char *in_file)
{
    char *in_path = pcmk__assert_asprintf("%s/%s", getenv("PCMK_CTS_CLI_DIR"),
                                          in_file);
    char *out_path = NULL;
    char *contents = NULL;
    int fd;

    /* Copy the CIB over to a temp location so we can modify it. */
    out_path = pcmk__assert_asprintf("%s/test-cib.XXXXXX", pcmk__get_tmpdir());

    fd = mkstemp(out_path);
    if (fd < 0) {
        free(out_path);
        return NULL;
    }

    if (pcmk__file_contents(in_path, &contents) != pcmk_rc_ok) {
        free(out_path);
        close(fd);
        return NULL;
    }

    if (pcmk__write_sync(fd, contents) != pcmk_rc_ok) {
        free(out_path);
        free(in_path);
        free(contents);
        close(fd);
        return NULL;
    }

    setenv("CIB_file", out_path, 1);
    return out_path;
}

void
pcmk__cib_test_cleanup(char *out_path)
{
    unlink(out_path);
    free(out_path);
    unsetenv("CIB_file");
}

/*!
 * \internal
 * \brief Initialize logging for unit testing purposes
 *
 * \param[in] name      What to use as system name for logging
 * \param[in] filename  If not NULL, enable debug logs to this file (intended
 *                      for debugging during development rather than committed
 *                      unit tests)
 */
void
pcmk__test_init_logging(const char *name, const char *filename)
{
    pcmk__cli_init_logging(name, 0);
    if (filename != NULL) {
        pcmk__add_logfile(filename);
        set_crm_log_level(LOG_DEBUG);
    }
}


// Output test utilities

static bool
fake_text_init(pcmk__output_t *out)
{
    return fake_text_init_succeeds;
}

static void
fake_text_free_priv(pcmk__output_t *out)
{
    // Intentionally left blank
}

pcmk__output_t *
pcmk__mk_fake_text_output(char **argv)
{
    pcmk__output_t *retval = calloc(1, sizeof(pcmk__output_t));

    if (retval == NULL) {
        return NULL;
    }

    retval->fmt_name = "text";

    retval->init = fake_text_init;
    retval->free_priv = fake_text_free_priv;

    retval->register_message = pcmk__register_message;
    retval->message = pcmk__call_message;

    return retval;
}

void
pcmk__set_fake_text_init_succeeds(bool value)
{
    fake_text_init_succeeds = value;
}

// LCOV_EXCL_STOP
