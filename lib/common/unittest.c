/*
 * Copyright 2024 the Pacemaker project contributors
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

// LCOV_EXCL_START

void
pcmk__assert_validates(xmlNode *xml)
{
    const char *schema_dir = NULL;
    char *cmd = NULL;
    gchar *out = NULL;
    gchar *err = NULL;
    gint status;
    GError *gerr = NULL;
    char *xmllint_input = crm_strdup_printf("%s/test-xmllint.XXXXXX",
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

    cmd = crm_strdup_printf("xmllint --relaxng %s/api/api-result.rng %s",
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

int
pcmk__cib_test_setup_group(void **state)
{
    /* This needs to be run before we attempt to read in a CIB or it will fail
     * to validate.  There's no harm in doing this before all tests.
     */
    pcmk__xml_init();
    return 0;
}

char *
pcmk__cib_test_copy_cib(const char *in_file)
{
    char *in_path = crm_strdup_printf("%s/%s", getenv("PCMK_CTS_CLI_DIR"), in_file);
    char *out_path = NULL;
    char *contents = NULL;
    int fd;

    /* Copy the CIB over to a temp location so we can modify it. */
    out_path = crm_strdup_printf("%s/test-cib.XXXXXX", pcmk__get_tmpdir());

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

// LCOV_EXCL_STOP
