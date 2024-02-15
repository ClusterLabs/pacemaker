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
