/*
 * Copyright 2011-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include <glib.h>

#include <crm/common/util.h>

/*!
 * \internal
 * \brief Read file contents into a string, with trailing whitespace removed
 *
 * \param[in] filename  Name of file to read
 *
 * \return File contents as a string, or \c NULL on failure or empty file
 *
 * \note It would be simpler to call \c pcmk__file_contents() directly without
 *       trimming trailing whitespace. However, this would change hashes for
 *       existing value files that have trailing whitespace. Similarly, if we
 *       trim trailing whitespace, it would make sense to trim leading
 *       whitespace, but this changes existing hashes.
 */
static char *
read_file_trimmed(const char *filename)
{
    char *p = NULL;
    char *buf = NULL;
    int rc = pcmk__file_contents(filename, &buf);

    if (rc != pcmk_rc_ok) {
        pcmk__err("Failed to read %s: %s", filename, pcmk_rc_str(rc));
        free(buf);
        return NULL;
    }

    if (buf == NULL) {
        pcmk__err("File %s is empty", filename);
        return NULL;
    }

    // Strip trailing white space
    for (p = buf + strlen(buf) - 1; (p >= buf) && isspace(*p); p--);
    *(p + 1) = '\0';

    return buf;
}

/*!
 * \internal
 * \brief Read checksum from a file and compare against calculated checksum
 *
 * \param[in] filename      File containing stored checksum
 * \param[in] secret_value  String to calculate checksum from
 * \param[in] rsc_id        Resource ID (for logging only)
 * \param[in] param         Parameter name (for logging only)
 *
 * \return Standard Pacemaker return code
 */
static int
validate_hash(const char *filename, const char *secret_value,
              const char *rsc_id, const char *param)
{
    char *stored = NULL;
    char *calculated = NULL;
    int rc = pcmk_rc_ok;

    stored = read_file_trimmed(filename);
    if (stored == NULL) {
        pcmk__err("Could not read md5 sum for resource %s parameter '%s' from "
                  "file '%s'",
                  rsc_id, param, filename);
        rc = ENOENT;
        goto done;
    }

    calculated = pcmk__md5sum(secret_value);
    if (calculated == NULL) {
        // Should be impossible
        rc = EINVAL;
        goto done;
    }

    crm_trace("Stored hash: %s, calculated hash: %s", stored, calculated);

    if (!pcmk__str_eq(stored, calculated, pcmk__str_casei)) {
        pcmk__err("Calculated md5 sum for resource %s parameter '%s' does not "
                  "match stored md5 sum",
                  rsc_id, param);
        rc = pcmk_rc_cib_corrupt;
    }

done:
    free(stored);
    free(calculated);
    return rc;
}

/*!
 * \internal
 * \brief Read secret parameter values from file
 *
 * Given a table of resource parameters, if any of their values are the
 * magic string indicating a CIB secret, replace that string with the
 * secret read from the file appropriate to the given resource.
 *
 * \param[in]     rsc_id  Resource whose parameters are being checked
 * \param[in,out] params  Resource parameters to check
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__substitute_secrets(const char *rsc_id, GHashTable *params)
{
    GHashTableIter iter;
    char *param = NULL;
    char *value = NULL;
    GString *filename = NULL;
    gsize dir_len = 0;
    int rc = pcmk_rc_ok;

    if (params == NULL) {
        return pcmk_rc_ok;
    }

    // Some params are sent with operations, so we cannot cache secret params
    g_hash_table_iter_init(&iter, params);
    while (g_hash_table_iter_next(&iter, (gpointer *) &param,
                                  (gpointer *) &value)) {
        char *secret_value = NULL;
        int hash_rc = pcmk_rc_ok;

        if (!pcmk__str_eq(value, "lrm://", pcmk__str_none)) {
            // Not a secret parameter
            continue;
        }

        if (filename == NULL) {
            // First secret parameter. Fill in directory path for use with all.
            crm_debug("Replacing secret parameters for resource %s", rsc_id);

            filename = g_string_sized_new(128);
            pcmk__g_strcat(filename, PCMK__CIB_SECRETS_DIR "/", rsc_id, "/",
                           NULL);
            dir_len = filename->len;

        } else {
            // Reset filename to the resource's secrets directory path
            g_string_truncate(filename, dir_len);
        }

        // Path to file containing secret value for this parameter
        g_string_append(filename, param);
        secret_value = read_file_trimmed(filename->str);
        if (secret_value == NULL) {
            pcmk__err("Secret value for resource %s parameter '%s' not found "
                      "in " PCMK__CIB_SECRETS_DIR,
                      rsc_id, param);
            rc = ENOENT;
            continue;
        }

        // Path to file containing md5 sum for this parameter
        g_string_append(filename, ".sign");
        hash_rc = validate_hash(filename->str, secret_value, rsc_id, param);
        if (hash_rc != pcmk_rc_ok) {
            rc = hash_rc;
            free(secret_value);
            continue;
        }

        g_hash_table_iter_replace(&iter, (gpointer) secret_value);
    }

    if (filename != NULL) {
        g_string_free(filename, TRUE);
    }
    return rc;
}
