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

#define MAX_VALUE_LEN 255

static bool
check_md5_hash(char *hash, char *value)
{
    bool rc = false;
    char *hash2 = NULL;

    hash2 = crm_md5sum(value);
    crm_debug("hash: %s, calculated hash: %s", hash, hash2);
    if (pcmk__str_eq(hash, hash2, pcmk__str_casei)) {
        rc = true;
    }
    free(hash2);
    return rc;
}

static char *
read_local_file(char *local_file)
{
    FILE *fp = fopen(local_file, "r");
    char buf[MAX_VALUE_LEN+1];
    char *p;

    if (!fp) {
        if (errno != ENOENT) {
            crm_perror(LOG_ERR, "cannot open %s" , local_file);
        }
        return NULL;
    }

    if (!fgets(buf, MAX_VALUE_LEN, fp)) {
        crm_perror(LOG_ERR, "cannot read %s", local_file);
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    // Strip trailing white space
    for (p = buf + strlen(buf) - 1; (p >= buf) && isspace(*p); p--);
    *(p+1) = '\0';
    return strdup(buf);
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
        char *hash = NULL;

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
        secret_value = read_local_file(filename->str);
        if (secret_value == NULL) {
            crm_err("Secret value for resource %s parameter '%s' not found in "
                    PCMK__CIB_SECRETS_DIR,
                    rsc_id, param);
            rc = ENOENT;
            continue;
        }

        // Path to file containing md5 sum for this parameter
        g_string_append(filename, ".sign");
        hash = read_local_file(filename->str);
        if (hash == NULL) {
            crm_err("Could not read md5 sum for resource %s parameter '%s' "
                    "from file '%s'",
                    rsc_id, param, filename->str);
            free(secret_value);
            rc = ENOENT;
            continue;
        }

        if (!check_md5_hash(hash, secret_value)) {
            crm_err("Calculated md5 sum for resource %s parameter '%s' does "
                    "not match stored md5 sum",
                    rsc_id, param);
            free(secret_value);
            free(hash);
            rc = pcmk_rc_cib_corrupt;
            continue;
        }

        free(hash);
        g_hash_table_iter_replace(&iter, (gpointer) secret_value);
    }

    if (filename != NULL) {
        g_string_free(filename, TRUE);
    }
    return rc;
}
