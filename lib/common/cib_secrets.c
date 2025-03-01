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

static int is_magic_value(char *p);
static bool check_md5_hash(char *hash, char *value);
static void add_secret_params(gpointer key, gpointer value, gpointer user_data);
static char *read_local_file(char *local_file);

#define MAX_VALUE_LEN 255
#define MAGIC "lrm://"

static int
is_magic_value(char *p)
{
    return !strcmp(p, MAGIC);
}

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
    GString *filename = NULL;
    gsize dir_len = 0;
    char *hash = NULL;
    GList *secret_params = NULL, *l;
    char *key, *pvalue, *secret_value;
    int rc = pcmk_rc_ok;

    if (params == NULL) {
        return pcmk_rc_ok;
    }

    /* secret_params could be cached with the resource;
     * there are also parameters sent with operations
     * which cannot be cached
     */
    g_hash_table_foreach(params, add_secret_params, &secret_params);
    if (secret_params == NULL) { // No secret parameters found
        return pcmk_rc_ok;
    }

    crm_debug("Replace secret parameters for resource %s", rsc_id);

    filename = g_string_sized_new(128);
    pcmk__g_strcat(filename, PCMK__CIB_SECRETS_DIR "/", rsc_id, "/", NULL);
    dir_len = filename->len;

    for (l = g_list_first(secret_params); l; l = g_list_next(l)) {
        key = (char *)(l->data);
        pvalue = g_hash_table_lookup(params, key);
        if (!pvalue) { /* this cannot really happen */
            crm_err("odd, no parameter %s for rsc %s found now", key, rsc_id);
            continue;
        }

        // Reset filename to the resource's secrets directory path
        g_string_truncate(filename, dir_len);

        // Now set filename to the secrets file for this particular parameter
        g_string_append(filename, key);

        secret_value = read_local_file(filename->str);
        if (!secret_value) {
            crm_err("secret for rsc %s parameter %s not found in %s",
                    rsc_id, key, PCMK__CIB_SECRETS_DIR);
            rc = ENOENT;
            continue;
        }

        g_string_append(filename, ".sign");
        hash = read_local_file(filename->str);
        if (hash == NULL) {
            crm_err("md5 sum for rsc %s parameter %s "
                    "cannot be read from %s", rsc_id, key, filename->str);
            free(secret_value);
            rc = ENOENT;
            continue;
        }

        if (!check_md5_hash(hash, secret_value)) {
            crm_err("md5 sum for rsc %s parameter %s "
                    "does not match", rsc_id, key);
            free(secret_value);
            free(hash);
            rc = pcmk_rc_cib_corrupt;
            continue;
        }
        free(hash);
        g_hash_table_replace(params, strdup(key), secret_value);
    }

    if (filename != NULL) {
        g_string_free(filename, TRUE);
    }
    g_list_free(secret_params);
    return rc;
}

static void
add_secret_params(gpointer key, gpointer value, gpointer user_data)
{
    GList **lp = (GList **)user_data;

    if (is_magic_value((char *)value)) {
        *lp = g_list_append(*lp, (char *)key);
    }
}
