/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <glib.h>		// g_str_has_prefix()

#include <crm/crm.h>
#include <crm/common/util.h>

/*!
 * \brief Get capabilities of a resource agent standard
 *
 * \param[in] standard  Standard name
 *
 * \return Bitmask of enum pcmk_ra_caps values
 */
uint32_t
pcmk_get_ra_caps(const char *standard)
{
    /* @COMPAT This should probably be case-sensitive, but isn't,
     * for backward compatibility.
     */
    if (standard == NULL) {
        return pcmk_ra_cap_none;

    } else if (!strcasecmp(standard, PCMK_RESOURCE_CLASS_OCF)) {
        return pcmk_ra_cap_provider | pcmk_ra_cap_params
               | pcmk_ra_cap_unique | pcmk_ra_cap_promotable
               | pcmk_ra_cap_cli_exec;

    } else if (!strcasecmp(standard, PCMK_RESOURCE_CLASS_STONITH)) {
        /* @COMPAT Stonith resources can't really be unique clones, but we've
         * allowed it in the past and have it in some scheduler regression tests
         * (which were likely never used as real configurations).
         *
         * @TODO Remove pcmk_ra_cap_unique at the next major schema version
         * bump, with a transform to remove PCMK_META_GLOBALLY_UNIQUE from the
         * config.
         */
        return pcmk_ra_cap_params | pcmk_ra_cap_unique | pcmk_ra_cap_stdin
               | pcmk_ra_cap_fence_params;

    } else if (!strcasecmp(standard, PCMK_RESOURCE_CLASS_LSB)) {
        return pcmk_ra_cap_status | pcmk_ra_cap_cli_exec;

    } else if (!strcasecmp(standard, PCMK_RESOURCE_CLASS_SYSTEMD)
               || !strcasecmp(standard, PCMK_RESOURCE_CLASS_SERVICE)) {
        return pcmk_ra_cap_status;
    }
    return pcmk_ra_cap_none;
}

int
pcmk__effective_rc(int rc)
{
    int remapped_rc = rc;

    switch (rc) {
        case PCMK_OCF_DEGRADED:
            remapped_rc = PCMK_OCF_OK;
            break;

        case PCMK_OCF_DEGRADED_PROMOTED:
            remapped_rc = PCMK_OCF_RUNNING_PROMOTED;
            break;

        default:
            break;
    }

    return remapped_rc;
}

char *
crm_generate_ra_key(const char *standard, const char *provider,
                    const char *type)
{
    bool std_empty = pcmk__str_empty(standard);
    bool prov_empty = pcmk__str_empty(provider);
    bool ty_empty = pcmk__str_empty(type);

    if (std_empty || ty_empty) {
        return NULL;
    }

    return pcmk__assert_asprintf("%s%s%s:%s",
                                 standard,
                                 (prov_empty ? "" : ":"),
                                 (prov_empty ? "" : provider),
                                 type);
}

/*!
 * \brief Parse a "standard[:provider]:type" agent specification
 *
 * \param[in]  spec      Agent specification
 * \param[out] standard  Where to store agent standard (may not be \c NULL)
 * \param[out] provider  Where to store agent provider if the standard supports
 *                       one (may not be \c NULL)
 * \param[put] type      Where to store agent type (may not be \c NULL)
 *
 * \return \c pcmk_ok if the string could be parsed, \c -EINVAL otherwise
 *
 * \note It is acceptable for the type to contain a ':' if the standard supports
 *       that. For example, systemd supports the form "systemd:UNIT@A:B".
 * \note On success, the caller is responsible for freeing \p *standard,
 *       \p *provider, and \p *type using \c free(). On failure, all of these
 *       are left unchanged.
 */
int
crm_parse_agent_spec(const char *spec, char **standard, char **provider,
                     char **type)
{
    gchar **parts = NULL;
    int rc = pcmk_ok;

    CRM_CHECK((spec != NULL) && (standard != NULL) && (provider != NULL)
              && (type != NULL), return -EINVAL);

    parts = g_strsplit(spec, ":", 3);

    if (pcmk__str_empty(parts[0])) {
        // Empty standard
        rc = -EINVAL;
        goto done;
    }

    if (pcmk__is_set(pcmk_get_ra_caps(parts[0]), pcmk_ra_cap_provider)) {
        if (pcmk__str_empty(parts[1]) || pcmk__str_empty(parts[2])) {
            // Empty provider or type
            rc = -EINVAL;
            goto done;
        }

        *standard = pcmk__str_copy(parts[0]);
        *provider = pcmk__str_copy(parts[1]);
        *type = pcmk__str_copy(parts[2]);

    } else {
        if (pcmk__str_empty(parts[1])) {
            // Empty type
            rc = -EINVAL;
            goto done;
        }

        *standard = pcmk__str_copy(parts[0]);

        if (parts[2] == NULL) {
            // Common case: type does not contain a colon
            *type = pcmk__str_copy(parts[1]);

        } else {
            // Accommodate "systemd:UNIT@A:B", for example
            gchar *joined = g_strjoinv(":", parts + 1);

            *type = pcmk__str_copy(joined);
            g_free(joined);
        }
    }

done:
    g_strfreev(parts);
    return rc;
}

/*!
 * \brief Check whether a given stonith parameter is handled by Pacemaker
 *
 * Return true if a given string is the name of one of the special resource
 * instance attributes interpreted directly by Pacemaker for stonith-class
 * resources.
 *
 * \param[in] param  Parameter name to check
 *
 * \return true if \p param is a special fencing parameter
 */
bool
pcmk_stonith_param(const char *param)
{
    if (param == NULL) {
        return false;
    }

    /* @COMPAT Pacemaker does not handle PCMK__FENCING_STONITH_TIMEOUT specially
     * as a resource parameter, so pcmk_stonith_param() should not return true
     * for it. It is unclear from the commit history why we returned true for it
     * in the first place.
     *
     * However, when the feature set is less than 3.16.0,
     * calculate_secure_digest() filters out these special fencing parameters
     * when calculating the digest. There's no good reason why a user should
     * have configured this as a fence resource parameter in the first place.
     *
     * But out of an abundance of caution, we should wait to drop
     * PCMK__FENCING_STONITH_TIMEOUT from this function until we no longer
     * support rolling upgrades from below Pacemaker 2.1.5.
     */
    if (pcmk__str_any_of(param, PCMK_FENCING_PROVIDES,
                         PCMK__FENCING_STONITH_TIMEOUT, NULL)) {
        return true;
    }

    if (!g_str_has_prefix(param, "pcmk_")) { // Short-circuit common case
        return false;
    }
    if (pcmk__str_any_of(param,
                         PCMK_FENCING_ACTION_LIMIT,
                         PCMK_FENCING_DELAY_BASE,
                         PCMK_FENCING_DELAY_MAX,
                         PCMK_FENCING_HOST_ARGUMENT,
                         PCMK_FENCING_HOST_CHECK,
                         PCMK_FENCING_HOST_LIST,
                         PCMK_FENCING_HOST_MAP,
                         NULL)) {
        return true;
    }
    param = strchr(param + 5, '_'); // Skip past "pcmk_ACTION"
    return pcmk__str_any_of(param, "_action", "_timeout", "_retries", NULL);
}
