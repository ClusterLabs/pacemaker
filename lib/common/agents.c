/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <strings.h>

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
               | pcmk_ra_cap_unique | pcmk_ra_cap_promotable;

    } else if (!strcasecmp(standard, PCMK_RESOURCE_CLASS_STONITH)) {
        /* @COMPAT Stonith resources can't really be unique clones, but we've
         * allowed it in the past and have it in some scheduler regression tests
         * (which were likely never used as real configurations).
         *
         * @TODO Remove pcmk_ra_cap_unique at the next major schema version
         * bump, with a transform to remove globally-unique from the config.
         */
        return pcmk_ra_cap_params | pcmk_ra_cap_unique | pcmk_ra_cap_stdin
               | pcmk_ra_cap_fence_params;

    } else if (!strcasecmp(standard, PCMK_RESOURCE_CLASS_SYSTEMD)
               || !strcasecmp(standard, PCMK_RESOURCE_CLASS_SERVICE)
               || !strcasecmp(standard, PCMK_RESOURCE_CLASS_LSB)
               || !strcasecmp(standard, PCMK_RESOURCE_CLASS_UPSTART)) {

        /* Since service can map to LSB, systemd, or upstart, these should
         * have identical capabilities
         */
        return pcmk_ra_cap_status;

    } else if (!strcasecmp(standard, PCMK_RESOURCE_CLASS_NAGIOS)) {
        return pcmk_ra_cap_params;
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

    return crm_strdup_printf("%s%s%s:%s",
                             standard,
                             (prov_empty ? "" : ":"), (prov_empty ? "" : provider),
                             type);
}

/*!
 * \brief Parse a "standard[:provider]:type" agent specification
 *
 * \param[in]  spec      Agent specification
 * \param[out] standard  Newly allocated memory containing agent standard (or NULL)
 * \param[out] provider  Newly allocated memory containing agent provider (or NULL)
 * \param[put] type      Newly allocated memory containing agent type (or NULL)
 *
 * \return pcmk_ok if the string could be parsed, -EINVAL otherwise
 *
 * \note It is acceptable for the type to contain a ':' if the standard supports
 *       that. For example, systemd supports the form "systemd:UNIT@A:B".
 * \note It is the caller's responsibility to free the returned values.
 */
int
crm_parse_agent_spec(const char *spec, char **standard, char **provider,
                     char **type)
{
    char *colon;

    CRM_CHECK(spec && standard && provider && type, return -EINVAL);
    *standard = NULL;
    *provider = NULL;
    *type = NULL;

    colon = strchr(spec, ':');
    if ((colon == NULL) || (colon == spec)) {
        return -EINVAL;
    }

    *standard = strndup(spec, colon - spec);
    spec = colon + 1;

    if (pcmk_is_set(pcmk_get_ra_caps(*standard), pcmk_ra_cap_provider)) {
        colon = strchr(spec, ':');
        if ((colon == NULL) || (colon == spec)) {
            free(*standard);
            return -EINVAL;
        }
        *provider = strndup(spec, colon - spec);
        spec = colon + 1;
    }

    if (*spec == '\0') {
        free(*standard);
        free(*provider);
        return -EINVAL;
    }

    *type = strdup(spec);
    return pcmk_ok;
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
    if (pcmk__str_any_of(param, PCMK_STONITH_PROVIDES,
                         PCMK_STONITH_STONITH_TIMEOUT, NULL)) {
        return true;
    }
    if (!pcmk__starts_with(param, "pcmk_")) { // Short-circuit common case
        return false;
    }
    if (pcmk__str_any_of(param,
                         PCMK_STONITH_ACTION_LIMIT,
                         PCMK_STONITH_DELAY_BASE,
                         PCMK_STONITH_DELAY_MAX,
                         PCMK_STONITH_HOST_ARGUMENT,
                         PCMK_STONITH_HOST_CHECK,
                         PCMK_STONITH_HOST_LIST,
                         PCMK_STONITH_HOST_MAP,
                         NULL)) {
        return true;
    }
    param = strchr(param + 5, '_'); // Skip past "pcmk_ACTION"
    return pcmk__str_any_of(param, "_action", "_timeout", "_retries", NULL);
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/agents_compat.h>

bool
crm_provider_required(const char *standard)
{
    return pcmk_is_set(pcmk_get_ra_caps(standard), pcmk_ra_cap_provider);
}

// LCOV_EXCL_STOP
// End deprecated API
