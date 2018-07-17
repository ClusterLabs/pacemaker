/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
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

char *
crm_generate_ra_key(const char *standard, const char *provider,
                    const char *type)
{
    if (!standard && !provider && !type) {
        return NULL;
    }

    return crm_strdup_printf("%s%s%s:%s",
                             (standard? standard : ""),
                             (provider? ":" : ""), (provider? provider : ""),
                             (type? type : ""));
}

/*!
 * \brief Check whether a resource standard requires a provider to be specified
 *
 * \param[in] standard  Standard name
 *
 * \return TRUE if standard requires a provider, FALSE otherwise
 */
bool
crm_provider_required(const char *standard)
{
    CRM_CHECK(standard != NULL, return FALSE);

    /* @TODO
     * - this should probably be case-sensitive, but isn't,
     *   for backward compatibility
     * - it might be nice to keep standards' capabilities (supports provider,
     *   can be promotable, etc.) as structured data somewhere
     */
    if (!strcasecmp(standard, PCMK_RESOURCE_CLASS_OCF)) {
        return TRUE;
    }
    return FALSE;
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

    if (crm_provider_required(*standard)) {
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
