/*
 * Copyright 2017-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef CRMD_METADATA_H
#define CRMD_METADATA_H

#include <stdint.h>             // uint32_t
#include <glib.h>               // GList, GHashTable
#include "controld_lrm.h"       // lrm_state_t, lrm_rsc_info_t

/*
 * @COMPAT pre-OCF-1.1 resource agents
 *
 * Pacemaker previously used the "reload" action to reload agent parameters,
 * but most agents used it to reload the service configuration. Pacemaker also
 * misused the OCF 1.0 "unique" parameter attribute to indicate reloadability.
 *
 * OCF 1.1 created the "reload-agent" action and "reloadable" parameter
 * attribute for the Pacemaker usage.
 *
 * Pacemaker now supports the OCF 1.1 usage. The old usage is now deprecated,
 * but will be supported if the agent does not claim OCF 1.1 or later
 * compliance and does not advertise the reload-agent action.
 */
enum ra_flags_e {
    ra_supports_legacy_reload   = (1 << 0),
    ra_supports_reload_agent    = (1 << 1),
};

enum ra_param_flags_e {
    ra_param_unique             = (1 << 0),
    ra_param_private            = (1 << 1),
    ra_param_reloadable         = (1 << 2),
};

// Allowed sources of resource agent meta-data when requesting it
enum controld_metadata_source_e {
    controld_metadata_from_cache    = (1 << 0),
    controld_metadata_from_agent    = (1 << 1),
};

struct ra_param_s {
    char *rap_name;
    uint32_t rap_flags; // bitmask of ra_param_flags_s
};

struct ra_metadata_s {
    char *ra_version;
    GList *ra_params;   // ra_param_s
    uint32_t ra_flags;  // bitmask of ra_flags_e
};

#define controld_set_ra_flags(ra_md, ra_key, flags_to_set) do {             \
        (ra_md)->ra_flags = pcmk__set_flags_as(__func__, __LINE__,          \
            LOG_TRACE, "Resource agent", ra_key,                            \
            (ra_md)->ra_flags, (flags_to_set), #flags_to_set);              \
    } while (0)

#define controld_set_ra_param_flags(ra_param, flags_to_set) do {            \
        (ra_param)->rap_flags = pcmk__set_flags_as(__func__, __LINE__,      \
            LOG_TRACE, "Resource agent parameter", (ra_param)->rap_name,    \
            (ra_param)->rap_flags, (flags_to_set), #flags_to_set);          \
    } while (0)

GHashTable *metadata_cache_new(void);
void metadata_cache_free(GHashTable *mdc);
void metadata_cache_reset(GHashTable *mdc);
void metadata_cache_fini(void);

struct ra_metadata_s *metadata_cache_update(GHashTable *mdc,
                                            const lrmd_rsc_info_t *rsc,
                                            const char *metadata_str);
struct ra_metadata_s *controld_get_rsc_metadata(lrm_state_t *lrm_state,
                                                const lrmd_rsc_info_t *rsc,
                                                uint32_t source);

static inline const char *
ra_param_flag2text(enum ra_param_flags_e flag)
{
    switch (flag) {
        case ra_param_reloadable:
            return "reloadable";
        case ra_param_unique:
            return "unique";
        case ra_param_private:
            return "private";
        default:
            return "unknown";
    }
}

#endif
