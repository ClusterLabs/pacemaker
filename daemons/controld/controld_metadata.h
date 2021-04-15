/*
 * Copyright 2017-2020 the Pacemaker project contributors
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

enum ra_flags_e {
    ra_supports_reload  = 0x01,
};

enum ra_param_flags_e {
    ra_param_unique     = 0x01,
    ra_param_private    = 0x02,
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
                                            lrmd_rsc_info_t *rsc,
                                            const char *metadata_str);
struct ra_metadata_s *controld_get_rsc_metadata(lrm_state_t *lrm_state,
                                                lrmd_rsc_info_t *rsc,
                                                bool from_agent);

static inline const char *
ra_param_flag2text(enum ra_param_flags_e flag)
{
    switch (flag) {
        case ra_param_unique:
            return "unique";
        case ra_param_private:
            return "private";
        default:
            return "unknown";
    }
}

#endif
