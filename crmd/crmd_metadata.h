#ifndef CRMD_METADATA_H
#define CRMD_METADATA_H

/*
 * Copyright (C) 2017 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

enum ra_flags_e {
    ra_supports_reload  = 0x01,
    ra_uses_private     = 0x02,
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

GHashTable *metadata_cache_new(void);
void metadata_cache_free(GHashTable *mdc);
void metadata_cache_reset(GHashTable *mdc);
void metadata_cache_fini(void);

struct ra_metadata_s *metadata_cache_update(GHashTable *mdc,
                                            lrmd_rsc_info_t *rsc,
                                            const char *metadata_str);
struct ra_metadata_s *metadata_cache_get(GHashTable *mdc, lrmd_rsc_info_t *rsc);

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
