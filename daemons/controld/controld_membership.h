/*
 * Copyright 2012-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef MEMBERSHIP__H
#  define MEMBERSHIP__H

#ifdef __cplusplus
extern "C" {
#endif

#include <crm/cluster/internal.h>

void post_cache_update(int instance);

extern gboolean check_join_state(enum crmd_fsa_state cur_state, const char *source);

#define proc_flags (crm_proc_controld | crm_get_cluster_proc())

#ifdef __cplusplus
}
#endif

#endif
