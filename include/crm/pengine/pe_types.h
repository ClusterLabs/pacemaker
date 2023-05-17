/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_PE_TYPES__H
#  define PCMK__CRM_PENGINE_PE_TYPES__H


#  include <stdbool.h>              // bool
#  include <sys/types.h>            // time_t
#  include <libxml/tree.h>          // xmlNode
#  include <glib.h>                 // gboolean, guint, GList, GHashTable
#  include <crm/common/iso8601.h>
#  include <crm/common/scheduler.h>
#  include <crm/pengine/common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Data types for cluster status
 * \ingroup pengine
 */

typedef struct pe_ticket_s {
    char *id;
    gboolean granted;
    time_t last_granted;
    gboolean standby;
    GHashTable *state;
} pe_ticket_t;

typedef struct pe_tag_s {
    char *id;
    GList *refs;
} pe_tag_t;

//!@{
//! \deprecated Do not use
enum pe_ordering {
    pe_order_none                  = 0x0,       /* deleted */
#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    pe_order_optional              = 0x1,       /* pure ordering, nothing implied */
    pe_order_apply_first_non_migratable = 0x2,  /* Only apply this constraint's ordering if first is not migratable. */

    pe_order_implies_first         = 0x10,      /* If 'then' is required, ensure 'first' is too */
    pe_order_implies_then          = 0x20,      /* If 'first' is required, ensure 'then' is too */
    pe_order_promoted_implies_first = 0x40,     /* If 'then' is required and then's rsc is promoted, ensure 'first' becomes required too */

    /* first requires then to be both runnable and migrate runnable. */
    pe_order_implies_first_migratable  = 0x80,

    pe_order_runnable_left         = 0x100,     /* 'then' requires 'first' to be runnable */

    pe_order_pseudo_left           = 0x200,     /* 'then' can only be pseudo if 'first' is runnable */
    pe_order_implies_then_on_node  = 0x400,     /* If 'first' is required on 'nodeX',
                                                 * ensure instances of 'then' on 'nodeX' are too.
                                                 * Only really useful if 'then' is a clone and 'first' is not
                                                 */
    pe_order_probe                 = 0x800,     /* If 'first->rsc' is
                                                 *  - running but about to stop, ignore the constraint
                                                 *  - otherwise, behave as runnable_left
                                                 */

    pe_order_restart               = 0x1000,    /* 'then' is runnable if 'first' is optional or runnable */
    pe_order_stonith_stop          = 0x2000,
    pe_order_serialize_only        = 0x4000,    /* serialize */
    pe_order_same_node             = 0x8000,    /* applies only if 'first' and 'then' are on same node */

    pe_order_implies_first_printed = 0x10000,   /* Like ..implies_first but only ensures 'first' is printed, not mandatory */
    pe_order_implies_then_printed  = 0x20000,   /* Like ..implies_then but only ensures 'then' is printed, not mandatory */

    pe_order_asymmetrical          = 0x100000,  /* Indicates asymmetrical one way ordering constraint. */
    pe_order_load                  = 0x200000,  /* Only relevant if... */
    pe_order_one_or_more           = 0x400000,  /* 'then' is runnable only if one or more of its dependencies are too */
    pe_order_anti_colocation       = 0x800000,

    pe_order_preserve              = 0x1000000, /* Hack for breaking user ordering constraints with container resources */
    pe_order_then_cancels_first    = 0x2000000, // if 'then' becomes required, 'first' becomes optional
    pe_order_trace                 = 0x4000000, /* test marker */

    pe_order_implies_first_master  = pe_order_promoted_implies_first,
#endif
};
//!@}

typedef struct pe_action_wrapper_s {
    enum pe_ordering type;
    enum pe_link_state state;
    pcmk_action_t *action;
} pe_action_wrapper_t;

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/pengine/pe_types_compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_PE_TYPES__H
