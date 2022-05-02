/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_IPC_ATTRD_INTERNAL__H
#  define PCMK__CRM_COMMON_IPC_ATTRD_INTERNAL__H

#include <glib.h>            // GList
#include <crm/common/ipc.h>  // pcmk_ipc_api_t

#ifdef __cplusplus
extern "C" {
#endif

//! Possible types of attribute manager replies
enum pcmk__attrd_api_reply {
    pcmk__attrd_reply_unknown,
    pcmk__attrd_reply_query,
};

// Information passed with pcmk__attrd_reply_query
typedef struct {
    const char *node;
    const char *name;
    const char *value;
} pcmk__attrd_query_pair_t;

/*!
 * Attribute manager reply passed to event callback
 *
 * \note The pointers in the reply are only guaranteed to be meaningful for the
 *       execution of the callback; if the values are needed for later, the
 *       callback should copy them.
 */
typedef struct {
    enum pcmk__attrd_api_reply reply_type;

    union {
        // pcmk__attrd_reply_query
        GList *pairs;
    } data;
} pcmk__attrd_api_reply_t;

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_IPC_ATTRD_INTERNAL__H
