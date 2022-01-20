/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_IPC_CONTROLD__H
#  define PCMK__CRM_COMMON_IPC_CONTROLD__H


#include <stdbool.h>                    // bool
#include <glib.h>                       // GList
#include <libxml/tree.h>                // xmlNode
#include <crm/common/ipc.h>             // pcmk_ipc_api_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief IPC commands for Pacemaker controller
 *
 * \ingroup core
 */

//! Possible types of controller replies
enum pcmk_controld_api_reply {
    pcmk_controld_reply_unknown,
    pcmk_controld_reply_reprobe,
    pcmk_controld_reply_info,
    pcmk_controld_reply_resource,
    pcmk_controld_reply_ping,
    pcmk_controld_reply_nodes,
};

// Node information passed with pcmk_controld_reply_nodes
typedef struct {
    uint32_t id;
    const char *uname;
    const char *state;
} pcmk_controld_api_node_t;

/*!
 * Controller reply passed to event callback
 *
 * \note Shutdown and election calls have no reply. Reprobe calls are
 *       acknowledged but contain no data (reply_type will be the only item
 *       set). Node info and ping calls have their own reply data. Fail and
 *       refresh calls use the resource reply type and reply data.
 * \note The pointers in the reply are only guaranteed to be meaningful for the
 *       execution of the callback; if the values are needed for later, the
 *       callback should copy them.
 */
typedef struct {
    enum pcmk_controld_api_reply reply_type;
    const char *feature_set; //!< CRM feature set advertised by controller
    const char *host_from;   //!< Name of node that sent reply

    union {
        // pcmk_controld_reply_info
        struct {
            bool have_quorum;
            bool is_remote;
            int id;
            const char *uuid;
            const char *uname;
            const char *state;
        } node_info;

        // pcmk_controld_reply_resource
        struct {
            xmlNode *node_state;    //<! Resource operation history XML
        } resource;

        // pcmk_controld_reply_ping
        struct {
            const char *sys_from;
            const char *fsa_state;
            const char *result;
        } ping;

        // pcmk_controld_reply_nodes
        GList *nodes; // list of pcmk_controld_api_node_t *
    } data;
} pcmk_controld_api_reply_t;

int pcmk_controld_api_reprobe(pcmk_ipc_api_t *api, const char *target_node,
                              const char *router_node);
int pcmk_controld_api_node_info(pcmk_ipc_api_t *api, uint32_t nodeid);
int pcmk_controld_api_fail(pcmk_ipc_api_t *api, const char *target_node,
                           const char *router_node, const char *rsc_id,
                           const char *rsc_long_id, const char *standard,
                           const char *provider, const char *type);
int pcmk_controld_api_refresh(pcmk_ipc_api_t *api, const char *target_node,
                              const char *router_node, const char *rsc_id,
                              const char *rsc_long_id, const char *standard,
                              const char *provider, const char *type,
                              bool cib_only);
int pcmk_controld_api_ping(pcmk_ipc_api_t *api, const char *node_name);
int pcmk_controld_api_list_nodes(pcmk_ipc_api_t *api);
unsigned int pcmk_controld_api_replies_expected(pcmk_ipc_api_t *api);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_IPC_CONTROLD__H
