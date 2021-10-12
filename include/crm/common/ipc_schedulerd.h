/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__IPC_SCHEDULERD__H
#  define PCMK__IPC_SCHEDULERD__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief IPC commands for Schedulerd
 *
 * \ingroup core
 */

#include <crm/common/ipc.h>  // pcmk_ipc_api_t

//! Possible types of schedulerd replies
enum pcmk_schedulerd_api_reply {
    pcmk_schedulerd_reply_unknown,
    pcmk_schedulerd_reply_graph,
};

/*!
 * Schedulerd reply passed to event callback
 */
typedef struct {
    enum pcmk_schedulerd_api_reply reply_type;

    union {
        // pcmk__schedulerd_reply_graph
        struct {
            xmlNode *tgraph;
            const char *reference;
            const char *input;
        } graph;
    } data;
} pcmk_schedulerd_api_reply_t;

/*!
 * \brief Make an IPC request to the scheduler for the transition graph
 *
 * \param[in]  api IPC API connection
 * \param[in]  cib The CIB to create a transition graph for
 * \param[out] ref The reference ID a response will have
 *
 * \return Standard Pacemaker return code
 */
int pcmk_schedulerd_api_graph(pcmk_ipc_api_t *api, xmlNode *cib, char **ref);

#ifdef __cplusplus
}
#endif

#endif // PCMK__IPC_SCHEDULERD__H
