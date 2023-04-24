/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_SCHEDULER__H
#  define PCMK__CRM_COMMON_SCHEDULER__H

#include <crm/common/actions.h>
#include <crm/common/nodes.h>
#include <crm/common/resources.h>
#include <crm/common/roles.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API
 * \ingroup core
 */

//! Possible responses to loss of quorum
enum pe_quorum_policy {
    pcmk_no_quorum_freeze,  //<! Do not recover resources from outside partition
    pcmk_no_quorum_stop,    //<! Stop all resources in partition
    pcmk_no_quorum_ignore,  //<! Act as if partition still holds quorum
    pcmk_no_quorum_fence,   //<! Fence all nodes in partition
    pcmk_no_quorum_demote,  //<! Demote promotable resources and stop all others

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_no_quorum_freeze instead
    no_quorum_freeze    = pcmk_no_quorum_freeze,

    //! \deprecated Use pcmk_no_quorum_stop instead
    no_quorum_stop      = pcmk_no_quorum_stop,

    //! \deprecated Use pcmk_no_quorum_ignore instead
    no_quorum_ignore    = pcmk_no_quorum_ignore,

    //! \deprecated Use pcmk_no_quorum_fence instead
    no_quorum_suicide   = pcmk_no_quorum_fence,
#endif
    no_quorum_demote    = pcmk_no_quorum_demote,
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_SCHEDULER__H
