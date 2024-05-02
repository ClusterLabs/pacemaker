/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_TICKETS__H
#  define PCMK__CRM_COMMON_TICKETS__H

#include <sys/types.h>      // time_t
#include <glib.h>           // gboolean, GHashTable

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for tickets
 * \ingroup core
 */

// Ticket constraint object
// @COMPAT Make internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
typedef struct pe_ticket_s {
    char *id;               // XML ID of ticket constraint or state
    gboolean granted;       // Whether cluster has been granted the ticket
    time_t last_granted;    // When cluster was last granted the ticket
    gboolean standby;       // Whether ticket is temporarily suspended
    GHashTable *state;      // XML attributes from ticket state
} pcmk_ticket_t;
//!@}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_TICKETS__H
