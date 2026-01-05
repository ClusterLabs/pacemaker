/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <tickets_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_TICKETS_INTERNAL__H
#define PCMK__CRM_COMMON_TICKETS_INTERNAL__H

#include <stdint.h>         // uint32_t, UINT32_C()
#include <sys/types.h>      // time_t
#include <glib.h>           // GHashTable

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for tickets
 * \ingroup core
 */

/*!
 * \internal
 * \brief Set ticket flags
 *
 * \param[in,out] ticket        Ticket to set flags for
 * \param[in]     flags_to_set  Group of enum pcmk__ticket_flags to set
 */
#define pcmk__set_ticket_flags(ticket, flags_to_set) do {           \
        (ticket)->flags = pcmk__set_flags_as(__func__, __LINE__,    \
            LOG_TRACE, "Ticket", (ticket)->id, (ticket)->flags,     \
            (flags_to_set), #flags_to_set);                         \
    } while (0)

/*!
 * \internal
 * \brief Clear ticket flags
 *
 * \param[in,out] ticket          Ticket to clear flags for
 * \param[in]     flags_to_clear  Group of enum pcmk__ticket_flags to clear
 */
#define pcmk__clear_ticket_flags(ticket, flags_to_clear) do {       \
        (ticket)->flags = pcmk__clear_flags_as(__func__, __LINE__,  \
            LOG_TRACE, "Ticket", (ticket)->id, (ticket)->flags,     \
            (flags_to_clear), #flags_to_clear);                     \
    } while (0)

enum pcmk__ticket_flags {
    pcmk__ticket_none       = UINT32_C(0),
    pcmk__ticket_granted    = (UINT32_C(1) << 0),
    pcmk__ticket_standby    = (UINT32_C(1) << 1),
};

// Ticket constraint object
typedef struct {
    char *id;               // XML ID of ticket constraint or state
    GHashTable *state;      // XML attributes from ticket state
    time_t last_granted;    // When cluster was last granted the ticket
    uint32_t flags;         // Group of enum pcmk__ticket_flags
} pcmk__ticket_t;

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_TICKETS_INTERNAL__H
