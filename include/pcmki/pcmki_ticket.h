/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_TICKET__H
#  define PCMK__PCMKI_PCMKI_TICKET__H

#include <crm/common/output_internal.h>

#include <crm/cib/cib_types.h>

/*!
 * \internal
 * \brief Display the constraints that apply to a given ticket
 *
 * \param[in,out]   out         Output object
 * \param[in]       cib         Open CIB connection
 * \param[in]       ticket_id   Ticket to find constraints for,
 *                              or \c NULL for all ticket constraints
 *
 * \return Standard Pacemaker return code
 */
int pcmk__ticket_constraints(pcmk__output_t *out, cib_t *cib, const char *ticket_id);

#endif
