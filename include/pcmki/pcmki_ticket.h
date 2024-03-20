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
 * \brief Return the state XML for a given ticket
 *
 * \param[in]  cib          Open CIB connection
 * \param[in]  ticket_id    Ticket to get state for, or \c NULL for all tickets
 * \param[out] state        Where to store the result XML
 *
 * \return Standard Pacemaker return code
 *
 * \note If \p ticket_id is not \c NULL and more than one ticket exists with
 *       that ID, this function returns \c pcmk_rc_duplicate_id.
 */
int pcmk__get_ticket_state(cib_t *cib, const char *ticket_id, xmlNode **state);

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

/*!
 * \internal
 * \brief Delete a ticket's state from the local cluster site
 *
 * \param[in,out]   out         Output object
 * \param[in]       cib         Open CIB connection
 * \param[in]       scheduler   Scheduler data
 * \param[in]       ticket_id   Ticket to delete
 * \param[in]       force       If \c true, delete the ticket even if it has
 *                              been granted
 *
 * \return Standard Pacemaker return code
 */
int pcmk__ticket_delete(pcmk__output_t *out, cib_t *cib, pcmk_scheduler_t *scheduler,
                        const char *ticket_id, bool force);

/*!
 * \internal
 * \brief Return the value of a ticket's attribute
 *
 * \param[in,out]   out             Output object
 * \param[in,out]   scheduler       Scheduler data
 * \param[in]       ticket_id       Ticket to find attribute value for
 * \param[in]       attr_name       Attribute's name to find value for
 * \param[in]       attr_default    If either the ticket or the attribute do not
 *                                  exist, use this as the value in the output
 *
 * \return Standard Pacemaker return code
 */
int pcmk__ticket_get_attr(pcmk__output_t *out, pcmk_scheduler_t *scheduler,
                          const char *ticket_id, const char *attr_name,
                          const char *attr_default);

/*!
 * \brief Return information about the given ticket
 *
 * \param[in,out] out           Output object
 * \param[in,out] scheduler     Scheduler data
 * \param[in]     ticket_id     Ticket to display info for, or \c NULL for
 *                              all tickets
 * \param[in]     details       If true (and \p out is not an XML format
 *                              object), output any additional attributes
 *                              set on a ticket beyond the basics
 * \param[in]     raw           If true (and \p out is not an XML format
 *                              object), simply list the IDs of all tickets.
 *                              This does not make a lot of sense if
 *                              \p ticket_id is not NULL, but that will not
 *                              raise an error.
 *
 * \return Standard Pacemaker return code
 */
int pcmk__ticket_info(pcmk__output_t *out, pcmk_scheduler_t *scheduler,
                      const char *ticket_id, bool details, bool raw);

/*!
 * \brief Remove the given attribute(s) from a ticket
 *
 * \param[in,out] out           Output object
 * \param[in]     cib           Open CIB connection
 * \param[in,out] scheduler     Scheduler data
 * \param[in]     ticket_id     Ticket to remove attributes from
 * \param[in]     attr_delete   A list of attribute names
 *
 * \return Standard Pacemaker return code
 */
int pcmk__ticket_remove_attr(pcmk__output_t *out, cib_t *cib, pcmk_scheduler_t *scheduler,
                             const char *ticket_id, GList *attr_delete);

/*!
 * \brief Set the given attribute(s) on a ticket
 *
 * \param[in,out] out           Output object
 * \param[in]     cib           Open CIB connection
 * \param[in,out] scheduler     Scheduler data
 * \param[in]     ticket_id     Ticket to set attributes on
 * \param[in]     attr_set      A hash table of attributes, where keys are the
 *                              attribute names and the values are the attribute
 *                              values
 *
 * \return Standard Pacemaker return code
 *
 * \note If no \p ticket_id attribute exists but \p attr_set is non-NULL, the
 *       ticket will be created with the given attributes.
 */
int pcmk__ticket_set_attr(pcmk__output_t *out, cib_t *cib, pcmk_scheduler_t *scheduler,
                          const char *ticket_id, GHashTable *attr_set);

/*!
 * \internal
 * \brief Return a ticket's state XML
 *
 * \param[in,out]   out         Output object
 * \param[in]       cib         Open CIB connection
 * \param[in]       ticket_id   Ticket to find constraints for,
 *                              or \c NULL for all ticket constraints
 *
 * \return Standard Pacemaker return code
 *
 * \note If \p ticket_id is not \c NULL and more than one ticket exists with
 *       that ID, this function returns \c pcmk_rc_duplicate_id.
 */
int pcmk__ticket_state(pcmk__output_t *out, cib_t *cib, const char *ticket_id);

#endif
