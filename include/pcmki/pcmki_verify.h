/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_VERIFY__H
#  define PCMK__PCMKI_PCMKI_VERIFY__H

#include <crm/common/output_internal.h>
#include <crm/common/scheduler.h>
#include <libxml/tree.h>

/*!
 * \internal
 * \brief Parse a CIB file
 *
 * This function parses a CIB file into a CIB object
 *
 * \param[in]     out          Output to use for logging and printing results
 * \param[in]     cib_source   Source of the CIB: 
 *                             NULL -> use live cib, "-" -> stdin
 *                             "<..." -> xml str, otherwise -> xml file name                    
 * \param[in,out] cib_object   The resulting, parsed CIB object
 *
 * \return Standard Pacemaker return code
 */
int pcmk__parse_cib(pcmk__output_t *out, const char *cib_source, xmlNodePtr *cib_object);

/*!
 * \internal
 * \brief Verify that a CIB is error-free or output errors and warnings
 *
 * This high-level function essentially implements crm_verify(8). It operates
 * on an input CIB file, which can be inputted through one of several ways. It
 * can either write out XML-formatted output or plaintext output.
 *
 * \param[in,out] scheduler    Scheduler data
 * \param[in]     out          Output to use for logging and printing results
 * \param[in]     cib_object   The parsed CIB object
 *
 * \return Standard Pacemaker return code
 */
int pcmk__verify(pcmk_scheduler_t *scheduler, pcmk__output_t *out, xmlNode *cib_object);

#endif
