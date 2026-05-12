/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RULES__H
#define PCMK__CRM_COMMON_RULES__H

#include <regex.h>                  // regmatch_t

#include <glib.h>                   // guint, GHashTable

#include <crm/common/iso8601.h>     // crm_time_t

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for rules
 * \ingroup core
 */

/* Allowed subexpressions of a rule
 * @COMPAT This should be made internal at an API compatibility break
 */
//!@{
//! \deprecated For Pacemaker use only
enum expression_type {
    pcmk__condition_unknown   = 0,  // Unknown or invalid condition
    pcmk__condition_rule      = 1,  // Nested rule
    pcmk__condition_attribute = 2,  // Node attribute expression
    pcmk__condition_location  = 3,  // Node location expression
    pcmk__condition_datetime  = 5,  // Date/time expression
    pcmk__condition_resource  = 7,  // Resource agent expression
    pcmk__condition_operation = 8,  // Operation expression

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    not_expr        = pcmk__condition_unknown,
    nested_rule     = pcmk__condition_rule,
    attr_expr       = pcmk__condition_attribute,
    loc_expr        = pcmk__condition_location,
    role_expr       = 4,
    time_expr       = pcmk__condition_datetime,
    version_expr    = 6,
    rsc_expr        = pcmk__condition_resource,
    op_expr         = pcmk__condition_operation,
#endif
};
//!@}

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/rules_compat.h>
#endif

#endif // PCMK__CRM_COMMON_RULES__H
