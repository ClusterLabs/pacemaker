/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RULES__H
#  define PCMK__CRM_COMMON_RULES__H

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
    pcmk__subexpr_unknown   = 0,        // Unknown subexpression type
    pcmk__subexpr_rule      = 1,        // Nested rule
    pcmk__subexpr_attribute = 2,        // Node attribute expression
    pcmk__subexpr_location  = 3,        // Node location expression
    pcmk__subexpr_datetime  = 5,        // Date/time expression
    pcmk__subexpr_resource  = 7,        // Resource agent expression
    pcmk__subexpr_operation = 8,        // Operation expression

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    not_expr        = pcmk__subexpr_unknown,
    nested_rule     = pcmk__subexpr_rule,
    attr_expr       = pcmk__subexpr_attribute,
    loc_expr        = pcmk__subexpr_location,
    role_expr       = 4,
    time_expr       = pcmk__subexpr_datetime,
    version_expr    = 6,
    rsc_expr        = pcmk__subexpr_resource,
    op_expr         = pcmk__subexpr_operation,
#endif
};
//!@}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RULES__H
