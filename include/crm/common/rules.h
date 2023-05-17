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
enum expression_type {
    not_expr        = 0,
    nested_rule     = 1,
    attr_expr       = 2,
    loc_expr        = 3,
    role_expr       = 4,
    time_expr       = 5,
#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    version_expr    = 6,
#endif
    rsc_expr        = 7,
    op_expr         = 8,
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RULES__H
