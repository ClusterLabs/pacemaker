/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CIB_UTIL_COMPAT__H
#  define PCMK__CIB_UTIL_COMPAT__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker CIB API
 * \ingroup cib
 * \deprecated Do not include this header directly. The CIB APIs in this header,
 *             and the header itself, will be removed in a future release.
 */

//! \deprecated This function will be removed in a future version of Pacemaker
int cib_apply_patch_event(xmlNode *event, xmlNode *input, xmlNode **output,
                          int level);

#ifdef __cplusplus
}
#endif

#endif // PCMK_CIB_UTIL_COMPAT__H
