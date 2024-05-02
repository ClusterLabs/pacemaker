/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_TAGS__H
#  define PCMK__CRM_COMMON_TAGS__H

#include <glib.h>           // GList

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for configuration tags
 * \ingroup core
 */

// Configuration tag object
// @COMPAT Make internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
typedef struct pe_tag_s {
    char *id;       // XML ID of tag
    GList *refs;    // XML IDs of objects that reference the tag
} pcmk_tag_t;
//!@}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_TAGS__H
