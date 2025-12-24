/*
 * Copyright 2025-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef BASED_NOTIFY__H
#define BASED_NOTIFY__H

#include <stdint.h>                 // UINT64_C

#include <libxml/tree.h>            // xmlNode

/*!
 * \internal
 * \brief Flags for CIB manager client notification types
 *
 * These are used for setting the \c flags field of a \c pcmk__client_t.
 */
enum based_notify_flags {
    //! This flag has no effect
    based_nf_none = UINT64_C(0),

    //! Notify when the CIB changes
    based_nf_diff = (UINT64_C(1) << 0),
};

enum based_notify_flags based_parse_notify_flag(const char *text);

void based_diff_notify(const char *op, int result, const char *call_id,
                       const char *client_id, const char *client_name,
                       const char *origin, xmlNode *update, xmlNode *diff);

#endif // BASED_NOTIFY__H
