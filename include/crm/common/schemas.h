/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_SCHEMAS__H
#define PCMK__CRM_COMMON_SCHEMAS__H

#include <libxml/tree.h>    // xmlNode

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief XML schema API
 * \ingroup core
 */

int
pcmk_update_configured_schema(xmlNode **xml);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_SCHEMAS__H
