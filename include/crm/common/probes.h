/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_PROBES__H
#define PCMK__CRM_COMMON_PROBES__H

#include <stdbool.h>                        // bool
#include <glib.h>                           // guint
#include <libxml/tree.h>                    // xmlNode

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for probes
 * \ingroup core
 */

bool pcmk_is_probe(const char *task, guint interval);
bool pcmk_xe_is_probe(const xmlNode *xml_op);
bool pcmk_xe_mask_probe_failure(const xmlNode *xml_op);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_PROBES__H
