/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_PE_TYPES__H
#  define PCMK__CRM_PENGINE_PE_TYPES__H


#  include <stdbool.h>              // bool
#  include <sys/types.h>            // time_t
#  include <libxml/tree.h>          // xmlNode
#  include <glib.h>                 // gboolean, guint, GList, GHashTable
#  include <crm/common/iso8601.h>
#  include <crm/common/scheduler.h>
#  include <crm/pengine/common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Data types for cluster status
 * \ingroup pengine
 */

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/pengine/pe_types_compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_PE_TYPES__H
