/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_SCHEMAS__H
#  define PCMK__CRM_COMMON_SCHEMAS__H

#include <glib.h>           // gboolean
#include <libxml/tree.h>    // xmlNode

gboolean validate_xml_verbose(const xmlNode *xml_blob);

int get_schema_version(const char *name);
const char *get_schema_name(int version);
gboolean cli_config_update(xmlNode ** xml, int *best_version, gboolean to_logs);

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/schemas_compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_SCHEMAS__H
