/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_SCHEMAS_COMPAT__H
#define PCMK__CRM_COMMON_SCHEMAS_COMPAT__H

#include <libxml/tree.h>    // xmlNode
#include <glib.h>           // gboolean

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker XML schemas API
 * \ingroup core
 * \deprecated Do not include this header directly. The APIs in this header, and
 *             the header itself, will be removed in a future release.
 */

//! \deprecated Do not use
const char *xml_latest_schema(void);

//! \deprecated Do not use
const char *get_schema_name(int version);

//! \deprecated Do not use
int get_schema_version(const char *name);

//! \deprecated Do not use
int update_validation(xmlNode **xml_blob, int *best, int max,
                      gboolean transform, gboolean to_logs);

//! \deprecated Do not use
gboolean validate_xml(xmlNode *xml_blob, const char *validation,
                      gboolean to_logs);

//! \deprecated Do not use
gboolean validate_xml_verbose(const xmlNode *xml_blob);

//! \deprecated Do not use
gboolean cli_config_update(xmlNode **xml, int *best_version, gboolean to_logs);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_SCHEMAS_COMPAT__H
