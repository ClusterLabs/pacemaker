/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CIB_UTIL__H
#define PCMK__CRM_CIB_UTIL__H

#include <glib.h>               // gboolean
#include <libxml/tree.h>        // xmlNode

#include <crm/cib/cib_types.h>  // cib_t

#ifdef __cplusplus
extern "C" {
#endif

/* Utility functions */
xmlNode *createEmptyCib(int cib_epoch);

gboolean cib_version_details(xmlNode * cib, int *admin_epoch, int *epoch, int *updates);

int update_attr_delegate(cib_t * the_cib, int call_options,
                         const char *section, const char *node_uuid,
                         const char *set_type, const char *set_name,
                         const char *attr_id, const char *attr_name,
                         const char *attr_value, gboolean to_console,
                         const char *user_name, const char *node_type);

int find_nvpair_attr_delegate(cib_t * the_cib, const char *attr,
                              const char *section, const char *node_uuid,
                              const char *set_type, const char *set_name,
                              const char *attr_id, const char *attr_name,
                              gboolean to_console, char **value, const char *user_name);

int read_attr_delegate(cib_t * the_cib,
                       const char *section, const char *node_uuid,
                       const char *set_type, const char *set_name,
                       const char *attr_id, const char *attr_name,
                       char **attr_value, gboolean to_console, const char *user_name);

int delete_attr_delegate(cib_t * the_cib, int options,
                         const char *section, const char *node_uuid,
                         const char *set_type, const char *set_name,
                         const char *attr_id, const char *attr_name,
                         const char *attr_value, gboolean to_console, const char *user_name);

int query_node_uuid(cib_t * the_cib, const char *uname, char **uuid, int *is_remote_node);

// NOTE: sbd (as of at least 1.5.2) uses this
int cib_apply_patch_event(xmlNode *event, xmlNode *input, xmlNode **output,
                          int level);

#ifdef __cplusplus
}
#endif

#endif  // PCMK__CRM_CIB_UTIL__H
