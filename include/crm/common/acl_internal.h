/*
 * Copyright 2015-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <acl_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_ACL_INTERNAL__H
#define PCMK__CRM_COMMON_ACL_INTERNAL__H

#include <stdbool.h>
#include <string.h>         // strcmp()
#include <libxml/tree.h>    // xmlNode

#include <crm/common/xml_internal.h>    // enum pcmk__xml_flags

#ifdef __cplusplus
extern "C" {
#endif

/* internal ACL-related utilities */

char *pcmk__uid2username(uid_t uid);
const char *pcmk__update_acl_user(xmlNode *request, const char *field,
                                  const char *peer_user);

static inline bool
pcmk__is_privileged(const char *user)
{
    return user && (!strcmp(user, CRM_DAEMON_USER) || !strcmp(user, "root"));
}

void pcmk__enable_acls(xmlDoc *source, xmlDoc *target, const char *user);

xmlNode *pcmk__acl_filtered_copy(const char *user, xmlDoc *acl_source,
                                 xmlNode *xml);

bool pcmk__check_acl(xmlNode *xml, const char *attr_name,
                     enum pcmk__xml_flags mode);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_INTERNAL__H
