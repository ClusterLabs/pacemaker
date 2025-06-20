/*
 * Copyright 2015-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ACL_INTERNAL__H
#define PCMK__CRM_COMMON_ACL_INTERNAL__H

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

void pcmk__enable_acl(xmlNode *acl_source, xmlNode *target, const char *user);

bool pcmk__check_acl(xmlNode *xml, const char *attr_name,
                     enum pcmk__xml_flags mode);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_INTERNAL__H
