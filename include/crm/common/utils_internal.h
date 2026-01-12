/*
 * Copyright 2015-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <utils_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_UTILS_INTERNAL__H
#define PCMK__CRM_COMMON_UTILS_INTERNAL__H

#include <sys/types.h>          // pid_t, uid_t, gid_t

#include <glib.h>               // GSourceFunc, gpointer, guint

#ifdef __cplusplus
extern "C" {
#endif

// Number of elements in a statically defined array
#define PCMK__NELEM(a) ((int) (sizeof(a)/sizeof(a[0])) )

int pcmk__compare_versions(const char *version1, const char *version2);

int pcmk__daemon_user(uid_t *uid, gid_t *gid);
bool pcmk__is_user_in_group(const char *user, const char *group);
int pcmk__lookup_user(const char *name, uid_t *uid, gid_t *gid);

char *pcmk__generate_uuid(void);
void pcmk__panic(const char *reason);
pid_t pcmk__locate_sbd(void);
void pcmk__sleep_ms(unsigned int ms);
guint pcmk__create_timer(guint interval_ms, GSourceFunc fn, gpointer data);
guint pcmk__timeout_ms2s(guint timeout_ms);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_UTILS_INTERNAL__H
