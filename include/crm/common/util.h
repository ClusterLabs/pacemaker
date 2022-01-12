/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_COMMON_UTIL__H
#  define CRM_COMMON_UTIL__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Utility functions
 * \ingroup core
 */

#  include <sys/types.h>    // gid_t, mode_t, size_t, time_t, uid_t
#  include <stdlib.h>
#  include <stdbool.h>
#  include <stdint.h>       // uint32_t
#  include <limits.h>
#  include <signal.h>
#  include <glib.h>

#  include <libxml/tree.h>

#  include <crm/lrmd.h>
#  include <crm/common/acl.h>
#  include <crm/common/agents.h>
#  include <crm/common/results.h>

#  define ONLINESTATUS  "online"  // Status of an online client
#  define OFFLINESTATUS "offline" // Status of an offline client

/* public node attribute functions (from attrd_client.c) */
char *pcmk_promotion_score_name(const char *rsc_id);

/* public Pacemaker Remote functions (from remote.c) */
int crm_default_remote_port(void);

/* public string functions (from strings.c) */
gboolean crm_is_true(const char *s);
int crm_str_to_boolean(const char *s, int *ret);
long long crm_get_msec(const char *input);
char * crm_strip_trailing_newline(char *str);
char *crm_strdup_printf(char const *format, ...) G_GNUC_PRINTF(1, 2);

guint crm_parse_interval_spec(const char *input);
int char2score(const char *score);
char *score2char(int score);
char *score2char_stack(int score, char *buf, size_t len);

/* public operation functions (from operations.c) */
gboolean parse_op_key(const char *key, char **rsc_id, char **op_type,
                      guint *interval_ms);
gboolean decode_transition_key(const char *key, char **uuid, int *transition_id,
                               int *action_id, int *target_rc);
gboolean decode_transition_magic(const char *magic, char **uuid,
                                 int *transition_id, int *action_id,
                                 int *op_status, int *op_rc, int *target_rc);
int rsc_op_expected_rc(lrmd_event_data_t *event);
gboolean did_rsc_op_fail(lrmd_event_data_t *event, int target_rc);
bool crm_op_needs_metadata(const char *rsc_class, const char *op);
xmlNode *crm_create_op_xml(xmlNode *parent, const char *prefix,
                           const char *task, const char *interval_spec,
                           const char *timeout);
#define CRM_DEFAULT_OP_TIMEOUT_S "20s"

bool pcmk_is_probe(const char *task, guint interval);
bool pcmk_xe_is_probe(xmlNode *xml_op);
bool pcmk_xe_mask_probe_failure(xmlNode *xml_op);

int compare_version(const char *version1, const char *version2);

/* coverity[+kill] */
void crm_abort(const char *file, const char *function, int line,
               const char *condition, gboolean do_core, gboolean do_fork);

/*!
 * \brief Check whether any of specified flags are set in a flag group
 *
 * \param[in] flag_group        The flag group being examined
 * \param[in] flags_to_check    Which flags in flag_group should be checked
 *
 * \return true if \p flags_to_check is nonzero and any of its flags are set in
 *         \p flag_group, or false otherwise
 */
static inline bool
pcmk_any_flags_set(uint64_t flag_group, uint64_t flags_to_check)
{
    return (flag_group & flags_to_check) != 0;
}

/*!
 * \brief Check whether all of specified flags are set in a flag group
 *
 * \param[in] flag_group        The flag group being examined
 * \param[in] flags_to_check    Which flags in flag_group should be checked
 *
 * \return true if \p flags_to_check is zero or all of its flags are set in
 *         \p flag_group, or false otherwise
 */
static inline bool
pcmk_all_flags_set(uint64_t flag_group, uint64_t flags_to_check)
{
    return (flag_group & flags_to_check) == flags_to_check;
}

/*!
 * \brief Convenience alias for pcmk_all_flags_set(), to check single flag
 */
#define pcmk_is_set(g, f)   pcmk_all_flags_set((g), (f))

char *crm_meta_name(const char *field);
const char *crm_meta_value(GHashTable * hash, const char *field);

char *crm_md5sum(const char *buffer);

char *crm_generate_uuid(void);

// This belongs in ipc.h but is here for backward compatibility
bool crm_is_daemon_name(const char *name);

int crm_user_lookup(const char *name, uid_t * uid, gid_t * gid);
int pcmk_daemon_user(uid_t *uid, gid_t *gid);

#ifdef HAVE_GNUTLS_GNUTLS_H
void crm_gnutls_global_init(void);
#endif

char *pcmk_hostname(void);

bool pcmk_str_is_infinity(const char *s);
bool pcmk_str_is_minus_infinity(const char *s);

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/util_compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif
