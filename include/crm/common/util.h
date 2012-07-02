/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRM_COMMON_UTIL__H
#  define CRM_COMMON_UTIL__H

#  include <sys/types.h>
#  include <stdlib.h>
#  include <limits.h>
#  include <signal.h>
#  include <sysexits.h>

#  include <crm/lrmd.h>

#  if SUPPORT_HEARTBEAT
#    include <heartbeat.h>
#  else
#    define	NORMALNODE	"normal"
#    define	ACTIVESTATUS	"active"/* fully functional, and all links are up */
#    define	DEADSTATUS	"dead"
                                /* Status of non-working link or machine */
#    define	PINGSTATUS	"ping"
                                /* Status of a working ping node */
#    define	JOINSTATUS	"join"
                                /* Status when an api client joins */
#    define	LEAVESTATUS	"leave"
                                /* Status when an api client leaves */
#    define	ONLINESTATUS	"online"/* Status of an online client */
#    define	OFFLINESTATUS	"offline"
                                        /* Status of an offline client */
#  endif

char *crm_itoa(int an_int);

int compare_version(const char *version1, const char *version2);

void g_hash_destroy_str(gpointer data);

gboolean crm_is_true(const char *s);

int crm_str_to_boolean(const char *s, int *ret);

long long crm_get_msec(const char *input);
unsigned long long crm_get_interval(const char *input);

char *generate_op_key(const char *rsc_id, const char *op_type, int interval);

gboolean parse_op_key(const char *key, char **rsc_id, char **op_type, int *interval);

char *generate_notify_key(const char *rsc_id, const char *notify_type, const char *op_type);

char *generate_transition_magic_v202(const char *transition_key, int op_status);

char *generate_transition_magic(const char *transition_key, int op_status, int op_rc);

gboolean decode_transition_magic(const char *magic, char **uuid,
                                        int *transition_id, int *action_id, int *op_status,
                                        int *op_rc, int *target_rc);

char *generate_transition_key(int action, int transition_id, int target_rc, const char *node);

gboolean decode_transition_key(const char *key, char **uuid, int *action, int *transition_id, int *target_rc);

gboolean decode_op_key(const char *key, char **rsc_id, char **op_type, int *interval);


#  define safe_str_eq(a, b) crm_str_eq(a, b, FALSE)

gboolean crm_str_eq(const char *a, const char *b, gboolean use_case);

gboolean safe_str_neq(const char *a, const char *b);
int crm_parse_int(const char *text, const char *default_text);

#  define crm_atoi(text, default_text) crm_parse_int(text, default_text)

void crm_abort(const char *file, const char *function, int line,
                      const char *condition, gboolean do_core, gboolean do_fork);

int char2score(const char *score);
char *score2char(int score);

#  define set_bit(word, bit) word = crm_set_bit(__PRETTY_FUNCTION__, NULL, word, bit)
#  define clear_bit(word, bit) word = crm_clear_bit(__PRETTY_FUNCTION__, NULL, word, bit)

#  define set_bit_inplace set_bit
#  define clear_bit_inplace clear_bit

static inline long long
crm_clear_bit(const char *function, const char *target, long long word, long long bit)
{
    long long rc = (word & ~bit);

    if(rc == word) {
        /* Unchanged */
    } else if (target) {
        crm_trace("Bit 0x%.8llx for %s cleared by %s", bit, target, function);
    } else {
        crm_trace("Bit 0x%.8llx cleared by %s", bit, function);
    }

    return rc;
}

static inline long long
crm_set_bit(const char *function, const char *target, long long word, long long bit)
{
    long long rc = (word|bit);

    if(rc == word) {
        /* Unchanged */
    } else if (target) {
        crm_trace("Bit 0x%.8llx for %s set by %s", bit, target, function);
    } else {
        crm_trace("Bit 0x%.8llx set by %s", bit, function);
    }

    return rc;
}

static inline gboolean
is_not_set(long long word, long long bit)
{
    return ((word & bit) == 0);
}

static inline gboolean
is_set(long long word, long long bit)
{
    return ((word & bit) == bit);
}

static inline gboolean
is_set_any(long long word, long long bit)
{
    return ((word & bit) != 0);
}

char *crm_meta_name(const char *field);
const char *crm_meta_value(GHashTable * hash, const char *field);

int rsc_op_expected_rc(lrmd_event_data_t *event);
gboolean did_rsc_op_fail(lrmd_event_data_t *event, int target_rc);

char *crm_md5sum(const char *buffer);

char *crm_generate_uuid(void);
int crm_user_lookup(const char *name, uid_t * uid, gid_t * gid);

#endif
