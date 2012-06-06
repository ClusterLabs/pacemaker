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

#  include <clplumbing/lsb_exitcodes.h>

#  include <sys/types.h>
#  include <stdlib.h>
#  include <limits.h>
#  include <signal.h>

#  include "crm/lrmd.h"

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

extern unsigned int crm_log_level;
extern gboolean crm_config_error;
extern gboolean crm_config_warning;

#  ifdef HAVE_GETOPT_H
#    include <getopt.h>
#  else
#    define no_argument 0
#    define required_argument 1
#  endif

#  define pcmk_option_default	0x00000
#  define pcmk_option_hidden	0x00001
#  define pcmk_option_paragraph	0x00002
#  define pcmk_option_example	0x00004

struct crm_option {
    /* Fields from 'struct option' in getopt.h */
    /* name of long option */
    const char *name;
    /*
     * one of no_argument, required_argument, and optional_argument:
     * whether option takes an argument
     */
    int has_arg;
    /* if not NULL, set *flag to val when option found */
    int *flag;
    /* if flag not NULL, value to set *flag to; else return value */
    int val;

    /* Custom fields */
    const char *desc;
    long flags;
};

#  define crm_config_err(fmt...) { crm_config_error = TRUE; crm_err(fmt); }
#  define crm_config_warn(fmt...) { crm_config_warning = TRUE; crm_warn(fmt); }

void crm_log_deinit(void);

gboolean daemon_option_enabled(const char *daemon, const char *option);

gboolean crm_log_cli_init(const char *entity);

gboolean crm_log_init(const char *entity, int level, gboolean daemon,
                      gboolean to_stderr, int argc, char **argv, gboolean quiet);

void crm_log_args(int argc, char **argv);

int crm_should_log(int level);

void crm_bump_log_level(void);

void crm_enable_stderr(int enable);

/* returns the old value */
unsigned int set_crm_log_level(unsigned int level);

unsigned int get_crm_log_level(void);

char *crm_itoa(int an_int);

char *crm_strdup_fn(const char *a, const char *file, const char *fn, int line);

char *generate_hash_key(const char *crm_msg_reference, const char *sys);

char *generate_hash_value(const char *src_node, const char *src_subsys);

gboolean decodeNVpair(const char *srcstring, char separator, char **name, char **value);

int compare_version(const char *version1, const char *version2);

char *generateReference(const char *custom1, const char *custom2);

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

char *generate_transition_key(int action, int transition_id, int target_rc,
                                     const char *node);

gboolean decode_transition_key(const char *key, char **uuid, int *action, int *transition_id,
                                      int *target_rc);

char *crm_concat(const char *prefix, const char *suffix, char join);

gboolean decode_op_key(const char *key, char **rsc_id, char **op_type, int *interval);

void filter_action_parameters(xmlNode * param_set, const char *version);
void filter_reload_parameters(xmlNode * param_set, const char *restart_string);

static inline int
crm_strlen_zero(const char *s)
{
    return !s || *s == '\0';
}

#  define safe_str_eq(a, b) crm_str_eq(a, b, FALSE)

gboolean crm_str_eq(const char *a, const char *b, gboolean use_case);

gboolean safe_str_neq(const char *a, const char *b);
int crm_parse_int(const char *text, const char *default_text);
long long crm_int_helper(const char *text, char **end_text);

#  define crm_atoi(text, default_text) crm_parse_int(text, default_text)

void crm_abort(const char *file, const char *function, int line,
                      const char *condition, gboolean do_core, gboolean do_fork);

char *generate_series_filename(const char *directory, const char *series, int sequence,
                                      gboolean bzip);

int get_last_sequence(const char *directory, const char *series);

void write_last_sequence(const char *directory, const char *series, int sequence, int max);

int crm_pid_active(long pid);
int crm_read_pidfile(const char *filename);
int crm_lock_pidfile(const char *filename);
void crm_make_daemon(const char *name, gboolean daemonize, const char *pidfile);

typedef struct pe_cluster_option_s {
    const char *name;
    const char *alt_name;
    const char *type;
    const char *values;
    const char *default_value;

     gboolean(*is_valid) (const char *);

    const char *description_short;
    const char *description_long;

} pe_cluster_option;

const char *cluster_option(GHashTable * options, gboolean(*validate) (const char *),
                                  const char *name, const char *old_name, const char *def_value);

const char *get_cluster_pref(GHashTable * options, pe_cluster_option * option_list, int len,
                                    const char *name);

void config_metadata(const char *name, const char *version, const char *desc_short,
                            const char *desc_long, pe_cluster_option * option_list, int len);

void verify_all_options(GHashTable * options, pe_cluster_option * option_list, int len);
gboolean check_time(const char *value);
gboolean check_timer(const char *value);
gboolean check_boolean(const char *value);
gboolean check_number(const char *value);

int char2score(const char *score);
char *score2char(int score);

gboolean crm_is_writable(const char *dir, const char *file,
                                const char *user, const char *group, gboolean need_both);

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

xmlNode *cib_recv_remote_msg(void *session, gboolean encrypted);
void cib_send_remote_msg(void *session, xmlNode * msg, gboolean encrypted);
char *crm_meta_name(const char *field);
const char *crm_meta_value(GHashTable * hash, const char *field);

void crm_set_options(const char *short_options, const char *usage,
                            struct crm_option *long_options, const char *app_desc);
int crm_get_option(int argc, char **argv, int *index);
void crm_help(char cmd, int exit_code);

int rsc_op_expected_rc(lrmd_event_data_t *event);
gboolean did_rsc_op_fail(lrmd_event_data_t *event, int target_rc);

extern int node_score_red;
extern int node_score_green;
extern int node_score_yellow;
extern int node_score_infinity;

xmlNode *create_operation_update(xmlNode * parent, lrmd_event_data_t *event, const char *caller_version,
                                        int target_rc, const char *origin, int level);

#  if USE_GHASH_COMPAT

typedef struct fake_ghi {
    GHashTable *hash;
    int nth;                    /* current index over the iteration */
    int lpc;                    /* internal loop counter inside g_hash_table_find */
    gpointer key;
    gpointer value;
} GHashTableIter;

static inline void
g_hash_prepend_value(gpointer key, gpointer value, gpointer user_data)
{
    GList **values = (GList **) user_data;

    *values = g_list_prepend(*values, value);
}

static inline GList *
g_hash_table_get_values(GHashTable * hash_table)
{
    GList *values = NULL;

    g_hash_table_foreach(hash_table, g_hash_prepend_value, &values);
    return values;
}

static inline gboolean
g_hash_table_nth_data(gpointer key, gpointer value, gpointer user_data)
{
    GHashTableIter *iter = (GHashTableIter *) user_data;

    if (iter->lpc++ == iter->nth) {
        iter->key = key;
        iter->value = value;
        return TRUE;
    }
    return FALSE;
}

static inline void
g_hash_table_iter_init(GHashTableIter * iter, GHashTable * hash_table)
{
    iter->hash = hash_table;
    iter->nth = 0;
    iter->lpc = 0;
    iter->key = NULL;
    iter->value = NULL;
}

static inline gboolean
g_hash_table_iter_next(GHashTableIter * iter, gpointer * key, gpointer * value)
{
    gboolean found = FALSE;

    iter->lpc = 0;
    iter->key = NULL;
    iter->value = NULL;
    if (iter->nth < g_hash_table_size(iter->hash)) {
        found = ! !g_hash_table_find(iter->hash, g_hash_table_nth_data, iter);
        iter->nth++;
    }
    if (key)
        *key = iter->key;
    if (value)
        *value = iter->value;
    return found;
}

#  endif                        /* USE_GHASH_COMPAT */

#  if ENABLE_ACL
static inline gboolean
is_privileged(const char *user)
{
    if (user == NULL) {
        return FALSE;
    } else if (strcmp(user, CRM_DAEMON_USER) == 0) {
        return TRUE;
    } else if (strcmp(user, "root") == 0) {
        return TRUE;
    }
    return FALSE;
}

void determine_request_user(char **user, IPC_Channel * channel, xmlNode * request,
                                   const char *field);
#  endif

void *find_library_function(void **handle, const char *lib, const char *fn);

void *convert_const_pointer(const void *ptr);

char *crm_generate_uuid(void);

char *crm_md5sum(const char *buffer);

void crm_enable_blackbox(int nsig);
void crm_enable_blackbox_tracing(int nsig);
void crm_write_blackbox(int nsig);

#endif
