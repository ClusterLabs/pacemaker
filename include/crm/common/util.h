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

#  include <lrm/lrm_api.h>

#  include <sys/types.h>
#  include <stdlib.h>
#  include <limits.h>
#  include <signal.h>

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

#  define DEBUG_INC SIGUSR1
#  define DEBUG_DEC SIGUSR2

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

extern void crm_log_deinit(void);

extern gboolean crm_log_init(const char *entity, int level, gboolean coredir, gboolean to_stderr,
                             int argc, char **argv);

extern gboolean crm_log_init_quiet(const char *entity, int level, gboolean coredir,
                                   gboolean to_stderr, int argc, char **argv);

extern gboolean daemon_option_enabled(const char *daemon, const char *option);

extern gboolean crm_log_init_worker(const char *entity, int level, gboolean coredir,
                                    gboolean to_stderr, int argc, char **argv, gboolean quiet);

extern void crm_log_args(int argc, char **argv);

extern int crm_should_log(int level);

extern void crm_bump_log_level(void);

extern void crm_enable_stderr(int enable);

/* returns the old value */
extern unsigned int set_crm_log_level(unsigned int level);

extern unsigned int get_crm_log_level(void);

extern char *crm_itoa(int an_int);

extern char *crm_strdup_fn(const char *a, const char *file, const char *fn, int line);

extern char *generate_hash_key(const char *crm_msg_reference, const char *sys);

extern char *generate_hash_value(const char *src_node, const char *src_subsys);

extern gboolean decodeNVpair(const char *srcstring, char separator, char **name, char **value);

extern int compare_version(const char *version1, const char *version2);

extern char *generateReference(const char *custom1, const char *custom2);

extern void alter_debug(int nsig);

extern void g_hash_destroy_str(gpointer data);

extern gboolean crm_is_true(const char *s);

extern int crm_str_to_boolean(const char *s, int *ret);

extern long long crm_get_msec(const char *input);
extern unsigned long long crm_get_interval(const char *input);

extern const char *op_status2text(op_status_t status);

extern char *generate_op_key(const char *rsc_id, const char *op_type, int interval);

extern gboolean parse_op_key(const char *key, char **rsc_id, char **op_type, int *interval);

extern char *generate_notify_key(const char *rsc_id, const char *notify_type, const char *op_type);

extern char *generate_transition_magic_v202(const char *transition_key, int op_status);

extern char *generate_transition_magic(const char *transition_key, int op_status, int op_rc);

extern gboolean decode_transition_magic(const char *magic, char **uuid,
                                        int *transition_id, int *action_id, int *op_status,
                                        int *op_rc, int *target_rc);

extern char *generate_transition_key(int action, int transition_id, int target_rc,
                                     const char *node);

extern gboolean decode_transition_key(const char *key, char **uuid, int *action, int *transition_id,
                                      int *target_rc);

extern char *crm_concat(const char *prefix, const char *suffix, char join);

extern gboolean decode_op_key(const char *key, char **rsc_id, char **op_type, int *interval);

extern void filter_action_parameters(xmlNode * param_set, const char *version);
extern void filter_reload_parameters(xmlNode * param_set, const char *restart_string);

#  define safe_str_eq(a, b) crm_str_eq(a, b, FALSE)

extern gboolean crm_str_eq(const char *a, const char *b, gboolean use_case);

extern gboolean safe_str_neq(const char *a, const char *b);
extern int crm_parse_int(const char *text, const char *default_text);
extern long long crm_int_helper(const char *text, char **end_text);

#  define crm_atoi(text, default_text) crm_parse_int(text, default_text)

extern void crm_abort(const char *file, const char *function, int line,
                      const char *condition, gboolean do_core, gboolean do_fork);

extern char *generate_series_filename(const char *directory, const char *series, int sequence,
                                      gboolean bzip);

extern int get_last_sequence(const char *directory, const char *series);

extern void write_last_sequence(const char *directory, const char *series, int sequence, int max);

extern int crm_pid_active(long pid);
extern int crm_read_pidfile(const char *filename);
extern int crm_lock_pidfile(const char *filename);
extern void crm_make_daemon(const char *name, gboolean daemonize, const char *pidfile);

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

extern const char *cluster_option(GHashTable * options, gboolean(*validate) (const char *),
                                  const char *name, const char *old_name, const char *def_value);

extern const char *get_cluster_pref(GHashTable * options, pe_cluster_option * option_list, int len,
                                    const char *name);

extern void config_metadata(const char *name, const char *version, const char *desc_short,
                            const char *desc_long, pe_cluster_option * option_list, int len);

extern void verify_all_options(GHashTable * options, pe_cluster_option * option_list, int len);
extern gboolean check_time(const char *value);
extern gboolean check_timer(const char *value);
extern gboolean check_boolean(const char *value);
extern gboolean check_number(const char *value);

extern int char2score(const char *score);
extern char *score2char(int score);

extern gboolean crm_is_writable(const char *dir, const char *file,
                                const char *user, const char *group, gboolean need_both);

extern long long crm_set_bit(const char *function, long long word, long long bit);
extern long long crm_clear_bit(const char *function, long long word, long long bit);

#  define set_bit(word, bit) word = crm_set_bit(__PRETTY_FUNCTION__, word, bit)
#  define clear_bit(word, bit) word = crm_clear_bit(__PRETTY_FUNCTION__, word, bit)

#  define set_bit_inplace(word, bit) word |= bit
#  define clear_bit_inplace(word, bit) word &= ~bit

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

extern xmlNode *cib_recv_remote_msg(void *session, gboolean encrypted);
extern void cib_send_remote_msg(void *session, xmlNode * msg, gboolean encrypted);
extern char *crm_meta_name(const char *field);
extern const char *crm_meta_value(GHashTable * hash, const char *field);

extern void crm_set_options(const char *short_options, const char *usage,
                            struct crm_option *long_options, const char *app_desc);
extern int crm_get_option(int argc, char **argv, int *index);
extern void crm_help(char cmd, int exit_code);

extern int rsc_op_expected_rc(lrm_op_t * op);
extern gboolean did_rsc_op_fail(lrm_op_t * op, int target_rc);

extern gboolean attrd_update_delegate(IPC_Channel * cluster, char command, const char *host,
                                      const char *name, const char *value, const char *section,
                                      const char *set, const char *dampen, const char *user_name);

static inline gboolean
attrd_update(IPC_Channel * cluster, char command, const char *host, const char *name,
             const char *value, const char *section, const char *set, const char *dampen)
{
    return attrd_update_delegate(cluster, command, host, name, value, section, set, dampen, NULL);
}

extern gboolean attrd_lazy_update(char command, const char *host, const char *name,
                                  const char *value, const char *section, const char *set,
                                  const char *dampen);
extern gboolean attrd_update_no_mainloop(int *connection, char command, const char *host,
                                         const char *name, const char *value, const char *section,
                                         const char *set, const char *dampen);

extern int node_score_red;
extern int node_score_green;
extern int node_score_yellow;
extern int node_score_infinity;

#  include <lrm/lrm_api.h>
extern xmlNode *create_operation_update(xmlNode * parent, lrm_op_t * op, const char *caller_version,
                                        int target_rc, const char *origin, int level);
extern void free_lrm_op(lrm_op_t * op);

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

extern void determine_request_user(char **user, IPC_Channel * channel, xmlNode * request,
                                   const char *field);
#  endif

extern void *find_library_function(void **handle, const char *lib, const char *fn);

extern void *convert_const_pointer(const void *ptr);

#endif
