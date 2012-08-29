/* crm_internal.h */

/* 
 * Copyright (C) 2006 - 2008
 *     Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef CRM_INTERNAL__H
#  define CRM_INTERNAL__H

#  include <config.h>
#  include <portability.h>

#  include <glib.h>
#  include <stdbool.h>
#  include <libxml/tree.h>

#  include <crm/lrmd.h>
#  include <crm/common/logging.h>

/* Dynamic loading of libraries */
void *find_library_function(void **handle, const char *lib, const char *fn, int fatal);
void *convert_const_pointer(const void *ptr);

/* For ACLs */
char *uid2username(uid_t uid);
void determine_request_user(char *user, xmlNode * request, const char *field);

#  if ENABLE_ACL
#    include <string.h>
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
#  endif

/* CLI option processing*/
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

void crm_set_options(const char *short_options, const char *usage, struct crm_option *long_options, const char *app_desc);
int crm_get_option(int argc, char **argv, int *index);
int crm_get_option_long(int argc, char **argv, int *index, const char **longname);
void crm_help(char cmd, int exit_code);

/* Cluster Option Processing */
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

const char *get_cluster_pref(GHashTable * options, pe_cluster_option * option_list, int len, const char *name);

void config_metadata(const char *name, const char *version, const char *desc_short,
                     const char *desc_long, pe_cluster_option * option_list, int len);

void verify_all_options(GHashTable * options, pe_cluster_option * option_list, int len);
gboolean check_time(const char *value);
gboolean check_timer(const char *value);
gboolean check_boolean(const char *value);
gboolean check_number(const char *value);

/* Shared PE/crmd functionality */
void filter_action_parameters(xmlNode * param_set, const char *version);
void filter_reload_parameters(xmlNode * param_set, const char *restart_string);

/* Resource operation updates */
xmlNode *create_operation_update(xmlNode * parent, lrmd_event_data_t *event, const char *caller_version,
                                 int target_rc, const char *origin, int level);

/* char2score */
extern int node_score_red;
extern int node_score_green;
extern int node_score_yellow;
extern int node_score_infinity;


/* Assorted convenience functions */
static inline int
crm_strlen_zero(const char *s)
{
    return !s || *s == '\0';
}

char *add_list_element(char *list, const char *value);
char *generate_series_filename(const char *directory, const char *series, int sequence, gboolean bzip);
int get_last_sequence(const char *directory, const char *series);
void write_last_sequence(const char *directory, const char *series, int sequence, int max);

void crm_make_daemon(const char *name, gboolean daemonize, const char *pidfile);
gboolean crm_is_writable(const char *dir, const char *file, const char *user, const char *group, gboolean need_both);

char *generate_op_key(const char *rsc_id, const char *op_type, int interval);
char *generate_notify_key(const char *rsc_id, const char *notify_type, const char *op_type);
char *generate_transition_magic_v202(const char *transition_key, int op_status);
char *generate_transition_magic(const char *transition_key, int op_status, int op_rc);
char *generate_transition_key(int action, int transition_id, int target_rc, const char *node);

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

#  define set_bit(word, bit) word = crm_set_bit(__PRETTY_FUNCTION__, NULL, word, bit)
#  define clear_bit(word, bit) word = crm_clear_bit(__PRETTY_FUNCTION__, NULL, word, bit)

void g_hash_destroy_str(gpointer data);

long long crm_int_helper(const char *text, char **end_text);
char *crm_concat(const char *prefix, const char *suffix, char join);
char *generate_hash_key(const char *crm_msg_reference, const char *sys);
xmlNode *crm_recv_remote_msg(void *session, gboolean encrypted);
void crm_send_remote_msg(void *session, xmlNode * msg, gboolean encrypted);

#  define crm_config_err(fmt...) { crm_config_error = TRUE; crm_err(fmt); }
#  define crm_config_warn(fmt...) { crm_config_warning = TRUE; crm_warn(fmt); }

#  define attrd_channel		T_ATTRD
#  define F_ATTRD_KEY		"attr_key"
#  define F_ATTRD_ATTRIBUTE	"attr_name"
#  define F_ATTRD_TASK		"task"
#  define F_ATTRD_VALUE		"attr_value"
#  define F_ATTRD_SET		"attr_set"
#  define F_ATTRD_SECTION	"attr_section"
#  define F_ATTRD_DAMPEN	"attr_dampening"
#  define F_ATTRD_IGNORE_LOCALLY "attr_ignore_locally"
#  define F_ATTRD_HOST		"attr_host"
#  define F_ATTRD_USER		"attr_user"

#  if SUPPORT_COROSYNC
#    if CS_USES_LIBQB
#      include <qb/qbipc_common.h>
#      include <corosync/corotypes.h>
typedef struct qb_ipc_request_header cs_ipc_header_request_t;
typedef struct qb_ipc_response_header cs_ipc_header_response_t;
#    else
#      include <corosync/corodefs.h>
#      include <corosync/coroipcc.h>
#      include <corosync/coroipc_types.h>
static inline int
qb_to_cs_error(int a)
{
    return a;
}

typedef coroipc_request_header_t cs_ipc_header_request_t;
typedef coroipc_response_header_t cs_ipc_header_response_t;
#    endif
#  else
typedef struct {
    int size __attribute__ ((aligned(8)));
    int id __attribute__ ((aligned(8)));
} __attribute__ ((aligned(8))) cs_ipc_header_request_t;

typedef struct {
    int size __attribute__ ((aligned(8)));
    int id __attribute__ ((aligned(8)));
    int error __attribute__ ((aligned(8)));
} __attribute__ ((aligned(8))) cs_ipc_header_response_t;

#  endif

#endif                          /* CRM_INTERNAL__H */
