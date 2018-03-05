/*
 * Copyright (C) 2017 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK_ATTRD_COMMON__H
#  define PCMK_ATTRD_COMMON__H

#include <regex.h>
#include <glib.h>
#include <crm/crm.h>
#include <crm/cib/internal.h>

void attrd_init_mainloop(void);
void attrd_run_mainloop(void);
gboolean attrd_mainloop_running(void);
void attrd_quit_mainloop(void);

gboolean attrd_shutting_down(void);
void attrd_shutdown(int nsig);
void attrd_init_ipc(qb_ipcs_service_t **ipcs,
                    qb_ipcs_msg_process_fn dispatch_fn);

void attrd_cib_disconnect(void);

gboolean attrd_value_needs_expansion(const char *value);
int attrd_expand_value(const char *value, const char *old_value);

/* regular expression to clear failures of all resources */
#define ATTRD_RE_CLEAR_ALL \
    "^(" CRM_FAIL_COUNT_PREFIX "|" CRM_LAST_FAILURE_PREFIX ")-"

/* regular expression to clear failure of all operations for one resource
 * (format takes resource name)
 *
 * @COMPAT attributes set < 1.1.17:
 * also match older attributes that do not have the operation part
 */
#define ATTRD_RE_CLEAR_ONE ATTRD_RE_CLEAR_ALL "%s(#.+_[0-9]+)?$"

/* regular expression to clear failure of one operation for one resource
 * (format takes resource name, operation name, and interval)
 *
 * @COMPAT attributes set < 1.1.17:
 * also match older attributes that do not have the operation part
 */
#define ATTRD_RE_CLEAR_OP ATTRD_RE_CLEAR_ALL "%s(#%s_%d)?$"

int attrd_failure_regex(regex_t *regex, const char *rsc, const char *op,
                        int interval_ms);

extern cib_t *the_cib;

/* Alerts */

extern lrmd_t *the_lrmd;
extern crm_trigger_t *attrd_config_read;

void attrd_lrmd_disconnect(void);
gboolean attrd_read_options(gpointer user_data);
void attrd_cib_updated_cb(const char *event, xmlNode *msg);
int attrd_send_attribute_alert(const char *node, int nodeid,
                               const char *attr, const char *value);
#endif /* PCMK_ATTRD_COMMON__H */
