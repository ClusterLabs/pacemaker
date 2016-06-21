/*
 * Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
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

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/pengine/rules.h>
#include "notify.h"
#include "crmd_messages.h"

static char *notify_script = NULL;
static char *notify_target = NULL;
static GListPtr notify_list = NULL;
static int alerts_inflight = 0;
static gboolean draining_alerts = FALSE;
static guint max_alert_timeout = CRMD_NOTIFY_DEFAULT_TIMEOUT_MS;

typedef struct {
    char *name;
    char *value;
} envvar_t;

typedef struct {
    char *id;
    char *path;
    int timeout;
    char *tstamp_format;
    char *recipient;
    GListPtr envvars;
} notify_entry_t;

enum notify_keys_e{
    CRM_notify_recipient = 0,
    CRM_notify_node,
    CRM_notify_nodeid,
    CRM_notify_rsc,
    CRM_notify_task,
    CRM_notify_interval,
    CRM_notify_desc,
    CRM_notify_status,
    CRM_notify_target_rc,
    CRM_notify_rc,
    CRM_notify_kind,
    CRM_notify_version,
    CRM_notify_node_sequence,
    CRM_notify_timestamp
};

/*
 * to allow script compatibility we can have more than one
 * set of environment variables
 */

static const char *notify_keys[][3] =
{
    [CRM_notify_recipient]     = {"CRM_notify_recipient",     "CRM_alert_recipient",     NULL},
    [CRM_notify_node]          = {"CRM_notify_node",          "CRM_alert_node",          NULL},
    [CRM_notify_nodeid]        = {"CRM_notify_nodeid",        "CRM_alert_nodeid",        NULL},
    [CRM_notify_rsc]           = {"CRM_notify_rsc",           "CRM_alert_rsc",           NULL},
    [CRM_notify_task]          = {"CRM_notify_task",          "CRM_alert_task",          NULL},
    [CRM_notify_interval]      = {"CRM_notify_interval",      "CRM_alert_interval",      NULL},
    [CRM_notify_desc]          = {"CRM_notify_desc",          "CRM_alert_desc",          NULL},
    [CRM_notify_status]        = {"CRM_notify_status",        "CRM_alert_status",        NULL},
    [CRM_notify_target_rc]     = {"CRM_notify_target_rc",     "CRM_alert_target_rc",     NULL},
    [CRM_notify_rc]            = {"CRM_notify_rc",            "CRM_alert_rc",            NULL},
    [CRM_notify_kind]          = {"CRM_notify_kind",          "CRM_alert_kind",          NULL},
    [CRM_notify_version]       = {"CRM_notify_version",       "CRM_alert_version",       NULL},
    [CRM_notify_node_sequence] = {"CRM_notify_node_sequence", "CRM_alert_node_sequence", NULL},
    [CRM_notify_timestamp]     = {"CRM_notify_timestamp",     "CRM_alert_timestamp",     NULL}
};

/*
 * higher accuracy time stuff to be generalized and moved to
 * e.g. lib/common/utils.c|iso8601.c
 */

#include <time.h>
#include <sys/time.h>
#include <ctype.h>
#include <crm/common/iso8601.h>

typedef struct crm_time_us crm_time_hr_t;
crm_time_hr_t *crm_time_hr_convert(crm_time_hr_t *target, crm_time_t *dt);
void crm_time_set_hr_dt(crm_time_t *target, crm_time_hr_t *hr_dt);
crm_time_hr_t *crm_time_timeval_hr_convert(crm_time_hr_t *target,
                                           struct timeval *tv);
crm_time_hr_t *crm_time_hr_new(const char *date_time);
void crm_time_hr_free(crm_time_hr_t * hr_dt);
char *crm_time_format_hr(const char *format, crm_time_hr_t * hr_dt);

crm_time_t *parse_date(const char *date_str); /* in iso8601.c global but
                                                 not in header */

struct crm_time_us {
    int years;
    int months;                 /* Only for durations */
    int days;
    int seconds;
    int offset;                 /* Seconds */
    bool duration;
    int useconds;
};

struct crm_time_s {
    int years;
    int months;                 /* Only for durations */
    int days;
    int seconds;
    int offset;                 /* Seconds */
    bool duration;
};



static void
ha_get_tm_time( struct tm *target, crm_time_t *source)
{
    *target = (struct tm) {
        .tm_year = source->years - 1900,
        .tm_yday = source->days - 1,
        .tm_sec = source->seconds % 60,
        .tm_min = ( source->seconds / 60 ) % 60,
        .tm_hour = source->seconds / 60 / 60,

#if defined(HAVE_STRUCT_TM_TM_GMTOFF)
        .tm_gmtoff = source->offset
#endif
    };
}

crm_time_hr_t *
crm_time_hr_convert(crm_time_hr_t *target, crm_time_t *dt)
{
    crm_time_hr_t *hr_dt = NULL;

    if (dt) {
        hr_dt = target?target:calloc(1, sizeof(crm_time_hr_t));
        if (hr_dt) {
            *hr_dt = (crm_time_hr_t) {
                .years = dt->years,
                .months = dt->months,
                .days = dt->days,
                .seconds = dt->seconds,
                .offset = dt->offset,
                .duration = dt->duration
            };
        }
    }

    return hr_dt;
}

void
crm_time_set_hr_dt(crm_time_t *target, crm_time_hr_t *hr_dt)
{
    CRM_ASSERT((hr_dt) && (target));
    *target = (crm_time_t) {
        .years = hr_dt->years,
        .months = hr_dt->months,
        .days = hr_dt->days,
        .seconds = hr_dt->seconds,
        .offset = hr_dt->offset,
        .duration = hr_dt->duration
    };
}

crm_time_hr_t *
crm_time_timeval_hr_convert(crm_time_hr_t *target, struct timeval *tv)
{
    crm_time_t dt;
    crm_time_hr_t *ret;

    crm_time_set_timet(&dt, &tv->tv_sec);
    ret = crm_time_hr_convert(target, &dt);
    if (ret) {
        ret->useconds = tv->tv_usec;
    }
    return ret;
}

crm_time_hr_t *
crm_time_hr_new(const char *date_time)
{
    crm_time_hr_t *hr_dt = NULL;
    struct timeval tv_now;

    if (!date_time) {
        if (gettimeofday(&tv_now, NULL) == 0) {
            hr_dt = crm_time_timeval_hr_convert(NULL, &tv_now);
        }
    } else {
        crm_time_t *dt;

        dt = parse_date(date_time);
        hr_dt = crm_time_hr_convert(NULL, dt);
        crm_time_free(dt);
    }
    return hr_dt;
}

void
crm_time_hr_free(crm_time_hr_t * hr_dt)
{
    free(hr_dt);
}

char *
crm_time_format_hr(const char *format, crm_time_hr_t * hr_dt)
{
    const char *mark_s;
    int max = 128, scanned_pos = 0, printed_pos = 0, fmt_pos = 0,
        date_len = 0, nano_digits = 0, fmt_len;
    char nano_s[10], date_s[max+1], nanofmt_s[5] = "%", *tmp_fmt_s;
    struct tm tm;
    crm_time_t dt;

    if (!format) {
        return NULL;
    }
    crm_time_set_hr_dt(&dt, hr_dt);
    ha_get_tm_time(&tm, &dt);
    sprintf(nano_s, "%06d000", hr_dt->useconds);

    while ((format[scanned_pos]) != '\0') {
        fmt_len = 0;
        mark_s = strchr(&format[scanned_pos], '%');
        if (mark_s) {
            fmt_pos = mark_s - format;
            fmt_len = 1;
            while ((format[fmt_pos+fmt_len] != '\0') &&
                (format[fmt_pos+fmt_len] >= '0') &&
                (format[fmt_pos+fmt_len] <= '9')) {
                fmt_len++;
            }
            scanned_pos = fmt_pos + fmt_len + 1;
            if (format[fmt_pos+fmt_len] == 'N') {
                nano_digits = atoi(&format[fmt_pos+1]);
                nano_digits = (nano_digits > 6)?6:nano_digits;
                nano_digits = (nano_digits < 0)?0:nano_digits;
                sprintf(&nanofmt_s[1], ".%ds", nano_digits);
            } else {
                if (format[scanned_pos] != '\0') {
                    continue;
                }
                fmt_pos = scanned_pos; /* print till end */
            }
        } else {
            scanned_pos = strlen(format);
            fmt_pos = scanned_pos; /* print till end */
        }
        tmp_fmt_s = strndup(&format[printed_pos], fmt_pos - printed_pos);
#ifdef GCC_FORMAT_NONLITERAL_CHECKING_ENABLED
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
        date_len += strftime(&date_s[date_len], max-date_len, tmp_fmt_s, &tm);
#ifdef GCC_FORMAT_NONLITERAL_CHECKING_ENABLED
#pragma GCC diagnostic pop
#endif
        printed_pos = scanned_pos;
        free(tmp_fmt_s);
        if (nano_digits) {
#ifdef GCC_FORMAT_NONLITERAL_CHECKING_ENABLED
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
            date_len += snprintf(&date_s[date_len], max-date_len,
                                 nanofmt_s, nano_s);
#ifdef GCC_FORMAT_NONLITERAL_CHECKING_ENABLED
#pragma GCC diagnostic pop
#endif
            nano_digits = 0;
        }
    }

    return (date_len == 0)?NULL:strdup(date_s);
}

/*
 * end of possibly generic time-handling stuff
 */


/*
 * syncronize local data with cib
 */

static void
free_envvar_entry(envvar_t *entry)
{
    free(entry->name);
    free(entry->value);
    free(entry);
}

static void
free_notify_list_entry(notify_entry_t *entry)
{
    free(entry->id);
    free(entry->path);
    free(entry->tstamp_format);
    free(entry->recipient);
    if (entry->envvars) {
        g_list_free_full(entry->envvars,
                         (GDestroyNotify) free_envvar_entry);
    }
    free(entry);
}

static void
free_notify_list()
{
    if (notify_list) {
        g_list_free_full(notify_list, (GDestroyNotify) free_notify_list_entry);
        notify_list = NULL;
    }
}

static gpointer
copy_envvar_entry(envvar_t * src,
                  gpointer data)
{
    envvar_t *dst = calloc(1, sizeof(envvar_t));

    CRM_ASSERT(dst);
    dst->name = strdup(src->name);
    dst->value = src->value?strdup(src->value):NULL;
    return (gpointer) dst;
}

static GListPtr
add_dup_envvar(GListPtr envvar_list,
               envvar_t *entry)
{
    return g_list_prepend(envvar_list, copy_envvar_entry(entry, NULL));
}

static GListPtr
drop_envvars(GListPtr envvar_list, int count)
{
    int i;

    for (i = 0;
         (envvar_list) && ((count < 0) || (i < count));
         i++) {
        free_envvar_entry((envvar_t *) g_list_first(envvar_list)->data);
        envvar_list = g_list_delete_link(envvar_list,
                                         g_list_first(envvar_list));
    }
    return envvar_list;
}

static GListPtr
copy_envvar_list_remove_dupes(GListPtr src)
{
    GListPtr dst = NULL, ls, ld;

    /* we are adding to the front so variable dupes coming via
     * recipient-section have got precedence over those in the
     * global section - we don't expect that many variables here
     * that it pays off to go for a hash-table to make dupe elimination
     * more efficient - maybe later when we might decide to do more
     * with the variables than cycling through them
     */

    for (ls = g_list_first(src); ls; ls = g_list_next(ls)) {
        for (ld = g_list_first(dst); ld; ld = g_list_next(ld)) {
            if (!strcmp(((envvar_t *)(ls->data))->name,
                        ((envvar_t *)(ld->data))->name)) {
                break;
            }
        }
        if (!ld) {
            dst = g_list_prepend(dst,
                    copy_envvar_entry((envvar_t *)(ls->data), NULL));
        }
    }

    return dst;
}

static void
add_dup_notify_list_entry(notify_entry_t *entry)
{
    notify_entry_t *new_entry =
        (notify_entry_t *) calloc(1, sizeof(notify_entry_t));

    CRM_ASSERT(new_entry);
    *new_entry = (notify_entry_t) {
        .id = strdup(entry->id),
        .path = strdup(entry->path),
        .timeout = entry->timeout,
        .tstamp_format = entry->tstamp_format?strdup(entry->tstamp_format):NULL,
        .recipient = entry->recipient?strdup(entry->recipient):NULL,
        .envvars = entry->envvars?
            copy_envvar_list_remove_dupes(entry->envvars)
            :NULL
    };
    notify_list = g_list_prepend(notify_list, new_entry);
}

static GListPtr
get_envvars_from_cib(xmlNode *basenode, GListPtr list, int *count)
{
    xmlNode *envvar;
    xmlNode *pair;

    if ((!basenode) ||
        (!(envvar = first_named_child(basenode, XML_TAG_ATTR_SETS)))) {
        return list;
    }

    for (pair = first_named_child(envvar, XML_CIB_TAG_NVPAIR);
         pair; pair = __xml_next(pair)) {

        envvar_t envvar_entry = (envvar_t) {
            .name = (char *) crm_element_value(pair, XML_NVPAIR_ATTR_NAME),
            .value = (char *) crm_element_value(pair, XML_NVPAIR_ATTR_VALUE)
        };
        crm_trace("Found environment variable %s = '%s'", envvar_entry.name,
                  envvar_entry.value?envvar_entry.value:"");
        (*count)++;
        list = add_dup_envvar(list, &envvar_entry);
    }

    return list;
}

static GHashTable *
get_meta_attrs_from_cib(xmlNode *basenode, notify_entry_t *entry,
                        guint *max_timeout)
{
    GHashTable *config_hash =
        g_hash_table_new_full(crm_str_hash, g_str_equal,
                              g_hash_destroy_str, g_hash_destroy_str);
    crm_time_t *now = crm_time_new(NULL);
    const char *value = NULL;

    unpack_instance_attributes(basenode, basenode, XML_TAG_META_SETS, NULL,
                               config_hash, NULL, FALSE, now);

    value = g_hash_table_lookup(config_hash, XML_ALERT_ATTR_TIMEOUT);
    if (value) {
        entry->timeout = crm_get_msec(value);
        if (entry->timeout <= 0) {
            if (entry->timeout == 0) {
                crm_trace("Setting timeout to default %dmsec",
                          CRMD_NOTIFY_DEFAULT_TIMEOUT_MS);
            } else {
                crm_warn("Invalid timeout value setting to default %dmsec",
                         CRMD_NOTIFY_DEFAULT_TIMEOUT_MS);
            }
            entry->timeout = CRMD_NOTIFY_DEFAULT_TIMEOUT_MS;
        } else {
            crm_trace("Found timeout %dmsec", entry->timeout);
        }
        if (entry->timeout > *max_timeout) {
            *max_timeout = entry->timeout;
        }
    }
    value = g_hash_table_lookup(config_hash, XML_ALERT_ATTR_TSTAMP_FORMAT);
    if (value) {
        /* hard to do any checks here as merely anything can
         * can be a valid time-format-string
         */
        entry->tstamp_format = (char *) value;
        crm_trace("Found timestamp format string '%s'", value);
    }

    crm_time_free(now);
    return config_hash; /* keep hash as long as strings are needed */
}

void
parse_notifications(xmlNode *notifications)
{
    xmlNode *notify;
    notify_entry_t entry;
    guint max_timeout = 0;

    free_notify_list();
    max_alert_timeout = CRMD_NOTIFY_DEFAULT_TIMEOUT_MS;

    if (notifications) {
        crm_info("We have an alerts section in the cib");

        if (notify_script) {
            crm_warn("Cib contains configuration for Legacy Notifications "
                     "which is overruled by alerts section");
        }
    } else {
        crm_info("No optional alerts section in cib");

        if (notify_script) {
            entry = (notify_entry_t) {
                .id = (char *) "legacy_notification",
                .path = notify_script,
                .timeout = CRMD_NOTIFY_DEFAULT_TIMEOUT_MS,
                .recipient = notify_target
            };
            add_dup_notify_list_entry(&entry);
            crm_info("Legacy Notifications enabled");
        }

        return;
    }

    for (notify = first_named_child(notifications, XML_CIB_TAG_ALERT);
         notify; notify = __xml_next(notify)) {
        xmlNode *recipient;
        int recipients = 0, envvars = 0;
        GHashTable *config_hash = NULL;

        entry = (notify_entry_t) {
            .id = (char *) crm_element_value(notify, XML_ATTR_ID),
            .path = (char *) crm_element_value(notify, XML_ALERT_ATTR_PATH),
            .timeout = CRMD_NOTIFY_DEFAULT_TIMEOUT_MS,
            .tstamp_format = (char *) CRMD_NOTIFY_DEFAULT_TSTAMP_FORMAT
        };

        entry.envvars =
            get_envvars_from_cib(notify,
                                 entry.envvars,
                                 &envvars);

        config_hash =
            get_meta_attrs_from_cib(notify, &entry, &max_timeout);

        crm_debug("Found alert: id=%s, path=%s, timeout=%d, "
                   "tstamp_format=%s, %d additional environment variables",
                   entry.id, entry.path, entry.timeout,
                   entry.tstamp_format, envvars);

        for (recipient = first_named_child(notify,
                                           XML_CIB_TAG_ALERT_RECIPIENT);
             recipient; recipient = __xml_next(recipient)) {
            int envvars_added = 0;

            entry.recipient = (char *) crm_element_value(recipient,
                                                XML_ALERT_ATTR_REC_VALUE);
            recipients++;

            entry.envvars =
                get_envvars_from_cib(recipient,
                                     entry.envvars,
                                     &envvars_added);

            {
                notify_entry_t recipient_entry = entry;
                GHashTable *config_hash =
                    get_meta_attrs_from_cib(recipient,
                                            &recipient_entry,
                                            &max_timeout);

                add_dup_notify_list_entry(&recipient_entry);

                crm_debug("Alert has recipient: id=%s, value=%s, "
                          "%d additional environment variables",
                          crm_element_value(recipient, XML_ATTR_ID),
                          recipient_entry.recipient, envvars_added);

                g_hash_table_destroy(config_hash);
            }

            entry.envvars =
                drop_envvars(entry.envvars, envvars_added);
        }

        if (recipients == 0) {
            add_dup_notify_list_entry(&entry);
        }

        drop_envvars(entry.envvars, -1);
        g_hash_table_destroy(config_hash);
    }

    if (max_timeout > 0) {
        max_alert_timeout = max_timeout;
    }
}

/*
 * end of synchronization of local data with cib
 */

void
crmd_enable_notifications(const char *script, const char *target)
{
    free(notify_script);
    notify_script = ((script) &&
                     (strcmp(script,"/dev/null")))?strdup(script):NULL;

    free(notify_target);
    notify_target = (target != NULL)?strdup(target):NULL;
}

static void
set_alert_key(enum notify_keys_e name, const char *value)
{
    const char **key;

    for (key = notify_keys[name]; *key; key++) {
        crm_trace("Setting alert key %s = '%s'", *key, value);
        if (value) {
            setenv(*key, value, 1);
        } else {
            unsetenv(*key);
        }
    }
}

static void
set_alert_key_int(enum notify_keys_e name, int value)
{
    char *s = crm_itoa(value);

    set_alert_key(name, s);
    free(s);
}

static void
unset_alert_keys()
{
    const char **key;
    enum notify_keys_e name;

    for(name = 0; name < DIMOF(notify_keys); name++) {
        for(key = notify_keys[name]; *key; key++) {
            crm_trace("Unsetting alert key %s", *key);
            unsetenv(*key);
        }
    }
}

static void
set_envvar_list(GListPtr envvars)
{
    GListPtr l;

    for (l = g_list_first(envvars); l; l = g_list_next(l)) {
        envvar_t *entry = (envvar_t *)(l->data);

        crm_trace("Setting environment variable %s = '%s'", entry->name,
                  entry->value?entry->value:"");
        if (entry->value) {
            setenv(entry->name, entry->value, 1);
        } else {
            unsetenv(entry->name);
        }
    }
}

static void
unset_envvar_list(GListPtr envvars)
{
    GListPtr l;

    for (l = g_list_first(envvars); l; l = g_list_next(l)) {
        envvar_t *entry = (envvar_t *)(l->data);

        crm_trace("Unsetting environment variable %s", entry->name);
        unsetenv(entry->name);
    }
}

static void
crmd_notify_complete(svc_action_t *op)
{
    alerts_inflight--;
    if(op->rc == 0) {
        crm_info("Alert %d (%s) complete", op->sequence, op->agent);
    } else {
        crm_warn("Alert %d (%s) failed: %d", op->sequence, op->agent,
                 op->rc);
    }
}

static void
send_notifications(const char *kind)
{
    svc_action_t *notify = NULL;
    static int operations = 0;
    GListPtr l;
    crm_time_hr_t *now = crm_time_hr_new(NULL);

    set_alert_key(CRM_notify_kind, kind);
    set_alert_key(CRM_notify_version, VERSION);

    for (l = g_list_first(notify_list); l; l = g_list_next(l)) {
        notify_entry_t *entry = (notify_entry_t *)(l->data);
        char *timestamp = crm_time_format_hr(entry->tstamp_format, now);

        operations++;

        if (!draining_alerts) {
            crm_debug("Sending '%s' alert to '%s' via '%s'", kind,
                    entry->recipient, entry->path);
            set_alert_key(CRM_notify_recipient, entry->recipient);
            set_alert_key_int(CRM_notify_node_sequence, operations);
            set_alert_key(CRM_notify_timestamp, timestamp);

            notify = services_action_create_generic(entry->path, NULL);

            notify->timeout = entry->timeout;
            notify->standard = strdup("event");
            notify->id = strdup(entry->id);
            notify->agent = strdup(entry->path);
            notify->sequence = operations;

            set_envvar_list(entry->envvars);

            alerts_inflight++;
            if(services_action_async(notify, &crmd_notify_complete) == FALSE) {
                services_action_free(notify);
                alerts_inflight--;
            }

            unset_envvar_list(entry->envvars);
        } else {
            crm_warn("Ignoring '%s' alert to '%s' via '%s' received "
                     "while shutting down",
                     kind, entry->recipient, entry->path);
        }

        free(timestamp);
    }

    unset_alert_keys();
    if (now) {
        free(now);
    }
}

void
crmd_notify_node_event(crm_node_t *node)
{
    if(!notify_list) {
        return;
    }

    set_alert_key(CRM_notify_node, node->uname);
    set_alert_key_int(CRM_notify_nodeid, node->id);
    set_alert_key(CRM_notify_desc, node->state);

    send_notifications("node");
}

void
crmd_notify_fencing_op(stonith_event_t * e)
{
    char *desc = NULL;

    if (!notify_list) {
        return;
    }

    desc = crm_strdup_printf(
        "Operation %s of %s by %s for %s@%s: %s (ref=%s)",
        e->action, e->target, e->executioner ? e->executioner : "<no-one>",
        e->client_origin, e->origin, pcmk_strerror(e->result), e->id);

    set_alert_key(CRM_notify_node, e->target);
    set_alert_key(CRM_notify_task, e->operation);
    set_alert_key(CRM_notify_desc, desc);
    set_alert_key_int(CRM_notify_rc, e->result);

    send_notifications("fencing");
    free(desc);
}

void
crmd_notify_resource_op(const char *node, lrmd_event_data_t * op)
{
    int target_rc = 0;

    if(!notify_list) {
        return;
    }

    target_rc = rsc_op_expected_rc(op);
    if(op->interval == 0 && target_rc == op->rc &&
       safe_str_eq(op->op_type, RSC_STATUS)) {
        /* Leave it up to the script if they want to notify for
         * 'failed' probes, only swallow ones for which the result was
         * unexpected.
         *
         * Even if we find a resource running, it was probably because
         * someone erased the status section.
         */
        return;
    }

    set_alert_key(CRM_notify_node, node);

    set_alert_key(CRM_notify_rsc, op->rsc_id);
    set_alert_key(CRM_notify_task, op->op_type);
    set_alert_key_int(CRM_notify_interval, op->interval);

    set_alert_key_int(CRM_notify_target_rc, target_rc);
    set_alert_key_int(CRM_notify_status, op->op_status);
    set_alert_key_int(CRM_notify_rc, op->rc);

    if(op->op_status == PCMK_LRM_OP_DONE) {
        set_alert_key(CRM_notify_desc, services_ocf_exitcode_str(op->rc));
    } else {
        set_alert_key(CRM_notify_desc, services_lrm_status_str(op->op_status));
    }

    send_notifications("resource");
}

static gboolean
alert_drain_timeout_callback(gpointer user_data)
{
    gboolean *timeout_popped = (gboolean *) user_data;

    *timeout_popped = TRUE;
    return FALSE;
}

void
crmd_drain_alerts(GMainContext *ctx)
{
    guint timer;
    gboolean timeout_popped = FALSE;

    draining_alerts = TRUE;

    timer = g_timeout_add(max_alert_timeout + 5000,
                          alert_drain_timeout_callback,
                          (gpointer) &timeout_popped);

    while(alerts_inflight && !timeout_popped) {
        crm_trace("Draining mainloop while still %d alerts are in flight (timeout=%dms)",
                  alerts_inflight, max_alert_timeout + 5000);
        g_main_context_iteration(ctx, TRUE);
    }

    if (!timeout_popped && (timer > 0)) {
        g_source_remove(timer);
    }
}
