/*
 * Copyright (C) 2010 Andrew Beekhof <andrew@beekhof.net>
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
#include <pacemaker.h>

#include <sys/utsname.h>
#include <sys/stat.h>           /* for calls to stat() */
#include <libgen.h>             /* For basename() and dirname() */

#include <sys/types.h>
#include <pwd.h>                /* For getpwname() */

#include <corosync/hdb.h>
#include <corosync/cfg.h>
#include <corosync/cpg.h>
#include <corosync/cmap.h>

#include <crm/cluster/internal.h>
#include <crm/common/mainloop.h>

enum cluster_type_e stack = pcmk_cluster_unknown;
static corosync_cfg_handle_t cfg_handle;

/* =::=::=::= CFG - Shutdown stuff =::=::=::= */

static void
cfg_shutdown_callback(corosync_cfg_handle_t h, corosync_cfg_shutdown_flags_t flags)
{
    crm_info("Corosync wants to shut down: %s",
             (flags == COROSYNC_CFG_SHUTDOWN_FLAG_IMMEDIATE) ? "immediate" :
             (flags == COROSYNC_CFG_SHUTDOWN_FLAG_REGARDLESS) ? "forced" : "optional");

    /* Never allow corosync to shut down while we're running */
    corosync_cfg_replyto_shutdown(h, COROSYNC_CFG_SHUTDOWN_FLAG_NO);
}

static corosync_cfg_callbacks_t cfg_callbacks = {
    .corosync_cfg_shutdown_callback = cfg_shutdown_callback,
};

static int
pcmk_cfg_dispatch(gpointer user_data)
{
    corosync_cfg_handle_t *handle = (corosync_cfg_handle_t *) user_data;
    cs_error_t rc = corosync_cfg_dispatch(*handle, CS_DISPATCH_ALL);

    if (rc != CS_OK) {
        return -1;
    }
    return 0;
}

static void
cfg_connection_destroy(gpointer user_data)
{
    crm_err("Connection destroyed");
    cfg_handle = 0;

    pcmk_shutdown(SIGTERM);
}

gboolean
cluster_disconnect_cfg(void)
{
    if (cfg_handle) {
        corosync_cfg_finalize(cfg_handle);
        cfg_handle = 0;
    }

    pcmk_shutdown(SIGTERM);
    return TRUE;
}

#define cs_repeat(counter, max, code) do {		\
	code;						\
	if(rc == CS_ERR_TRY_AGAIN || rc == CS_ERR_QUEUE_FULL) {  \
	    counter++;					\
	    crm_debug("Retrying operation after %ds", counter);	\
	    sleep(counter);				\
	} else {                                        \
            break;                                      \
	}						\
    } while(counter < max)

gboolean
cluster_connect_cfg(uint32_t * nodeid)
{
    cs_error_t rc;
    int fd = 0, retries = 0;

    static struct mainloop_fd_callbacks cfg_fd_callbacks = {
        .dispatch = pcmk_cfg_dispatch,
        .destroy = cfg_connection_destroy,
    };

    cs_repeat(retries, 30, rc = corosync_cfg_initialize(&cfg_handle, &cfg_callbacks));

    if (rc != CS_OK) {
        crm_err("corosync cfg init error %d", rc);
        return FALSE;
    }

    rc = corosync_cfg_fd_get(cfg_handle, &fd);
    if (rc != CS_OK) {
        crm_err("corosync cfg fd_get error %d", rc);
        goto bail;
    }

    retries = 0;
    cs_repeat(retries, 30, rc = corosync_cfg_local_get(cfg_handle, nodeid));

    if (rc != CS_OK) {
        crm_err("corosync cfg local_get error %d", rc);
        goto bail;
    }

    crm_debug("Our nodeid: %d", *nodeid);
    mainloop_add_fd("corosync-cfg", G_PRIORITY_DEFAULT, fd, &cfg_handle, &cfg_fd_callbacks);

    return TRUE;

  bail:
    corosync_cfg_finalize(cfg_handle);
    return FALSE;
}

/* =::=::=::= Configuration =::=::=::= */
static int
get_config_opt(uint64_t unused, cmap_handle_t object_handle, const char *key, char **value,
               const char *fallback)
{
    int rc = 0, retries = 0;

    cs_repeat(retries, 5, rc = cmap_get_string(object_handle, key, value));
    if (rc != CS_OK) {
        crm_trace("Search for %s failed %d, defaulting to %s", key, rc, fallback);
        if (fallback) {
            *value = strdup(fallback);
        } else {
            *value = NULL;
        }
    }
    crm_trace("%s: %s", key, *value);
    return rc;
}

gboolean
mcp_read_config(void)
{
    int rc = CS_OK;
    int retries = 0;

    const char *const_value = NULL;

    cmap_handle_t local_handle;
    uint64_t config = 0;

    // There can be only one possibility
    do {
        rc = cmap_initialize(&local_handle);
        if (rc != CS_OK) {
            retries++;
            printf("cmap connection setup failed: %s.  Retrying in %ds\n", cs_strerror(rc), retries);
            crm_info("cmap connection setup failed: %s.  Retrying in %ds", cs_strerror(rc), retries);
            sleep(retries);

        } else {
            break;
        }

    } while (retries < 5);

    if (rc != CS_OK) {
        printf("Could not connect to Cluster Configuration Database API, error %d\n", rc);
        crm_warn("Could not connect to Cluster Configuration Database API, error %d", rc);
        return FALSE;
    }

    stack = get_cluster_type();
    crm_info("Reading configure for stack: %s", name_for_cluster_type(stack));

    /* =::=::= Should we be here =::=::= */
    if (stack == pcmk_cluster_corosync) {
        set_daemon_option("cluster_type", "corosync");
        set_daemon_option("quorum_type", "corosync");

    } else {
        crm_err("Unsupported stack type: %s", name_for_cluster_type(stack));
        return FALSE;
    }

    /* =::=::= Logging =::=::= */
    if (daemon_option("debug")) {
        /* Syslog logging is already setup by crm_log_init() */

    } else {
        /* Check corosync */
        char *debug_enabled = NULL;

        get_config_opt(config, local_handle, "logging.debug", &debug_enabled, "off");

        if (crm_is_true(debug_enabled)) {
            set_daemon_option("debug", "1");
            if (get_crm_log_level() < LOG_DEBUG) {
                set_crm_log_level(LOG_DEBUG);
            }

        } else {
            set_daemon_option("debug", "0");
        }

        free(debug_enabled);
    }

    /* If the user didn't explicitly configure a Pacemaker log file, check
     * whether they configured a corosync log file, and use that.
     *
     * @TODO Maybe we should drop this, and just rely on the logging set up by
     * crm_log_init(). That would be a significant user-visible change that
     * would need to be publicized.
     */
    if (daemon_option("logfile") == NULL) {
        /* Check corosync */
        char *logfile = NULL;
        char *logfile_enabled = NULL;

        get_config_opt(config, local_handle, "logging.to_logfile", &logfile_enabled, "on");
        get_config_opt(config, local_handle, "logging.logfile", &logfile,
                       CRM_LOG_DIR "/pacemaker.log");

        if (crm_is_true(logfile_enabled) == FALSE) {
            crm_trace("File logging disabled in corosync");

        } else if (crm_add_logfile(logfile)) {
            set_daemon_option("logfile", logfile);

        } else {
            crm_err("Couldn't create logfile: %s", logfile);
            set_daemon_option("logfile", "none");
        }

        free(logfile);
        free(logfile_enabled);
    }

    if (daemon_option("logfacility")) {
        /* Syslog logging is already setup by crm_log_init() */

    } else {
        /* Check corosync */
        char *syslog_enabled = NULL;
        char *syslog_facility = NULL;

        get_config_opt(config, local_handle, "logging.to_syslog", &syslog_enabled, "on");
        get_config_opt(config, local_handle, "logging.syslog_facility", &syslog_facility, "daemon");

        if (crm_is_true(syslog_enabled) == FALSE) {
            qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_ENABLED, QB_FALSE);
            set_daemon_option("logfacility", "none");

        } else {
            qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_FACILITY, qb_log_facility2int(syslog_facility));
            qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_ENABLED, QB_TRUE);
            set_daemon_option("logfacility", syslog_facility);
        }

        free(syslog_enabled);
        free(syslog_facility);
    }

    const_value = daemon_option("logfacility");
    if (const_value) {
        /* cluster-glue module needs HA_LOGFACILITY */
        setenv("HA_LOGFACILITY", const_value, 1);
    }

    if(local_handle){
        gid_t gid = 0;
        if (crm_user_lookup(CRM_DAEMON_USER, NULL, &gid) < 0) {
            crm_warn("Could not authorize group with corosync " CRM_XS
                     " No group found for user %s", CRM_DAEMON_USER);

        } else {
            char key[PATH_MAX];
            snprintf(key, PATH_MAX, "uidgid.gid.%u", gid);
            rc = cmap_set_uint8(local_handle, key, 1);
            if (rc != CS_OK) {
                crm_warn("Could not authorize group with corosync "CRM_XS
                         " group=%u rc=%d (%s)", gid, rc, ais_error2text(rc));
            }
        }
    }
    cmap_finalize(local_handle);

    return TRUE;
}
