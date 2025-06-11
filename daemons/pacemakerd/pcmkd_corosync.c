/*
 * Copyright 2010-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include "pacemakerd.h"
#include "pcmkd_corosync.h"

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
#include <crm/common/ipc.h>     /* for crm_ipc_is_authentic_process */
#include <crm/common/mainloop.h>

#include <crm/common/ipc_internal.h>  /* PCMK__SPECIAL_PID* */

static corosync_cfg_handle_t cfg_handle = 0;
static mainloop_timer_t *reconnect_timer = NULL;

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
close_cfg(void)
{
    if (cfg_handle != 0) {
#ifdef HAVE_COROSYNC_CFG_TRACKSTART
        /* Ideally, we would call corosync_cfg_trackstop(cfg_handle) here, but a
         * bug in corosync 3.1.1 and 3.1.2 makes it hang forever. Thankfully,
         * it's not necessary since we exit immediately after this.
         */
#endif
        corosync_cfg_finalize(cfg_handle);
        cfg_handle = 0;
    }
}

static gboolean
cluster_reconnect_cb(gpointer data)
{
    if (cluster_connect_cfg()) {
        mainloop_timer_del(reconnect_timer);
        reconnect_timer = NULL;
        crm_notice("Cluster reconnect succeeded");
        pacemakerd_read_config();
        restart_cluster_subdaemons();
        return G_SOURCE_REMOVE;
    } else {
        crm_info("Cluster reconnect failed "
                 "(connection will be reattempted once per second)");
    }
    /*
     * In theory this will continue forever. In practice the CIB connection from
     * attrd will timeout and shut down Pacemaker when it gets bored.
     */
    return G_SOURCE_CONTINUE;
}


static void
cfg_connection_destroy(gpointer user_data)
{
    crm_warn("Lost connection to cluster layer "
             "(connection will be reattempted once per second)");
    corosync_cfg_finalize(cfg_handle);
    cfg_handle = 0;
    reconnect_timer = mainloop_timer_add("corosync reconnect", 1000, TRUE, cluster_reconnect_cb, NULL);
    mainloop_timer_start(reconnect_timer);
}

void
cluster_disconnect_cfg(void)
{
    close_cfg();
    if (reconnect_timer != NULL) {
        /* The mainloop should be gone by this point, so this isn't necessary,
         * but cleaning up memory should make valgrind happier.
         */
        mainloop_timer_del(reconnect_timer);
        reconnect_timer = NULL;
    }
}

#define cs_repeat(counter, max, code) do {		\
	code;						\
	if(rc == CS_ERR_TRY_AGAIN || rc == CS_ERR_QUEUE_FULL) {  \
	    counter++;					\
	    crm_debug("Retrying Corosync operation after %ds", counter);    \
	    sleep(counter);				\
	} else {                                        \
            break;                                      \
	}						\
    } while(counter < max)

gboolean
cluster_connect_cfg(void)
{
    cs_error_t rc;
    int fd = -1, retries = 0, rv;
    uid_t found_uid = 0;
    gid_t found_gid = 0;
    pid_t found_pid = 0;
    uint32_t nodeid;

    static struct mainloop_fd_callbacks cfg_fd_callbacks = {
        .dispatch = pcmk_cfg_dispatch,
        .destroy = cfg_connection_destroy,
    };

    cs_repeat(retries, 30, rc = corosync_cfg_initialize(&cfg_handle, &cfg_callbacks));

    if (rc != CS_OK) {
        crm_crit("Could not connect to Corosync CFG: %s " QB_XS " rc=%d",
                 cs_strerror(rc), rc);
        return FALSE;
    }

    rc = corosync_cfg_fd_get(cfg_handle, &fd);
    if (rc != CS_OK) {
        crm_crit("Could not get Corosync CFG descriptor: %s " QB_XS " rc=%d",
                 cs_strerror(rc), rc);
        goto bail;
    }

    /* CFG provider run as root (in given user namespace, anyway)? */
    if (!(rv = crm_ipc_is_authentic_process(fd, (uid_t) 0,(gid_t) 0, &found_pid,
                                            &found_uid, &found_gid))) {
        crm_crit("Rejecting Corosync CFG provider because process %lld "
                 "is running as uid %lld gid %lld, not root",
                  (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                 (long long) found_uid, (long long) found_gid);
        goto bail;
    } else if (rv < 0) {
        crm_crit("Could not authenticate Corosync CFG provider: %s "
                 QB_XS " rc=%d", strerror(-rv), -rv);
        goto bail;
    }

    retries = 0;
    cs_repeat(retries, 30, rc = corosync_cfg_local_get(cfg_handle, &nodeid));
    if (rc != CS_OK) {
        crm_crit("Could not get local node ID from Corosync: %s "
                 QB_XS " rc=%d", cs_strerror(rc), rc);
        goto bail;
    }
    crm_debug("Corosync reports local node ID is %lu", (unsigned long) nodeid);

#ifdef HAVE_COROSYNC_CFG_TRACKSTART
    retries = 0;
    cs_repeat(retries, 30, rc = corosync_cfg_trackstart(cfg_handle, 0));
    if (rc != CS_OK) {
        crm_crit("Could not enable Corosync CFG shutdown tracker: %s " QB_XS " rc=%d",
                 cs_strerror(rc), rc);
        goto bail;
    }
#endif

    mainloop_add_fd("corosync-cfg", G_PRIORITY_DEFAULT, fd, &cfg_handle, &cfg_fd_callbacks);
    return TRUE;

  bail:
    corosync_cfg_finalize(cfg_handle);
    return FALSE;
}

void
pcmkd_shutdown_corosync(void)
{
    cs_error_t rc;

    if (cfg_handle == 0) {
        crm_warn("Unable to shut down Corosync: No connection");
        return;
    }
    crm_info("Asking Corosync to shut down");
    rc = corosync_cfg_try_shutdown(cfg_handle,
                                    COROSYNC_CFG_SHUTDOWN_FLAG_IMMEDIATE);
    if (rc == CS_OK) {
        close_cfg();
    } else {
        crm_warn("Corosync shutdown failed: %s " QB_XS " rc=%d",
                 cs_strerror(rc), rc);
    }
}

bool
pcmkd_corosync_connected(void)
{
    cpg_handle_t local_handle = 0;
    cpg_model_v1_data_t cpg_model_info = {CPG_MODEL_V1, NULL, NULL, NULL, 0};
    int fd = -1;

    if (cpg_model_initialize(&local_handle, CPG_MODEL_V1, (cpg_model_data_t *) &cpg_model_info, NULL) != CS_OK) {
        return false;
    }

    if (cpg_fd_get(local_handle, &fd) != CS_OK) {
        return false;
    }

    cpg_finalize(local_handle);

    return true;
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
        pcmk__str_update(value, fallback);
    }
    crm_trace("%s: %s", key, *value);
    return rc;
}

gboolean
pacemakerd_read_config(void)
{
    cs_error_t rc = CS_OK;
    int retries = 0;
    cmap_handle_t local_handle;
    uint64_t config = 0;
    int fd = -1;
    uid_t found_uid = 0;
    gid_t found_gid = 0;
    pid_t found_pid = 0;
    int rv;
    enum pcmk_cluster_layer cluster_layer = pcmk_cluster_layer_unknown;
    const char *cluster_layer_s = NULL;

    // There can be only one possibility
    do {
        rc = pcmk__init_cmap(&local_handle);
        if (rc != CS_OK) {
            retries++;
            crm_info("Could not connect to Corosync CMAP: %s (retrying in %ds) "
                     QB_XS " rc=%d", cs_strerror(rc), retries, rc);
            sleep(retries);

        } else {
            break;
        }

    } while (retries < 5);

    if (rc != CS_OK) {
        crm_crit("Could not connect to Corosync CMAP: %s "
                 QB_XS " rc=%d", cs_strerror(rc), rc);
        return FALSE;
    }

    rc = cmap_fd_get(local_handle, &fd);
    if (rc != CS_OK) {
        crm_crit("Could not get Corosync CMAP descriptor: %s " QB_XS " rc=%d",
                 cs_strerror(rc), rc);
        cmap_finalize(local_handle);
        return FALSE;
    }

    /* CMAP provider run as root (in given user namespace, anyway)? */
    if (!(rv = crm_ipc_is_authentic_process(fd, (uid_t) 0,(gid_t) 0, &found_pid,
                                            &found_uid, &found_gid))) {
        crm_crit("Rejecting Corosync CMAP provider because process %lld "
                 "is running as uid %lld gid %lld, not root",
                 (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                 (long long) found_uid, (long long) found_gid);
        cmap_finalize(local_handle);
        return FALSE;
    } else if (rv < 0) {
        crm_crit("Could not authenticate Corosync CMAP provider: %s "
                 QB_XS " rc=%d", strerror(-rv), -rv);
        cmap_finalize(local_handle);
        return FALSE;
    }

    cluster_layer = pcmk_get_cluster_layer();
    cluster_layer_s = pcmk_cluster_layer_text(cluster_layer);

    if (cluster_layer != pcmk_cluster_layer_corosync) {
        crm_crit("Expected Corosync cluster layer but detected %s "
                 QB_XS " cluster_layer=%d",
                 cluster_layer_s, cluster_layer);
        return FALSE;
    }

    crm_info("Reading configuration for %s cluster layer", cluster_layer_s);
    pcmk__set_env_option(PCMK__ENV_CLUSTER_TYPE, PCMK_VALUE_COROSYNC, true);

    // If debug logging is not configured, check whether corosync has it
    if (pcmk__env_option(PCMK__ENV_DEBUG) == NULL) {
        char *debug_enabled = NULL;

        get_config_opt(config, local_handle, "logging.debug", &debug_enabled,
                       PCMK_VALUE_OFF);

        if (crm_is_true(debug_enabled)) {
            pcmk__set_env_option(PCMK__ENV_DEBUG, "1", true);
            if (get_crm_log_level() < LOG_DEBUG) {
                set_crm_log_level(LOG_DEBUG);
            }

        } else {
            pcmk__set_env_option(PCMK__ENV_DEBUG, "0", true);
        }

        free(debug_enabled);
    }

    if(local_handle){
        gid_t gid = 0;
        if (pcmk_daemon_user(NULL, &gid) < 0) {
            crm_warn("Could not authorize group with Corosync " QB_XS
                     " No group found for user %s", CRM_DAEMON_USER);

        } else {
            char key[PATH_MAX];
            pcmk__snprintf(key, PATH_MAX, "uidgid.gid.%u", gid);
            rc = cmap_set_uint8(local_handle, key, 1);
            if (rc != CS_OK) {
                crm_warn("Could not authorize group with Corosync: %s " QB_XS
                         " group=%u rc=%d", pcmk__cs_err_str(rc), gid, rc);
            }
        }
    }
    cmap_finalize(local_handle);

    return TRUE;
}
