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
#if HAVE_CONFDB
#  include <corosync/confdb.h>
#endif

#include <crm/common/cluster.h>

#if SUPPORT_CMAN
#  include <libcman.h>
#endif

#if HAVE_CMAP
#  include <corosync/cmap.h>
#endif

static struct cpg_name cpg_group = {
    .length = 0,
    .value[0] = 0,
};

gboolean use_cman = FALSE;
static cpg_handle_t cpg_handle;
static corosync_cfg_handle_t cfg_handle;
static corosync_cfg_state_notification_t cfg_buffer;

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
    .corosync_cfg_state_track_callback = NULL,
};

static gboolean
pcmk_cfg_dispatch(int sender, gpointer user_data)
{
    corosync_cfg_handle_t *handle = (corosync_cfg_handle_t *) user_data;
    cs_error_t rc = corosync_cfg_dispatch(*handle, CS_DISPATCH_ALL);

    if (rc != CS_OK) {
        return FALSE;
    }
    return TRUE;
}

static void
cfg_connection_destroy(gpointer user_data)
{
    crm_err("Connection destroyed");
    cfg_handle = 0;

    pcmk_shutdown(SIGTERM);
    return;
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

    retries = 0;
    cs_repeat(retries, 30, rc = corosync_cfg_state_track(cfg_handle, 0, &cfg_buffer));

    if (rc != CS_OK) {
        crm_err("corosync cfg stack_track error %d", rc);
        goto bail;
    }

    crm_debug("Adding fd=%d to mainloop", fd);
    G_main_add_fd(G_PRIORITY_HIGH, fd, FALSE, pcmk_cfg_dispatch, &cfg_handle,
                  cfg_connection_destroy);

    return TRUE;

  bail:
    corosync_cfg_finalize(cfg_handle);
    return FALSE;
}

/* =::=::=::= CPG - Closed Process Group Messaging =::=::=::= */

static gboolean
pcmk_cpg_dispatch(int sender, gpointer user_data)
{
    cpg_handle_t *handle = (cpg_handle_t *) user_data;
    cs_error_t rc = cpg_dispatch(*handle, CS_DISPATCH_ALL);

    if (rc != CS_OK) {
        return FALSE;
    }
    return TRUE;
}

static void
cpg_connection_destroy(gpointer user_data)
{
    crm_err("Connection destroyed");
    cpg_handle = 0;
    return;
}

static void
pcmk_cpg_deliver(cpg_handle_t handle,
                 const struct cpg_name *groupName,
                 uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    if (nodeid != local_nodeid) {
        uint32_t procs = 0;
        xmlNode *xml = string2xml(msg);
        const char *uname = crm_element_value(xml, "uname");

        crm_element_value_int(xml, "proclist", (int *)&procs);
        /* crm_debug("Got proclist %.32x from %s", procs, uname); */
        if (update_node_processes(nodeid, uname, procs)) {
            update_process_clients();
        }
    }
}

static void
pcmk_cpg_membership(cpg_handle_t handle,
                    const struct cpg_name *groupName,
                    const struct cpg_address *member_list, size_t member_list_entries,
                    const struct cpg_address *left_list, size_t left_list_entries,
                    const struct cpg_address *joined_list, size_t joined_list_entries)
{
    /* Don't care about CPG membership */
    update_process_peers();
}

cpg_callbacks_t cpg_callbacks = {
    .cpg_deliver_fn = pcmk_cpg_deliver,
    .cpg_confchg_fn = pcmk_cpg_membership,
};

gboolean
cluster_disconnect_cpg(void)
{
    if (cpg_handle) {
        cpg_finalize(cpg_handle);
        cpg_handle = 0;
    }
    return TRUE;
}

gboolean
cluster_connect_cpg(void)
{
    cs_error_t rc;
    unsigned int nodeid;
    int fd;
    int retries = 0;

    strcpy(cpg_group.value, "pcmk");
    cpg_group.length = strlen(cpg_group.value) + 1;

    retries = 0;
    cs_repeat(retries, 30, rc = cpg_initialize(&cpg_handle, &cpg_callbacks));
    if (rc != CS_OK) {
        crm_err("corosync cpg init error %d", rc);
        return FALSE;
    }

    rc = cpg_fd_get(cpg_handle, &fd);
    if (rc != CS_OK) {
        crm_err("corosync cpg fd_get error %d", rc);
        goto bail;
    }

    retries = 0;
    cs_repeat(retries, 30, rc = cpg_local_get(cpg_handle, &nodeid));
    if (rc != CS_OK) {
        crm_err("corosync cpg local_get error %d", rc);
        goto bail;
    }

    crm_debug("Our nodeid: %d", nodeid);

    retries = 0;
    cs_repeat(retries, 30, rc = cpg_join(cpg_handle, &cpg_group));

    if (rc != CS_OK) {
        crm_err("Could not join the CPG group '%s': %d", crm_system_name, rc);
        goto bail;
    }

    crm_debug("Adding fd=%d to mainloop", fd);
    G_main_add_fd(G_PRIORITY_HIGH, fd, FALSE, pcmk_cpg_dispatch, &cpg_handle,
                  cpg_connection_destroy);

    return TRUE;

  bail:
    cpg_finalize(cpg_handle);
    return FALSE;
}

gboolean
send_cpg_message(struct iovec * iov)
{
    int rc = CS_OK;
    int retries = 0;

    errno = 0;

    do {
        rc = cpg_mcast_joined(cpg_handle, CPG_TYPE_AGREED, iov, 1);
        if (rc == CS_ERR_TRY_AGAIN || rc == CS_ERR_QUEUE_FULL) {
            cpg_flow_control_state_t fc_state = CPG_FLOW_CONTROL_DISABLED;
            int rc2 = cpg_flow_control_state_get(cpg_handle, &fc_state);

            if (rc2 == CS_OK && fc_state == CPG_FLOW_CONTROL_ENABLED) {
                crm_debug("Attempting to clear cpg dispatch queue");
                rc2 = cpg_dispatch(cpg_handle, CS_DISPATCH_ALL);
            }

            if (rc2 != CS_OK) {
                crm_warn("Could not check/clear the cpg connection");
                goto bail;

            } else {
                retries++;
                crm_debug("Retrying operation after %ds", retries);
                sleep(retries);
            }
        } else {
            break;
        }

        /* 5 retires is plenty, we'll resend once the membership reforms anyway */
    } while (retries < 5);

  bail:
    if (rc != CS_OK) {
        crm_err("Sending message via cpg FAILED: (rc=%d) %s", rc, ais_error2text(rc));
    }

    return (rc == CS_OK);
}

/* =::=::=::= Configuration =::=::=::= */
#if HAVE_CONFDB
static int
get_config_opt(confdb_handle_t config,
               hdb_handle_t object_handle, const char *key, char **value, const char *fallback)
{
    size_t len = 0;
    char *env_key = NULL;
    const char *env_value = NULL;
    char buffer[256];

    if (*value) {
        crm_free(*value);
        *value = NULL;
    }

    if (object_handle > 0) {
        if (CS_OK == confdb_key_get(config, object_handle, key, strlen(key), &buffer, &len)) {
            *value = crm_strdup(buffer);
        }
    }

    if (*value) {
        crm_info("Found '%s' for option: %s", *value, key);
        return 0;
    }

    env_key = crm_concat("HA", key, '_');
    env_value = getenv(env_key);
    crm_free(env_key);

    if (*value) {
        crm_info("Found '%s' in ENV for option: %s", *value, key);
        *value = crm_strdup(env_value);
        return 0;
    }

    if (fallback) {
        crm_info("Defaulting to '%s' for option: %s", fallback, key);
        *value = crm_strdup(fallback);

    } else {
        crm_info("No default for option: %s", key);
    }

    return -1;
}

static confdb_handle_t
config_find_init(confdb_handle_t config)
{
    cs_error_t rc = CS_OK;
    confdb_handle_t local_handle = OBJECT_PARENT_HANDLE;

    rc = confdb_object_find_start(config, local_handle);
    if (rc == CS_OK) {
        return local_handle;
    } else {
        crm_err("Couldn't create search context: %d", rc);
    }
    return 0;
}

static hdb_handle_t
config_find_next(confdb_handle_t config, const char *name, confdb_handle_t top_handle)
{
    cs_error_t rc = CS_OK;
    hdb_handle_t local_handle = 0;

    if (top_handle == 0) {
        crm_err("Couldn't search for %s: no valid context", name);
        return 0;
    }

    crm_trace("Searching for %s in " HDB_X_FORMAT, name, top_handle);
    rc = confdb_object_find(config, top_handle, name, strlen(name), &local_handle);
    if (rc != CS_OK) {
        crm_info("No additional configuration supplied for: %s", name);
        local_handle = 0;
    } else {
        crm_info("Processing additional %s options...", name);
    }
    return local_handle;
}
#else
static int
get_config_opt(cmap_handle_t object_handle, const char *key, char **value, const char *fallback)
{
    int rc = 0, retries = 0;

    cs_repeat(retries, 5, rc = cmap_get_string(object_handle, key, value));
    if(rc != CS_OK) {
        crm_trace("Search for %s failed %d, defaulting to %s", key, rc, fallback);
        if(fallback) {
            *value = crm_strdup(fallback);
        } else {
            *value = NULL;
        }
    }
    crm_trace("%s: %s", key, *value);
    return rc;
}

#endif

char *
get_local_node_name(void)
{
    char *name = NULL;
    struct utsname res;

    if (use_cman) {
#if SUPPORT_CMAN
        cman_node_t us;
        cman_handle_t cman;

        cman = cman_init(NULL);
        if (cman != NULL && cman_is_active(cman)) {
            us.cn_name[0] = 0;
            cman_get_node(cman, CMAN_NODEID_US, &us);
            name = crm_strdup(us.cn_name);
            crm_info("Using CMAN node name: %s", name);

        } else {
            crm_err("Couldn't determin node name from CMAN");
        }

        cman_finish(cman);
#endif

    } else if (uname(&res) < 0) {
        crm_perror(LOG_ERR, "Could not determin the current host");
        exit(100);

    } else {
        name = crm_strdup(res.nodename);
    }
    return name;
}


gboolean
read_config(void)
{
    int rc = CS_OK;
    int retries = 0;
    gboolean have_log = FALSE;

    char *logging_debug = NULL;
    char *logging_logfile = NULL;
    char *logging_to_logfile = NULL;
    char *logging_to_syslog = NULL;
    char *logging_syslog_facility = NULL;    

    enum cluster_type_e stack = pcmk_cluster_unknown;

#if HAVE_CONFDB
    char *value = NULL;
    confdb_handle_t config;
    confdb_handle_t top_handle = 0;
    hdb_handle_t local_handle;
    static confdb_callbacks_t callbacks = { };

    do {
        rc = confdb_initialize(&config, &callbacks);
	if(rc < 0) {
	    retries++;
	    printf("Connection setup failed: %d.  Retrying in %ds\n", rc, retries);
	    sleep(retries);

	} else {
            break;
        }

    } while(retries < 5);
#endif

#if HAVE_CMAP
    cmap_handle_t local_handle;

    /* There can be only one (possibility if confdb isn't around) */
    do {
        rc = cmap_initialize(&local_handle);
	if(rc < 0) {
	    retries++;
	    printf("Connection setup failed: %s.  Retrying in %ds\n",
                   cs_strerror(rc), retries);
	    sleep(retries);

	} else {
            break;
        }

    } while(retries < 5);
#endif

    if (rc != CS_OK) {
        printf("Could not initialize Cluster Configuration Database API instance, error %d\n", rc);
        return FALSE;
    }

    stack = get_cluster_type();
    crm_info("Reading configure for stack: %s", name_for_cluster_type(stack));
    
    /* =::=::= Should we be here =::=::= */
    if (stack == pcmk_cluster_corosync) {
        setenv("HA_cluster_type", "corosync", 1);
        setenv("HA_quorum_type",  "corosync", 1);

#if HAVE_CONFDB
    } else if (stack == pcmk_cluster_cman) {
        setenv("HA_cluster_type", "cman", 1);
        setenv("HA_quorum_type",  "cman", 1);
        enable_crmd_as_root(TRUE);
        use_cman = TRUE;

    } else if (stack == pcmk_cluster_classic_ais) {
        setenv("HA_cluster_type", "openais", 1);
        setenv("HA_quorum_type",  "pcmk", 1);

        /* Look for a service block to indicate our plugin is loaded */
        top_handle = config_find_init(config);
        local_handle = config_find_next(config, "service", top_handle);

        while (local_handle) {
            crm_free(value);
            get_config_opt(config, local_handle, "name", &value, NULL);
            if (safe_str_eq("pacemaker", value)) {
                crm_free(value);
                get_config_opt(config, local_handle, "ver", &value, "0");
                if (safe_str_eq(value, "1")) {
                    crm_free(value);
                    get_config_opt(config, local_handle, "use_logd", &value, "no");
                    setenv("HA_use_logd", value, 1);
                    setenv("HA_LOGD", value, 1);

                    crm_free(value);
                    get_config_opt(config, local_handle, "use_mgmtd", &value, "no");
                    enable_mgmtd(crm_is_true(value));

                } else {
                    crm_err("We can only start Pacemaker from init if using version 1"
                            " of the Pacemaker plugin for Corosync.  Terminating.");
                    exit(100);
                }
                break;
            }
            local_handle = config_find_next(config, "service", top_handle);
        }
        crm_free(value);

#endif
    } else {
        crm_err("Unsupported stack type: %s", name_for_cluster_type(stack));
        return FALSE;
    }

#if HAVE_CMAP
    /* =::=::= Logging =::=::= */
    get_config_opt(local_handle, "logging.debug", &logging_debug, "on");
    get_config_opt(local_handle, "logging.logfile", &logging_logfile, "/var/log/pacemaker");
    get_config_opt(local_handle, "logging.to_logfile", &logging_to_logfile, "off");
    get_config_opt(local_handle, "logging.to_syslog", &logging_to_syslog, "on");
    get_config_opt(local_handle, "logging.syslog_facility", &logging_syslog_facility, "daemon");

    cmap_finalize(local_handle); 
#endif

#if HAVE_CONFDB
    top_handle = config_find_init(config);
    local_handle = config_find_next(config, "logging", top_handle);
    
    get_config_opt(config, local_handle, "debug", &logging_debug, "on");
    get_config_opt(config, local_handle, "logfile", &logging_logfile, "/var/log/pacemaker");
    get_config_opt(config, local_handle, "to_logfile", &logging_to_logfile, "off");
    get_config_opt(config, local_handle, "to_syslog", &logging_to_syslog, "on");
    get_config_opt(config, local_handle, "syslog_facility", &logging_syslog_facility, "daemon");

    confdb_finalize(config);    
#endif
    
    if (crm_is_true(logging_debug) && get_crm_log_level() < LOG_DEBUG) {
        set_crm_log_level(LOG_DEBUG);
    }

    if (get_crm_log_level() >= LOG_DEBUG) {
        setenv("HA_debug", "1", 1);
    }

    if (crm_is_true(logging_to_logfile)) {
        struct stat parent;
        uid_t pcmk_uid = 0;
        uid_t pcmk_gid = getegid();

        FILE *logfile = NULL;
        char *parent_dir = NULL;
        struct passwd *pcmk_user = getpwnam(CRM_DAEMON_USER);

        if(pcmk_user) { 
            pcmk_uid = pcmk_user->pw_uid;

        } else {
            crm_err("User %s does not exist. Terminating", CRM_DAEMON_USER);
            exit(100);
        }

        parent_dir = dirname(strdup(logging_logfile));
        rc = stat(parent_dir, &parent);

        if (rc != 0) {
            crm_err("Directory '%s' does not exist for logfile '%s'", parent_dir, logging_logfile);

        } else if (parent.st_uid == pcmk_uid && (parent.st_mode & (S_IRUSR | S_IWUSR))) {
            /* all good - user */
            logfile = fopen(logging_logfile, "a");

        } else if (parent.st_gid == pcmk_gid && (parent.st_mode & S_IXGRP)) {
            /* all good - group */
            logfile = fopen(logging_logfile, "a");

        } else {
            crm_err
                ("Daemons running as %s do not have permission to access '%s'. Logging to '%s' is disabled",
                 CRM_DAEMON_USER, parent_dir, logging_logfile);
        }

        if (logfile) {
            int logfd = fileno(logfile);

            setenv("HA_debugfile", logging_logfile, 1);
            setenv("HA_DEBUGLOG", logging_logfile, 1);
            setenv("HA_LOGFILE", logging_logfile, 1);

            /* Ensure the file has the correct permissions */
            rc = fchown(logfd, pcmk_uid, pcmk_gid);
            if(rc < 0) {
                crm_warn("Cannot change the ownership of %s to user %s and gid %d",
                         logging_logfile, CRM_DAEMON_USER, pcmk_gid);
            }
            rc = fchmod(logfd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
            if(rc < 0) {
                crm_warn("Cannot change the mode of %s to rw-rw----", logging_logfile);
            }

            fprintf(logfile, "Set r/w permissions for uid=%d, gid=%d on %s\n",
                    pcmk_uid, pcmk_gid, logging_logfile);
            fflush(logfile);
            fsync(logfd);
            fclose(logfile);
            have_log = TRUE;

        } else {
            crm_err("Couldn't create logfile: %s", logging_logfile);
        }
        crm_free(parent_dir);
    }

    if (have_log && crm_is_true(logging_to_syslog) == FALSE) {
        crm_info("User configured file based logging and explicitly disabled syslog.");
        free(logging_syslog_facility);
        logging_syslog_facility = NULL;

    } else {
        if (crm_is_true(logging_to_syslog) == FALSE) {
            crm_err
                ("Please enable some sort of logging, either 'to_logfile: on' or  'to_syslog: on'.");
            crm_err("If you use file logging, be sure to also define a value for 'logfile'");
        }
    }

    if(logging_syslog_facility) {
        setenv("HA_logfacility", logging_syslog_facility, 1);
        setenv("HA_LOGFACILITY", logging_syslog_facility, 1);
    } else {
        unsetenv("HA_logfacility");
        unsetenv("HA_LOGFACILITY");
    }
    
    free(logging_debug);
    free(logging_logfile);
    free(logging_to_logfile);
    free(logging_to_syslog);
    free(logging_syslog_facility);
    return TRUE;
}
