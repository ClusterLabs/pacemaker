/*
 * Copyright 2006-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <crm/common/attrd_internal.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_attrd_internal.h>
#include <crm/msg_xml.h>

#include <pacemaker-controld.h>

static pcmk_ipc_api_t *attrd_api = NULL;

enum attrd_command {
    cmd_clear,
    cmd_purge,
    cmd_update
};

void
controld_close_attrd_ipc(void)
{
    if (attrd_api != NULL) {
        crm_trace("Closing connection to pacemaker-attrd");
        pcmk_disconnect_ipc(attrd_api);
        pcmk_free_ipc_api(attrd_api);
        attrd_api = NULL;
    }
}

static inline const char *
node_type(bool is_remote)
{
    return is_remote? "Pacemaker Remote" : "cluster";
}

static inline const char *
when(void)
{
    return pcmk_is_set(fsa_input_register, R_SHUTDOWN)? " at shutdown" : "";
}

static void
handle_attr_error(void)
{
    if (AM_I_DC) {
        /* We are unable to provide accurate information to the
         * scheduler, so allow another node to take over DC.
         * @TODO Should we do this unconditionally on any failure?
         */
        crmd_exit(CRM_EX_FATAL);

    } else if (pcmk_is_set(fsa_input_register, R_SHUTDOWN)) {
        // Fast-track shutdown since unable to request via attribute
        register_fsa_input(C_FSA_INTERNAL, I_FAIL, NULL);
    }
}

static void
log_attrd_error(const char *host, const char *name, const char *value,
                gboolean is_remote, enum attrd_command command, int rc)
{
    switch (command) {
        case cmd_clear:
            crm_err("Could not clear failure attributes for %s on %s node %s%s: %s "
                    CRM_XS " rc=%d", (name? name : "all resources"),
                    node_type(is_remote), host, when(), pcmk_rc_str(rc), rc);
            break;

        case cmd_purge:
            crm_err("Could not purge %s node %s in attribute manager%s: %s "
                    CRM_XS " rc=%d",
                    node_type(is_remote), host, when(), pcmk_rc_str(rc), rc);
            break;

        case cmd_update:
            /* We weren't able to update an attribute after several retries,
             * so something is horribly wrong with the attribute manager or the
             * underlying system.
             */
            do_crm_log(AM_I_DC? LOG_CRIT : LOG_ERR,
                       "Could not update attribute %s=%s for %s node %s%s: %s "
                       CRM_XS " rc=%d", name, value, node_type(is_remote), host,
                       when(), pcmk_rc_str(rc), rc);
            handle_attr_error();
            break;
    }
}

static void
update_attrd_helper(const char *host, const char *name, const char *value,
                    const char *interval_spec, const char *user_name,
                    gboolean is_remote_node, enum attrd_command command)
{
    int rc;
    int attrd_opts = pcmk__node_attr_none;

    if (is_remote_node) {
        pcmk__set_node_attr_flags(attrd_opts, pcmk__node_attr_remote);
    }

    if (attrd_api == NULL) {
        rc = pcmk_new_ipc_api(&attrd_api, pcmk_ipc_attrd);

        if (rc != pcmk_rc_ok) {
            log_attrd_error(host, name, value, is_remote_node, command, rc);
            return;
        }
    }

    switch (command) {
        case cmd_clear:
            /* name/value is really resource/operation */
            rc = pcmk__attrd_api_clear_failures(attrd_api, host, name,
                                                value, interval_spec,
                                                user_name, attrd_opts);
            break;

        case cmd_update:
            rc = pcmk__attrd_api_update(attrd_api, host, name, value,
                                        NULL, NULL, user_name,
                                        attrd_opts | pcmk__node_attr_value);
            break;

        case cmd_purge:
            rc = pcmk__attrd_api_purge(attrd_api, host);
            break;
    }

    if (rc != pcmk_rc_ok) {
        log_attrd_error(host, name, value, is_remote_node, command, rc);
    }
}

void
update_attrd(const char *host, const char *name, const char *value,
             const char *user_name, gboolean is_remote_node)
{
    update_attrd_helper(host, name, value, NULL, user_name, is_remote_node,
                        cmd_update);
}

void
update_attrd_list(GList *attrs, uint32_t opts)
{
    int rc = pcmk_rc_ok;

    if (attrd_api == NULL) {
        rc = pcmk_new_ipc_api(&attrd_api, pcmk_ipc_attrd);
    }
    if (rc == pcmk_rc_ok) {
        rc = pcmk__attrd_api_update_list(attrd_api, attrs, NULL, NULL, NULL,
                                         opts | pcmk__node_attr_value);
    }
    if (rc != pcmk_rc_ok) {
        do_crm_log(AM_I_DC? LOG_CRIT : LOG_ERR,
                   "Could not update multiple node attributes: %s "
                   CRM_XS " rc=%d", pcmk_rc_str(rc), rc);
        handle_attr_error();
    }
}

void
update_attrd_remote_node_removed(const char *host, const char *user_name)
{
    crm_trace("Asking attribute manager to purge Pacemaker Remote node %s",
              host);
    update_attrd_helper(host, NULL, NULL, NULL, user_name, TRUE, cmd_purge);
}

void
update_attrd_clear_failures(const char *host, const char *rsc, const char *op,
                            const char *interval_spec, gboolean is_remote_node)
{
    const char *op_desc = NULL;
    const char *interval_desc = NULL;

    if (op) {
        interval_desc = interval_spec? interval_spec : "nonrecurring";
        op_desc = op;
    } else {
        interval_desc = "all";
        op_desc = "operations";
    }
    crm_info("Asking pacemaker-attrd to clear failure of %s %s for %s on %s node %s",
             interval_desc, op_desc, rsc, node_type(is_remote_node), host);
    update_attrd_helper(host, rsc, op, interval_spec, NULL, is_remote_node, cmd_clear);
}
