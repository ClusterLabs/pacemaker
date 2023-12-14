/*
 * Copyright 2006-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <crm/common/attrs_internal.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_attrd_internal.h>
#include <crm/common/xml.h>

#include <pacemaker-controld.h>

static pcmk_ipc_api_t *attrd_api = NULL;

void
controld_close_attrd_ipc(void)
{
    if (attrd_api != NULL) {
        crm_trace("Closing connection to " PCMK__SERVER_ATTRD);
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
    return pcmk_is_set(controld_globals.fsa_input_register,
                       R_SHUTDOWN)? " at shutdown" : "";
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

    } else if (pcmk_is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
        // Fast-track shutdown since unable to request via attribute
        register_fsa_input(C_FSA_INTERNAL, I_FAIL, NULL);
    }
}

void
update_attrd(const char *host, const char *name, const char *value,
             const char *user_name, gboolean is_remote_node)
{
    int rc = pcmk_rc_ok;

    if (attrd_api == NULL) {
        rc = pcmk_new_ipc_api(&attrd_api, pcmk_ipc_attrd);
    }
    if (rc == pcmk_rc_ok) {
        uint32_t attrd_opts = pcmk__node_attr_value;

        if (is_remote_node) {
            pcmk__set_node_attr_flags(attrd_opts, pcmk__node_attr_remote);
        }
        rc = pcmk__attrd_api_update(attrd_api, host, name, value,
                                    NULL, NULL, user_name, attrd_opts);
    }
    if (rc != pcmk_rc_ok) {
        do_crm_log(AM_I_DC? LOG_CRIT : LOG_ERR,
                   "Could not update attribute %s=%s for %s node %s%s: %s "
                   QB_XS " rc=%d", name, value, node_type(is_remote_node),
                   host, when(), pcmk_rc_str(rc), rc);
        handle_attr_error();
    }
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
                   QB_XS " rc=%d", pcmk_rc_str(rc), rc);
        handle_attr_error();
    }
}

/*!
 * \internal
 * \brief Ask attribute manager to purge a node and its transient attributes
 *
 * \param[in] node_name   Node to purge
 * \param[in] from_cache  If true, purge from node caches as well
 */
void
controld_purge_node_attrs(const char *node_name, bool from_cache)
{
    int rc = pcmk_rc_ok;

    if (attrd_api == NULL) {
        rc = pcmk_new_ipc_api(&attrd_api, pcmk_ipc_attrd);
    }
    if (rc == pcmk_rc_ok) {
        crm_debug("Asking %s to purge transient attributes%s for %s ",
                  pcmk_ipc_name(attrd_api, true),
                  (from_cache? " and node cache" : ""), node_name);
        rc = pcmk__attrd_api_purge(attrd_api, node_name, from_cache);
    }
    if (rc != pcmk_rc_ok) {
        crm_err("Could not purge node %s from attribute manager%s: %s "
                QB_XS " rc=%d", node_name, when(), pcmk_rc_str(rc), rc);
    }
}

void
update_attrd_clear_failures(const char *host, const char *rsc, const char *op,
                            const char *interval_spec, gboolean is_remote_node)
{
    int rc = pcmk_rc_ok;

    if (attrd_api == NULL) {
        rc = pcmk_new_ipc_api(&attrd_api, pcmk_ipc_attrd);
    }
    if (rc == pcmk_rc_ok) {
        uint32_t attrd_opts = pcmk__node_attr_none;

        if (is_remote_node) {
            pcmk__set_node_attr_flags(attrd_opts, pcmk__node_attr_remote);
        }
        rc = pcmk__attrd_api_clear_failures(attrd_api, host, rsc, op,
                                            interval_spec, NULL, attrd_opts);
    }
    if (rc != pcmk_rc_ok) {
        const char *interval_desc = "all";

        if (op != NULL) {
            interval_desc = pcmk__s(interval_spec, "nonrecurring");
        }
        crm_err("Could not clear failure of %s %s for %s on %s node %s%s: %s "
                QB_XS " rc=%d", interval_desc, pcmk__s(op, "operations"),
                pcmk__s(rsc, "all resources"), node_type(is_remote_node), host,
                when(), pcmk_rc_str(rc), rc);
    }
}
