/*
 * Copyright 2013-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>
#include <crm/pengine/rules.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/iso8601.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/xml.h>
#include <crm/cluster/internal.h>

#include <crm/common/attrd_internal.h>
#include "pacemaker-attrd.h"

#define SUMMARY "daemon for managing Pacemaker node attributes"

lrmd_t *the_lrmd = NULL;
crm_cluster_t *attrd_cluster = NULL;
crm_trigger_t *attrd_config_read = NULL;
static crm_exit_t attrd_exit_status = CRM_EX_OK;

static void
attrd_cpg_dispatch(cpg_handle_t handle,
                 const struct cpg_name *groupName,
                 uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    uint32_t kind = 0;
    xmlNode *xml = NULL;
    const char *from = NULL;
    char *data = pcmk_message_common_cs(handle, nodeid, pid, msg, &kind, &from);

    if(data == NULL) {
        return;
    }

    if (kind == crm_class_cluster) {
        xml = string2xml(data);
    }

    if (xml == NULL) {
        crm_err("Bad message of class %d received from %s[%u]: '%.120s'", kind, from, nodeid, data);
    } else {
        crm_node_t *peer = crm_get_peer(nodeid, from);

        attrd_peer_message(peer, xml);
    }

    free_xml(xml);
    free(data);
}

static void
attrd_cpg_destroy(gpointer unused)
{
    if (attrd_shutting_down()) {
        crm_info("Corosync disconnection complete");

    } else {
        crm_crit("Lost connection to cluster layer, shutting down");
        attrd_exit_status = CRM_EX_DISCONNECT;
        attrd_shutdown(0);
    }
}

static void
attrd_cib_destroy_cb(gpointer user_data)
{
    cib_t *conn = user_data;

    conn->cmds->signoff(conn);  /* Ensure IPC is cleaned up */

    if (attrd_shutting_down()) {
        crm_info("Connection disconnection complete");

    } else {
        /* eventually this should trigger a reconnect, not a shutdown */
        crm_crit("Lost connection to the CIB manager, shutting down");
        attrd_exit_status = CRM_EX_DISCONNECT;
        attrd_shutdown(0);
    }

    return;
}

static void
attrd_erase_cb(xmlNode *msg, int call_id, int rc, xmlNode *output,
               void *user_data)
{
    do_crm_log_unlikely((rc? LOG_NOTICE : LOG_DEBUG),
                        "Cleared transient attributes: %s "
                        CRM_XS " xpath=%s rc=%d",
                        pcmk_strerror(rc), (char *) user_data, rc);
}

#define XPATH_TRANSIENT "//node_state[@uname='%s']/" XML_TAG_TRANSIENT_NODEATTRS

/*!
 * \internal
 * \brief Wipe all transient attributes for this node from the CIB
 *
 * Clear any previous transient node attributes from the CIB. This is
 * normally done by the DC's controller when this node leaves the cluster, but
 * this handles the case where the node restarted so quickly that the
 * cluster layer didn't notice.
 *
 * \todo If pacemaker-attrd respawns after crashing (see PCMK_respawned),
 *       ideally we'd skip this and sync our attributes from the writer.
 *       However, currently we reject any values for us that the writer has, in
 *       attrd_peer_update().
 */
static void
attrd_erase_attrs(void)
{
    int call_id;
    char *xpath = crm_strdup_printf(XPATH_TRANSIENT, attrd_cluster->uname);

    crm_info("Clearing transient attributes from CIB " CRM_XS " xpath=%s",
             xpath);

    call_id = the_cib->cmds->remove(the_cib, xpath, NULL,
                                    cib_quorum_override | cib_xpath);
    the_cib->cmds->register_callback_full(the_cib, call_id, 120, FALSE, xpath,
                                          "attrd_erase_cb", attrd_erase_cb,
                                          free);
}

static int
attrd_cib_connect(int max_retry)
{
    static int attempts = 0;

    int rc = -ENOTCONN;

    the_cib = cib_new();
    if (the_cib == NULL) {
        return -ENOTCONN;
    }

    do {
        if(attempts > 0) {
            sleep(attempts);
        }

        attempts++;
        crm_debug("Connection attempt %d to the CIB manager", attempts);
        rc = the_cib->cmds->signon(the_cib, T_ATTRD, cib_command);

    } while(rc != pcmk_ok && attempts < max_retry);

    if (rc != pcmk_ok) {
        crm_err("Connection to the CIB manager failed: %s " CRM_XS " rc=%d",
                pcmk_strerror(rc), rc);
        goto cleanup;
    }

    crm_debug("Connected to the CIB manager after %d attempts", attempts);

    rc = the_cib->cmds->set_connection_dnotify(the_cib, attrd_cib_destroy_cb);
    if (rc != pcmk_ok) {
        crm_err("Could not set disconnection callback");
        goto cleanup;
    }

    rc = the_cib->cmds->add_notify_callback(the_cib, T_CIB_REPLACE_NOTIFY, attrd_cib_replaced_cb);
    if(rc != pcmk_ok) {
        crm_err("Could not set CIB notification callback");
        goto cleanup;
    }

    rc = the_cib->cmds->add_notify_callback(the_cib, T_CIB_DIFF_NOTIFY, attrd_cib_updated_cb);
    if (rc != pcmk_ok) {
        crm_err("Could not set CIB notification callback (update)");
        goto cleanup;
    }

    return pcmk_ok;

  cleanup:
    cib__clean_up_connection(&the_cib);
    return -ENOTCONN;
}

/*!
 * \internal
 * \brief Prepare the CIB after cluster is connected
 */
static void
attrd_cib_init(void)
{
    // We have no attribute values in memory, wipe the CIB to match
    attrd_erase_attrs();

    // Set a trigger for reading the CIB (for the alerts section)
    attrd_config_read = mainloop_add_trigger(G_PRIORITY_HIGH, attrd_read_options, NULL);

    // Always read the CIB at start-up
    mainloop_set_trigger(attrd_config_read);
}

static qb_ipcs_service_t *ipcs = NULL;

static int32_t
attrd_ipc_dispatch(qb_ipcs_connection_t * c, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    pcmk__client_t *client = pcmk__find_client(c);
    xmlNode *xml = NULL;
    const char *op;

    // Sanity-check, and parse XML from IPC data
    CRM_CHECK((c != NULL) && (client != NULL), return 0);
    if (data == NULL) {
        crm_debug("No IPC data from PID %d", pcmk__client_pid(c));
        return 0;
    }
    xml = pcmk__client_data2xml(client, data, &id, &flags);
    if (xml == NULL) {
        crm_debug("Unrecognizable IPC data from PID %d", pcmk__client_pid(c));
        return 0;
    }

    CRM_ASSERT(client->user != NULL);
    pcmk__update_acl_user(xml, PCMK__XA_ATTR_USER, client->user);

    op = crm_element_value(xml, PCMK__XA_TASK);

    if (client->name == NULL) {
        const char *value = crm_element_value(xml, F_ORIG);
        client->name = crm_strdup_printf("%s.%d", value?value:"unknown", client->pid);
    }

    if (pcmk__str_eq(op, PCMK__ATTRD_CMD_PEER_REMOVE, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_peer_remove(client, xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_CLEAR_FAILURE, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_clear_failure(xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_update(xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE_BOTH, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_update(xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE_DELAY, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_update(xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_REFRESH, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_refresh();

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_QUERY, pcmk__str_casei)) {
        /* queries will get reply, so no ack is necessary */
        attrd_client_query(client, id, flags, xml);

    } else {
        crm_info("Ignoring request from client %s with unknown operation %s",
                 pcmk__client_name(client), op);
    }

    free_xml(xml);
    return 0;
}

void
attrd_ipc_fini(void)
{
    if (ipcs != NULL) {
        pcmk__drop_all_clients(ipcs);
        qb_ipcs_destroy(ipcs);
        ipcs = NULL;
    }
}

static int
attrd_cluster_connect(void)
{
    attrd_cluster = calloc(1, sizeof(crm_cluster_t));

    attrd_cluster->destroy = attrd_cpg_destroy;
    attrd_cluster->cpg.cpg_deliver_fn = attrd_cpg_dispatch;
    attrd_cluster->cpg.cpg_confchg_fn = pcmk_cpg_membership;

    crm_set_status_callback(&attrd_peer_change_cb);

    if (crm_cluster_connect(attrd_cluster) == FALSE) {
        crm_err("Cluster connection failed");
        return -ENOTCONN;
    }
    return pcmk_ok;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args) {
    return pcmk__build_arg_context(args, NULL, NULL, NULL);
}

int
main(int argc, char **argv)
{
    crm_ipc_t *old_instance = NULL;

    GError *error = NULL;
    bool initialized = false;

    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, NULL);
    GOptionContext *context = build_arg_context(args);

    attrd_init_mainloop();
    crm_log_preinit(NULL, argc, argv);
    mainloop_add_signal(SIGTERM, attrd_shutdown);

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        attrd_exit_status = CRM_EX_USAGE;
        goto done;
    }

    if (args->version) {
        g_strfreev(processed_args);
        pcmk__free_arg_context(context);
        /* FIXME:  When pacemaker-attrd is converted to use formatted output, this can go. */
        pcmk__cli_help('v', CRM_EX_OK);
    }

    initialized = true;

    crm_log_init(T_ATTRD, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    crm_notice("Starting Pacemaker node attribute manager");

    old_instance = crm_ipc_new(T_ATTRD, 0);
    if (crm_ipc_connect(old_instance)) {
        /* IPC end-point already up */
        crm_ipc_close(old_instance);
        crm_ipc_destroy(old_instance);
        crm_err("pacemaker-attrd is already active, aborting startup");
        crm_exit(CRM_EX_OK);
    } else {
        /* not up or not authentic, we'll proceed either way */
        crm_ipc_destroy(old_instance);
        old_instance = NULL;
    }

    attributes = pcmk__strkey_table(NULL, free_attribute);

    /* Connect to the CIB before connecting to the cluster or listening for IPC.
     * This allows us to assume the CIB is connected whenever we process a
     * cluster or IPC message (which also avoids start-up race conditions).
     */
    if (attrd_cib_connect(30) != pcmk_ok) {
        attrd_exit_status = CRM_EX_FATAL;
        goto done;
    }
    crm_info("CIB connection active");

    if (attrd_cluster_connect() != pcmk_ok) {
        attrd_exit_status = CRM_EX_FATAL;
        goto done;
    }
    crm_info("Cluster connection active");

    // Initialization that requires the cluster to be connected
    attrd_election_init();
    attrd_cib_init();

    /* Set a private attribute for ourselves with the protocol version we
     * support. This lets all nodes determine the minimum supported version
     * across all nodes. It also ensures that the writer learns our node name,
     * so it can send our attributes to the CIB.
     */
    attrd_broadcast_protocol();

    attrd_init_ipc(&ipcs, attrd_ipc_dispatch);
    crm_notice("Pacemaker node attribute manager successfully started and accepting connections");
    attrd_run_mainloop();

  done:
    if (initialized) {
        crm_info("Shutting down attribute manager");

        attrd_election_fini();
        attrd_ipc_fini();
        attrd_lrmd_disconnect();
        attrd_cib_disconnect();
        g_hash_table_destroy(attributes);
    }

    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(error, NULL);
    crm_exit(attrd_exit_status);
}
