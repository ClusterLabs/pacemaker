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
#include <crm/common/output_internal.h>
#include <crm/common/xml.h>
#include <crm/cluster/internal.h>

#include <crm/common/attrd_internal.h>
#include "pacemaker-attrd.h"

#define SUMMARY "daemon for managing Pacemaker node attributes"

static pcmk__output_t *out = NULL;

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

lrmd_t *the_lrmd = NULL;
crm_cluster_t *attrd_cluster = NULL;
crm_trigger_t *attrd_config_read = NULL;
crm_exit_t attrd_exit_status = CRM_EX_OK;

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

static bool
ipc_already_running(void)
{
    pcmk_ipc_api_t *old_instance = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk_new_ipc_api(&old_instance, pcmk_ipc_attrd);
    if (rc != pcmk_rc_ok) {
        return false;
    }

    rc = pcmk_connect_ipc(old_instance, pcmk_ipc_dispatch_sync);
    if (rc != pcmk_rc_ok) {
        pcmk_free_ipc_api(old_instance);
        return false;
    }

    pcmk_disconnect_ipc(old_instance);
    pcmk_free_ipc_api(old_instance);
    return true;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    return pcmk__build_arg_context(args, "text (default), xml", group, NULL);
}

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;

    GError *error = NULL;
    bool initialized = false;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, NULL);
    GOptionContext *context = build_arg_context(args, &output_group);

    attrd_init_mainloop();
    crm_log_preinit(NULL, argc, argv);
    mainloop_add_signal(SIGTERM, attrd_shutdown);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        attrd_exit_status = CRM_EX_USAGE;
        goto done;
    }

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if ((rc != pcmk_rc_ok) || (out == NULL)) {
        attrd_exit_status = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, attrd_exit_status,
                    "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    initialized = true;

    crm_log_init(T_ATTRD, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    crm_notice("Starting Pacemaker node attribute manager");

    if (ipc_already_running()) {
        crm_err("pacemaker-attrd is already active, aborting startup");
        crm_exit(CRM_EX_OK);
    }

    attributes = pcmk__strkey_table(NULL, attrd_free_attribute);

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

    attrd_init_ipc();
    crm_notice("Pacemaker node attribute manager successfully started and accepting connections");
    attrd_run_mainloop();

  done:
    if (initialized) {
        crm_info("Shutting down attribute manager");

        attrd_election_fini();
        attrd_ipc_fini();
        attrd_lrmd_disconnect();
        attrd_cib_disconnect();
        attrd_free_waitlist();
        g_hash_table_destroy(attributes);
    }

    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(error, out);

    if (out != NULL) {
        out->finish(out, attrd_exit_status, true, NULL);
        pcmk__output_free(out);
    }
    crm_exit(attrd_exit_status);
}
