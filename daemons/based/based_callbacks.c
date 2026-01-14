/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // EACCES, ECONNREFUSED
#include <stdbool.h>
#include <stddef.h>                 // NULL, size_t
#include <stdint.h>                 // uint32_t, uint64_t
#include <stdlib.h>                 // free
#include <syslog.h>                 // LOG_INFO, LOG_DEBUG
#include <time.h>                   // time_t

#include <glib.h>                   // gboolean, gpointer, g_*, etc.
#include <libxml/tree.h>            // xmlNode
#include <qb/qblog.h>               // LOG_TRACE

#include <crm/cib.h>                // cib_call_options values
#include <crm/cib/internal.h>       // cib__*
#include <crm/cluster/internal.h>   // pcmk__cluster_send_message
#include <crm/common/internal.h>    // pcmk__s, pcmk__str_eq
#include <crm/common/ipc.h>         // crm_ipc_*, pcmk_ipc_*
#include <crm/common/logging.h>     // CRM_LOG_ASSERT, CRM_CHECK
#include <crm/common/mainloop.h>    // mainloop_*
#include <crm/common/results.h>     // pcmk_rc_*
#include <crm/common/xml.h>         // PCMK_XA_*, PCMK_XE_*
#include <crm/crm.h>                // CRM_OP_*

#include "pacemaker-based.h"

static mainloop_timer_t *digest_timer = NULL;
static long long ping_seq = 0;
static char *ping_digest = NULL;
static bool ping_modified_since = false;

/*!
 * \internal
 * \brief Request CIB digests from all peer nodes
 *
 * This is used as a callback that runs 5 seconds after we modify the CIB on the
 * DC. It sends a ping request to all cluster nodes. They will respond by
 * sending their current digests and version info, which we will validate in
 * process_ping_reply(). If their digest doesn't match, we'll sync our own CIB
 * to them. This helps ensure consistency across the cluster after a CIB update.
 *
 * \param[in] data  Ignored
 *
 * \return \c G_SOURCE_REMOVE (to destroy the timeout)
 *
 * \note It's not clear why we wait 5 seconds rather than sending the ping
 *       request immediately after a performing a modifying op. Perhaps it's to
 *       avoid overwhelming other nodes with ping requests when there are a lot
 *       of modifying requests in a short period. The timer restarts after
 *       every successful modifying op, so we send ping requests **at most**
 *       every 5 seconds. Or perhaps it's a remnant of legacy mode (pre-1.1.12).
 *       In any case, the other nodes shouldn't need time to process the
 *       modifying op before responding to the ping request. The ping request is
 *       sent after the op is sent, so it should also be received after the op
 *       is received.
 */
static gboolean
digest_timer_cb(gpointer data)
{
    xmlNode *ping = NULL;

    if (based_shutting_down()) {
        return G_SOURCE_REMOVE;
    }

    if (!based_get_local_node_dc()) {
        // Only the DC sends a ping
        return G_SOURCE_REMOVE;
    }

    if (++ping_seq < 0) {
        ping_seq = 0;
    }

    g_clear_pointer(&ping_digest, free);
    ping_modified_since = false;

    ping = pcmk__xe_create(NULL, PCMK__XE_PING);
    pcmk__xe_set(ping, PCMK__XA_T, PCMK__VALUE_CIB);
    pcmk__xe_set(ping, PCMK__XA_CIB_OP, CRM_OP_PING);
    pcmk__xe_set_ll(ping, PCMK__XA_CIB_PING_ID, ping_seq);
    pcmk__xe_set(ping, PCMK_XA_CRM_FEATURE_SET, CRM_FEATURE_SET);

    pcmk__trace("Requesting peer digests (%lld)", ping_seq);
    pcmk__cluster_send_message(NULL, pcmk_ipc_based, ping);

    pcmk__xml_free(ping);
    return G_SOURCE_REMOVE;
}

/*!
 * \internal
 * \brief Initialize data structures used for CIB manager callbacks
 */
void
based_callbacks_init(void)
{
    if (digest_timer == NULL) {
        digest_timer = mainloop_timer_add("based_digest_timer", 5000, false,
                                          digest_timer_cb, NULL);
    }
}

/*!
 * \internal
 * \brief Free data structures used for CIB manager callbacks
 */
void
based_callbacks_cleanup(void)
{
    g_clear_pointer(&digest_timer, mainloop_timer_del);
    g_clear_pointer(&ping_digest, free);
}

/*!
 * \internal
 * \brief Create reply XML for a CIB request
 *
 * \param[in] request    CIB request
 * \param[in] rc         Request return code (standard Pacemaker return code)
 * \param[in] call_data  Request output data (may be entire live CIB or result
 *                       CIB in case of error)
 *
 * \return Reply XML (guaranteed not to be \c NULL)
 *
 * \note The caller is responsible for freeing the return value using
 *       \p pcmk__xml_free().
 */
static xmlNode *
create_cib_reply(const xmlNode *request, int rc, xmlNode *call_data)
{
    xmlNode *reply = pcmk__xe_create(NULL, PCMK__XE_CIB_REPLY);

    pcmk__xe_set(reply, PCMK__XA_T, PCMK__VALUE_CIB);

    /* We could simplify by copying all attributes from request. We would just
     * have to ensure that there are never "private" attributes that we want to
     * hide from external clients with notify callbacks.
     */
    pcmk__xe_set(reply, PCMK__XA_CIB_OP,
                 pcmk__xe_get(request, PCMK__XA_CIB_OP));

    pcmk__xe_set(reply, PCMK__XA_CIB_CALLID,
                 pcmk__xe_get(request, PCMK__XA_CIB_CALLID));

    pcmk__xe_set(reply, PCMK__XA_CIB_CLIENTID,
                 pcmk__xe_get(request, PCMK__XA_CIB_CLIENTID));

    pcmk__xe_set(reply, PCMK__XA_CIB_CALLOPT,
                 pcmk__xe_get(request, PCMK__XA_CIB_CALLOPT));

    pcmk__xe_set_int(reply, PCMK__XA_CIB_RC, pcmk_rc2legacy(rc));
    cib__set_calldata(reply, call_data);

    crm_log_xml_explicit(reply, "cib:reply");
    return reply;
}

static void
do_local_notify(const xmlNode *xml, const char *client_id, bool sync_reply,
                bool from_peer)
{
    int call_id = 0;
    int rc = pcmk_rc_ok;
    pcmk__client_t *client = NULL;
    uint32_t flags = crm_ipc_server_event;
    const char *client_type = NULL;
    const char *client_name = NULL;
    const char *client_desc = "";
    const char *sync_s = (sync_reply? "synchronously" : "asynchronously");

    CRM_CHECK((xml != NULL) && (client_id != NULL), return);

    if (from_peer) {
        client_desc = " (originator of delegated_request)";
    }

    pcmk__trace("Performing local %s notification for %s", sync_s, client_id);

    pcmk__xe_get_int(xml, PCMK__XA_CIB_CALLID, &call_id);

    client = pcmk__find_client_by_id(client_id);
    if (client == NULL) {
        pcmk__debug("Could not notify client %s%s %s of call %d result: client "
                    "no longer exists", client_id, client_desc, sync_s,
                    call_id);
        return;
    }

    client_type = pcmk__client_type_str(PCMK__CLIENT_TYPE(client));
    client_name = pcmk__client_name(client);

    if (sync_reply) {
        flags = crm_ipc_flags_none;
        if (client->ipcs != NULL) {
            call_id = client->request_id;
            client->request_id = 0;
        }
    }

    switch (PCMK__CLIENT_TYPE(client)) {
        case pcmk__client_ipc:
            rc = pcmk__ipc_send_xml(client, call_id, xml, flags);
            break;
        case pcmk__client_tls:
        case pcmk__client_tcp:
            rc = pcmk__remote_send_xml(client->remote, xml);
            break;
        default:
            rc = EPROTONOSUPPORT;
            break;
    }

    if (rc == pcmk_rc_ok) {
        pcmk__trace("Notified %s client %s%s %s of call %d result",
                    client_type, client_name, client_desc, sync_s, call_id);
    } else {
        pcmk__warn("Could not notify %s client %s%s %s of call %d result: %s",
                   client_type, client_name, client_desc, sync_s, call_id,
                   pcmk_rc_str(rc));
    }
}

/*!
 * \internal
 * \brief Process a reply to a \c CRM_OP_PING request
 *
 * See \c digest_timer_cb() for details on how the ping process works, and see
 * \c based_process_ping() for the construction of the ping reply.
 *
 * We ignore the reply if we are no longer the DC, if the reply is malformed or
 * received out of sequence, or if we may have modified the CIB since the last
 * time we sent a ping request.
 *
 * Otherwise, we compare the CIB digest received in the reply against the digest
 * of the local CIB. If the digests don't match, we sync our CIB to the node
 * that sent the reply. This helps to ensure that all other nodes' views of the
 * CIB eventually match the DC's view of the CIB.
 *
 * \param[in] reply  Ping reply
 */
static void
process_ping_reply(const xmlNode *reply)
{
    const char *host = pcmk__xe_get(reply, PCMK__XA_SRC);

    xmlNode *pong = cib__get_calldata(reply);
    long long seq = 0;
    const char *digest = pcmk__xe_get(pong, PCMK_XA_DIGEST);

    xmlNode *remote_versions = cib__get_calldata(pong);

    int rc = pcmk__xe_get_ll(pong, PCMK__XA_CIB_PING_ID, &seq);

    if (rc != pcmk_rc_ok) {
        pcmk__debug("Ignoring ping reply with unset or invalid "
                    PCMK__XA_CIB_PING_ID ": %s", pcmk_rc_str(rc));
        return;
    }

    if (!based_get_local_node_dc()) {
        pcmk__trace("Ignoring ping reply %lld from %s because we are no longer "
                    "DC", seq, host);
        return;
    }

    if (digest == NULL) {
        pcmk__trace("Ignoring ping reply %lld from %s with no digest", seq,
                    host);
        return;
    }

    if (seq != ping_seq) {
        pcmk__trace("Ignoring out-of-sequence ping reply %lld from %s", seq,
                    host);
        return;
    }

    if (ping_modified_since) {
        pcmk__trace("Ignoring ping reply %lld from %s: CIB updated since", seq,
                    host);
        return;
    }

    if (ping_digest == NULL) {
        ping_digest = pcmk__digest_xml(based_cib, true);
    }

    pcmk__trace("Processing ping reply %lld from %s (%s)", seq, host, digest);

    if (pcmk__str_eq(ping_digest, digest, pcmk__str_casei)) {
        return;
    }

    pcmk__notice("Local CIB %s.%s.%s.%s differs from %s: %s.%s.%s.%s",
                 pcmk__xe_get(based_cib, PCMK_XA_ADMIN_EPOCH),
                 pcmk__xe_get(based_cib, PCMK_XA_EPOCH),
                 pcmk__xe_get(based_cib, PCMK_XA_NUM_UPDATES),
                 ping_digest, host,
                 pcmk__xe_get(remote_versions, PCMK_XA_ADMIN_EPOCH),
                 pcmk__xe_get(remote_versions, PCMK_XA_EPOCH),
                 pcmk__xe_get(remote_versions, PCMK_XA_NUM_UPDATES), digest);

    sync_our_cib(reply, false);
}

static void
log_local_options(const pcmk__client_t *client, const char *host,
                  const char *op)
{
    if (based_stand_alone()) {
        pcmk__trace("Processing %s op from client %s (stand-alone)", op,
                    pcmk__client_name(client));

    } else {
        pcmk__trace("Processing %saddressed %s op from client %s",
                    ((host != NULL)? "locally " : "un"), op,
                    pcmk__client_name(client));
    }
}

static bool
parse_peer_options(const cib__operation_t *operation, pcmk__request_t *request,
                   bool *local_notify, bool *needs_reply, bool *process)
{
    /* Don't send replies for modifying ops because they already get forwarded
     * to all nodes. Also don't send a reply if the client specifically told us
     * not to.
     */
    const bool can_reply = !operation->modifies_cib;

    const char *host = pcmk__xe_get(request->xml, PCMK__XA_CIB_HOST);
    const char *delegated = pcmk__xe_get(request->xml,
                                         PCMK__XA_CIB_DELEGATED_FROM);
    const char *originator = pcmk__xe_get(request->xml, PCMK__XA_SRC);
    const char *reply_to = pcmk__xe_get(request->xml, PCMK__XA_CIB_ISREPLYTO);

    bool is_reply = pcmk__str_eq(reply_to, OUR_NODENAME, pcmk__str_casei);

    if (originator == NULL) { // Shouldn't be possible
        originator = "peer";
    }

    if (is_reply && pcmk__str_eq(request->op, CRM_OP_PING, pcmk__str_none)) {
        process_ping_reply(request->xml);
        return false;
    }

    if (pcmk__str_eq(request->op, PCMK__CIB_REQUEST_SHUTDOWN, pcmk__str_none)) {
        /* @COMPAT We stopped sending shutdown requests as of 3.0.2. During a
         * rolling upgrade, the requesting node expects a reply. We might as
         * well continue sending one until we no longer support rolling upgrades
         * from versions earlier than 3.0.2. (If the requesting node doesn't
         * receive a reply, it simply exits with CRM_EX_ERROR after 10 seconds.)
         */
        *needs_reply = true;
        return true;
    }

    if (is_reply
        && pcmk__str_eq(request->op, PCMK__CIB_REQUEST_SYNC, pcmk__str_none)) {

        pcmk__trace("Will notify local clients for %s reply from %s",
                    request->op, originator);
        *process = false;
        *local_notify = true;
        return true;
    }

    if ((reply_to != NULL)
        && pcmk__str_eq(request->op, PCMK__CIB_REQUEST_REPLACE,
                        pcmk__str_none)) {

        // sync_our_cib() sets PCMK__XA_CIB_ISREPLYTO
        delegated = reply_to;

        /* @FIXME can_reply is always false here because cib__op_replace has
         * modifies_cib=true. Should we be sending a reply here?
         */
        *needs_reply = can_reply;

    } else if (pcmk__str_eq(request->op, PCMK__CIB_REQUEST_UPGRADE,
                            pcmk__str_none)) {
        /* Only the DC (node with the oldest software) should process
         * this operation if PCMK__XA_CIB_SCHEMA_MAX is unset.
         *
         * If the DC is happy it will then send out another
         * PCMK__CIB_REQUEST_UPGRADE which will tell all nodes to do the actual
         * upgrade.
         *
         * Except this time PCMK__XA_CIB_SCHEMA_MAX will be set which puts a
         * limit on how far newer nodes will go
         */
        const char *max = pcmk__xe_get(request->xml, PCMK__XA_CIB_SCHEMA_MAX);
        const char *upgrade_rc = pcmk__xe_get(request->xml,
                                              PCMK__XA_CIB_UPGRADE_RC);

        pcmk__trace("Parsing upgrade %s for %s with max=%s and upgrade_rc=%s",
                    (is_reply? "reply" : "request"),
                    (based_get_local_node_dc()? "DC" : "non-DC node"),
                    pcmk__s(max, "none"), pcmk__s(upgrade_rc, "none"));

        if (upgrade_rc != NULL) {
            // Our upgrade request was rejected by DC, notify clients of result
            pcmk__assert(is_reply);
            pcmk__xe_set(request->xml, PCMK__XA_CIB_RC, upgrade_rc);

            pcmk__trace("Will notify local clients for %s reply from %s",
                        request->op, originator);
            *process = false;
            *local_notify = true;
            return true;
        }

        if ((max == NULL) && !based_get_local_node_dc()) {
            // Ignore broadcast client requests when we're not the DC
            return false;
        }
    }

    *local_notify = pcmk__str_eq(delegated, OUR_NODENAME, pcmk__str_casei);

    if (pcmk__str_eq(host, OUR_NODENAME, pcmk__str_casei)) {
        pcmk__trace("Processing %s request sent to us from %s", request->op,
                    originator);
        *needs_reply = can_reply;
        return true;
    }

    if (host != NULL) {
        pcmk__trace("Ignoring %s request intended for CIB manager on %s",
                    request->op, host);
        return false;
    }

    if (!is_reply && pcmk__str_eq(request->op, CRM_OP_PING, pcmk__str_none)) {
        *needs_reply = can_reply;
        return true;
    }

    pcmk__trace("Processing %s request broadcast by %s call %s on %s "
                "(local clients will%s be notified)", request->op,
                pcmk__s(pcmk__xe_get(request->xml, PCMK__XA_CIB_CLIENTNAME),
                        "client"),
                pcmk__s(pcmk__xe_get(request->xml, PCMK__XA_CIB_CALLID),
                        "without ID"),
                originator, (*local_notify? "" : "not"));
    return true;
}

/*!
 * \internal
 * \brief Forward a CIB request to the appropriate target host(s)
 *
 * \param[in] request  CIB request to forward
 *
 * \note \p request is modified within the function, but its initial state is
 *       restored before returning. This probably doesn't matter, however.
 */
static void
forward_request(pcmk__request_t *request)
{
    const char *host = pcmk__xe_get(request->xml, PCMK__XA_CIB_HOST);
    pcmk__node_status_t *peer = NULL;

    if (host != NULL) {
        peer = pcmk__get_node(0, host, NULL, pcmk__node_search_cluster_member);
    }

    // Set PCMK__XA_CIB_DELEGATED_FROM only temporarily
    pcmk__xe_set(request->xml, PCMK__XA_CIB_DELEGATED_FROM, OUR_NODENAME);
    pcmk__cluster_send_message(peer, pcmk_ipc_based, request->xml);
    pcmk__xe_remove_attr(request->xml, PCMK__XA_CIB_DELEGATED_FROM);
}

static int
based_perform_op_rw(pcmk__request_t *request, const cib__operation_t *operation,
                    cib__op_fn_t op_function, xmlNode **output)
{
    const char *feature_set = pcmk__xe_get(based_cib,
                                           PCMK_XA_CRM_FEATURE_SET);
    xmlNode *result_cib = based_cib;
    xmlNode *cib_diff = NULL;

    const char *originator = pcmk__xe_get(request->xml, PCMK__XA_SRC);
    bool config_changed = false;
    int rc = pcmk_rc_ok;

    /* result_cib must not be modified after cib__perform_op_rw() returns.
     *
     * It's not important whether the client variant is cib_native or
     * cib_remote.
     */
    rc = cib__perform_op_rw(cib_undefined, op_function, request->xml,
                            &config_changed, &result_cib, &cib_diff, output);

    /* On validation error, include the schema-violating result CIB in any reply
     * or notification that we will send.
     */
    if (rc == pcmk_rc_schema_validation) {
        pcmk__assert((result_cib != based_cib) && (*output == NULL));
        *output = result_cib;
        goto done;
    }

    // Discard result for failure or dry run
    if ((rc != pcmk_rc_ok)
        || pcmk__any_flags_set(request->call_options, cib_dryrun)) {

        if (result_cib != based_cib) {
            pcmk__xml_free(result_cib);
        }

        goto done;
    }

    if (result_cib != based_cib) {
        /* Write to disk on config change or successful upgrade (which may
         * update PCMK_XA_VALIDATE_WITH without changing the configuration),
         * unless the request is part of a transaction. Since a transaction
         * is atomic, intermediate results must not be written to disk.
         */
        const bool to_disk = !pcmk__is_set(request->call_options,
                                           cib_transaction)
                             && (config_changed
                                 || (operation->type == cib__op_upgrade));

        rc = based_activate_cib(result_cib, to_disk, request->op);
    }

    /* @COMPAT Nodes older than feature set 3.19.0 don't support transactions.
     * In a mixed-version cluster with nodes <3.19.0, we must sync the updated
     * CIB, so that the older nodes receive the changes. Any node that has
     * already applied the transaction will ignore the synced CIB.
     *
     * To ensure the updated CIB is synced from only one node, we sync it from
     * the originator.
     */
    if ((operation->type == cib__op_commit_transact)
        && pcmk__str_eq(originator, OUR_NODENAME, pcmk__str_casei)
        && (pcmk__compare_versions(feature_set, "3.19.0") < 0)) {

        sync_our_cib(request->xml, true);
    }

    if (cib_diff != NULL) {
        ping_modified_since = true;
    }

    mainloop_timer_start(digest_timer);

done:
    if (!pcmk__any_flags_set(request->call_options,
                             cib_dryrun|cib_inhibit_notify|cib_transaction)) {

        based_diff_notify(request->xml, rc, cib_diff);
    }

    pcmk__xml_free(cib_diff);
    return rc;
}

/*!
 * \internal
 * \brief Log the result of processing a CIB request locally
 *
 * \param[in] request    Request XML
 * \param[in] operation  Operation info
 * \param[in] rc         Return code from processing the request
 * \param[in] elapsed    How long processing took in seconds
 */
static void
log_op_result(const xmlNode *request, const cib__operation_t *operation, int rc,
              double elapsed)
{
    int level = LOG_INFO;

    const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);
    const char *section = pcmk__xe_get(request, PCMK__XA_CIB_SECTION);
    const char *originator = pcmk__xe_get(request, PCMK__XA_SRC);
    const char *client_name = pcmk__xe_get(request, PCMK__XA_CIB_CLIENTNAME);
    const char *call_id = pcmk__xe_get(request, PCMK__XA_CIB_CALLID);

    int admin_epoch = 0;
    int epoch = 0;
    int num_updates = 0;

    if (!operation->modifies_cib) {
        level = LOG_TRACE;

    } else if (rc != pcmk_rc_ok) {
        level = LOG_WARNING;
    }

    section = pcmk__s(section, "'all'");
    originator = pcmk__s(originator, "local");
    client_name = pcmk__s(client_name, "client");

    pcmk__xe_get_int(based_cib, PCMK_XA_ADMIN_EPOCH, &admin_epoch);
    pcmk__xe_get_int(based_cib, PCMK_XA_EPOCH, &epoch);
    pcmk__xe_get_int(based_cib, PCMK_XA_NUM_UPDATES, &num_updates);

    do_crm_log(level,
               "Completed %s operation for section %s: %s (rc=%d, "
               "origin=%s/%s/%s, version=%d.%d.%d)",
               op, section, pcmk_rc_str(rc), rc,
               originator, client_name, call_id,
               admin_epoch, epoch, num_updates);

    if (elapsed > 3) {
        pcmk__trace("%s operation took %.2fs to complete", op, elapsed);
        crm_write_blackbox(0, NULL);
    }
}

static void
send_peer_reply(xmlNode *msg, const char *originator)
{
    const pcmk__node_status_t *node = NULL;

    if ((msg == NULL) || (originator == NULL)) {
        return;
    }

    // Send reply via cluster to originating node
    node = pcmk__get_node(0, originator, NULL,
                          pcmk__node_search_cluster_member);

    pcmk__trace("Sending request result to %s only", originator);
    pcmk__xe_set(msg, PCMK__XA_CIB_ISREPLYTO, originator);
    pcmk__cluster_send_message(node, pcmk_ipc_based, msg);
}

/*!
 * \internal
 * \brief Handle a request from a CIB manager client or peer
 *
 * \param[in,out] request  CIB manager request
 *
 * \return Standard Pacemaker return code
 */
int
based_handle_request(pcmk__request_t *request)
{
    // @TODO: Break into multiple smaller functions
    bool process = true;        // Whether to process request locally now
    bool needs_reply = false;   // Whether to build a reply
    bool local_notify = false;  // Whether to notify (local) requester

    int rc = pcmk_rc_ok;
    const char *originator = pcmk__xe_get(request->xml, PCMK__XA_SRC);
    const char *host = pcmk__xe_get(request->xml, PCMK__XA_CIB_HOST);
    const char *call_id = pcmk__xe_get(request->xml, PCMK__XA_CIB_CALLID);
    const char *reply_to = pcmk__xe_get(request->xml, PCMK__XA_CIB_ISREPLYTO);

    /* These are the client ID and name on the originator node, so we need to
     * get these from the request XML. request->ipc_client is NULL if this
     * request came from the cluster.
     */
    const char *client_id = pcmk__xe_get(request->xml, PCMK__XA_CIB_CLIENTID);
    const char *client_name = pcmk__s(pcmk__xe_get(request->xml,
                                                   PCMK__XA_CIB_CLIENTNAME),
                                      "client");

    const cib__operation_t *operation = NULL;
    cib__op_fn_t op_function = NULL;

    xmlNode *output = NULL;
    time_t start_time = 0;

    if (based_shutting_down()) {
        pcmk__info("Ignoring pending CIB request during shutdown");
        pcmk__reset_request(request);
        return ENOTCONN;
    }

    if (pcmk__str_empty(host)) {
        host = NULL;
    }

    if (request->ipc_client == NULL) {
        pcmk__trace("Processing peer %s operation from %s/%s on %s intended "
                    "for %s (reply=%s)", request->op, client_name, call_id,
                    originator, pcmk__s(host, "all"), reply_to);
    } else {
        pcmk__xe_set(request->xml, PCMK__XA_SRC, OUR_NODENAME);
        pcmk__trace("Processing local %s operation from %s/%s intended for %s",
                    request->op, client_name, call_id, pcmk__s(host, "all"));
    }

    rc = cib__get_operation(request->op, &operation);
    if (rc != pcmk_rc_ok) {
        pcmk__err("Pre-processing of command failed: %s", pcmk_rc_str(rc));
        pcmk__reset_request(request);
        return rc;
    }

    op_function = based_get_op_function(operation);
    if (op_function == NULL) {
        pcmk__err("Operation %s not supported by CIB manager", request->op);
        pcmk__reset_request(request);
        return EOPNOTSUPP;
    }

    if (pcmk__is_set(request->call_options, cib_transaction)) {
        /* All requests in a transaction are processed locally against a working
         * CIB copy, and we don't notify for individual requests because the
         * entire transaction is atomic.
         */
        pcmk__trace("Processing %s op from %s/%s on %s locally because it's "
                    "part of a transaction", request->op, client_name, call_id,
                    pcmk__xe_get(request->xml, PCMK__XA_SRC));

    } else if (request->ipc_client != NULL) {
        // Forward modifying and non-local requests via cluster
        if (!based_stand_alone()
            && (operation->modifies_cib
                || !pcmk__str_eq(host, OUR_NODENAME,
                                 pcmk__str_casei|pcmk__str_null_matches))) {

            forward_request(request);
            pcmk__reset_request(request);
            return pcmk_rc_ok;
        }

        // Process locally and notify local client; no peer to reply to
        local_notify = true;

        log_local_options(request->ipc_client, host, request->op);

    } else if (!parse_peer_options(operation, request, &local_notify,
                                   &needs_reply, &process)) {
        pcmk__reset_request(request);
        return pcmk_rc_ok;
    }

    if (cib_status != pcmk_rc_ok) {
        rc = cib_status;
        pcmk__err("Ignoring request because cluster configuration is invalid "
                  "(please repair and restart): %s", pcmk_rc_str(rc));
        output = based_cib;
        goto done;
    }

    if (!process) {
        goto done;
    }

    start_time = time(NULL);

    if (!operation->modifies_cib) {
        rc = cib__perform_op_ro(op_function, request->xml, &based_cib, &output);

    } else {
        rc = based_perform_op_rw(request, operation, op_function, &output);
    }

    log_op_result(request->xml, operation, rc, difftime(time(NULL), start_time));

done:
    if (needs_reply) {
        xmlNode *reply = create_cib_reply(request->xml, rc, output);

        send_peer_reply(reply, originator);
        pcmk__xml_free(reply);
    }

    if (local_notify && (client_id != NULL)) {
        do_local_notify((process? reply : request->xml), client_id,
                        pcmk__is_set(request->call_options, cib_sync_call),
                        (request->ipc_client == NULL));
    }

    if ((output != NULL) && (output->doc != based_cib->doc)) {
        pcmk__xml_free(output);
    }

    pcmk__xml_free(reply);
    pcmk__reset_request(request);
    return rc;
}
