/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // EINVAL, ENOTCONN, EPROTO
#include <stdbool.h>
#include <stddef.h>                 // NULL
#include <stdlib.h>                 // free

#include <glib.h>                   // g_list_free_full, GList
#include <libxml/tree.h>            // xmlNode
#include <qb/qblog.h>               // QB_XS

#include <crm/cib/internal.h>       // PCMK__CIB_REQUEST_UPGRADE
#include <crm/cluster/internal.h>   // pcmk__cluster_send_message
#include <crm/common/internal.h>    // pcmk__info, pcmk__xml_free, etc.
#include <crm/common/ipc.h>         // pcmk_ipc_server
#include <crm/common/logging.h>     // CRM_CHECK
#include <crm/common/results.h>     // pcmk_err, pcmk_ok, pcmk_rc*
#include <crm/common/xml.h>         // PCMK_XA_*, PCMK_XE_*
#include <crm/crm.h>                // CRM_FEATURE_SET

#include "pacemaker-based.h"

/* Maximum number of diffs to ignore while waiting for a resync */
#define MAX_DIFF_RETRY 5

bool based_is_primary = false;

xmlNode *the_cib = NULL;

/* Set to 1 when a sync is requested, incremented when a diff is ignored,
 * reset to 0 when a sync is received
 */
static int sync_in_progress = 0;

/*!
 * \internal
 * \brief Process a \c PCMK__CIB_REQUEST_ABS_DELETE
 *
 * \param[in] op            Ignored
 * \param[in] options       Ignored
 * \param[in] section       Ignored
 * \param[in] req           Ignored
 * \param[in] input         Ignored
 * \param[in] existing_cib  Ignored
 * \param[in] result_cib    Ignored
 * \param[in] answer        Ignored
 *
 * \return \c EINVAL
 *
 * \note This is unimplemented and simply returns an error.
 */
int
based_process_abs_delete(const char *op, int options, const char *section,
                         xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                         xmlNode **result_cib, xmlNode **answer)
{
    /* @COMPAT Remove when PCMK__CIB_REQUEST_ABS_DELETE is removed. Note that
     * external clients with Pacemaker versions < 3.0.0 can send it.
     */
    return EINVAL;
}

int
based_process_apply_patch(const char *op, int options, const char *section,
                          xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                          xmlNode **result_cib, xmlNode **answer)
{
    int rc = pcmk_rc_ok;

    if (sync_in_progress > MAX_DIFF_RETRY) {
        /* Don't ignore diffs forever; the last request may have been lost.
         * If the diff fails, we'll ask for another full resync.
         */
        sync_in_progress = 0;
    }

    // The primary instance should never ignore a diff
    if (sync_in_progress && !based_is_primary) {
        int source[] = { 0, 0, 0 };
        int target[] = { 0, 0, 0 };

        pcmk__xml_patchset_versions(input, source, target);

        sync_in_progress++;
        pcmk__notice("Not applying diff %d.%d.%d -> %d.%d.%d (sync in "
                     "progress)",
                     source[0], source[1], source[2],
                     target[0], target[1], target[2]);
        return pcmk_rc_diff_resync;
    }

    rc = cib__process_apply_patch(op, options, section, req, input,
                                  existing_cib, result_cib, answer);
    pcmk__trace("result: %s (%d), %s", pcmk_rc_str(rc), rc,
                (based_is_primary? "primary": "secondary"));

    if ((rc == pcmk_rc_diff_resync) && !based_is_primary) {
        pcmk__xml_free(*result_cib);
        *result_cib = NULL;
        send_sync_request();

    } else if (rc == pcmk_rc_diff_resync) {
        rc = pcmk_rc_diff_failed;
    }

    return rc;
}

int
based_process_commit_transact(const char *op, int options, const char *section,
                              xmlNode *req, xmlNode *input,
                              xmlNode *existing_cib, xmlNode **result_cib,
                              xmlNode **answer)
{
    /* On success, our caller will activate *result_cib locally, trigger a
     * replace notification if appropriate, and sync *result_cib to all nodes.
     * On failure, our caller will free *result_cib.
     */
    int rc = pcmk_rc_ok;
    const char *client_id = pcmk__xe_get(req, PCMK__XA_CIB_CLIENTID);
    const char *origin = pcmk__xe_get(req, PCMK__XA_SRC);
    pcmk__client_t *client = pcmk__find_client_by_id(client_id);

    rc = based_commit_transaction(input, client, origin, result_cib);
    if (rc != pcmk_rc_ok) {
        char *source = based_transaction_source_str(client, origin);

        pcmk__err("Could not commit transaction for %s: %s", source,
                  pcmk_rc_str(rc));
        free(source);
    }

    return rc;
}

int
based_process_is_primary(const char *op, int options, const char *section,
                         xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                         xmlNode **result_cib, xmlNode **answer)
{
    // @COMPAT Pacemaker Remote clients <3.0.0 may send this
    return (based_is_primary? pcmk_rc_ok : EPERM);
}

// @COMPAT: Remove when PCMK__CIB_REQUEST_NOOP is removed
int
based_process_noop(const char *op, int options, const char *section,
                   xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                   xmlNode **result_cib, xmlNode **answer)
{
    *answer = NULL;
    return pcmk_rc_ok;
}

int
based_process_ping(const char *op, int options, const char *section,
                   xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                   xmlNode **result_cib, xmlNode **answer)
{
    /* existing_cib and *result_cib should be identical. In the absence of ACL
     * filtering, they should also match the_cib. However, they may be copies
     * filtered based on the current CIB user's ACLs. In that case, our log
     * messages can use info from the full CIB, and the answer can include the
     * digest of the full CIB. But the answer should hide the version attributes
     * if they're not visible to the CIB user.
     */
    const char *host = pcmk__xe_get(req, PCMK__XA_SRC);
    const char *seq = pcmk__xe_get(req, PCMK__XA_CIB_PING_ID);
    char *digest = pcmk__digest_xml(the_cib, true);

    xmlNode *wrapper = NULL;

    *answer = pcmk__xe_create(NULL, PCMK__XE_PING_RESPONSE);

    pcmk__xe_set(*answer, PCMK_XA_CRM_FEATURE_SET, CRM_FEATURE_SET);
    pcmk__xe_set(*answer, PCMK_XA_DIGEST, digest);
    pcmk__xe_set(*answer, PCMK__XA_CIB_PING_ID, seq);

    wrapper = pcmk__xe_create(*answer, PCMK__XE_CIB_CALLDATA);

    if (*result_cib != NULL) {
        // Use *result_cib so that ACL filtering is applied to the answer
        pcmk__if_tracing(
            {
                /* Append additional detail so the receiver can log the
                 * differences
                 */
                pcmk__xml_copy(wrapper, *result_cib);
            },
            {
                // Always include at least the version details
                const char *name = (const char *) (*result_cib)->name;
                xmlNode *shallow = pcmk__xe_create(wrapper, name);

                pcmk__xe_copy_attrs(shallow, *result_cib, pcmk__xaf_none);
            }
        );
    }

    pcmk__info("Reporting our current digest to %s: %s for %s.%s.%s",
               host, digest,
               pcmk__xe_get(the_cib, PCMK_XA_ADMIN_EPOCH),
               pcmk__xe_get(the_cib, PCMK_XA_EPOCH),
               pcmk__xe_get(the_cib, PCMK_XA_NUM_UPDATES));

    free(digest);

    return pcmk_rc_ok;
}

int
based_process_primary(const char *op, int options, const char *section,
                      xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                      xmlNode **result_cib, xmlNode ** answer)
{
    if (!based_is_primary) {
        pcmk__info("We are now in R/W mode");
        based_is_primary = true;

    } else {
        pcmk__debug("We are still in R/W mode");
    }

    return pcmk_rc_ok;
}

int
based_process_replace(const char *op, int options, const char *section,
                      xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                      xmlNode **result_cib, xmlNode **answer)
{
    int rc = cib__process_replace(op, options, section, req, input,
                                  existing_cib, result_cib, answer);

    if ((rc == pcmk_rc_ok) && pcmk__xe_is(input, PCMK_XE_CIB)) {
        sync_in_progress = 0;
    }
    return rc;
}

int
based_process_schemas(const char *op, int options, const char *section,
                      xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                      xmlNode **result_cib, xmlNode **answer)
{
    xmlNode *wrapper = NULL;
    xmlNode *data = NULL;

    const char *after_ver = NULL;
    GList *schemas = NULL;
    GList *already_included = NULL;

    *answer = pcmk__xe_create(NULL, PCMK__XA_SCHEMAS);

    wrapper = pcmk__xe_first_child(req, PCMK__XE_CIB_CALLDATA, NULL, NULL);
    data = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);
    if (data == NULL) {
        pcmk__warn("No data specified in request");
        return EPROTO;
    }

    after_ver = pcmk__xe_get(data, PCMK_XA_VERSION);
    if (after_ver == NULL) {
        pcmk__warn("No version specified in request");
        return EPROTO;
    }

    /* The client requested all schemas after the latest one we know about, which
     * means the client is fully up-to-date.  Return a properly formatted reply
     * with no schemas.
     */
    if (pcmk__str_eq(after_ver, pcmk__highest_schema_name(), pcmk__str_none)) {
        return pcmk_rc_ok;
    }

    schemas = pcmk__schema_files_later_than(after_ver);

    for (GList *iter = schemas; iter != NULL; iter = iter->next) {
        pcmk__build_schema_xml_node(*answer, iter->data, &already_included);
    }

    g_list_free_full(schemas, free);
    g_list_free_full(already_included, free);
    return pcmk_rc_ok;
}

int
based_process_secondary(const char *op, int options, const char *section,
                        xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                        xmlNode **result_cib, xmlNode **answer)
{
    if (based_is_primary) {
        pcmk__info("We are now in R/O mode");
        based_is_primary = false;

    } else {
        pcmk__debug("We are still in R/O mode");
    }

    return pcmk_rc_ok;
}

int
based_process_shutdown(const char *op, int options, const char *section,
                       xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                       xmlNode **result_cib, xmlNode **answer)
{
    const char *host = pcmk__xe_get(req, PCMK__XA_SRC);

    *answer = NULL;

    if (pcmk__xe_get(req, PCMK__XA_CIB_ISREPLYTO) == NULL) {
        pcmk__info("Peer %s is requesting to shut down", host);
        return pcmk_rc_ok;
    }

    if (!cib_shutdown_flag) {
        pcmk__err("Peer %s mistakenly thinks we wanted to shut down", host);
        return EINVAL;
    }

    pcmk__info("Exiting after %s acknowledged our shutdown request", host);
    based_terminate(CRM_EX_OK);
    return pcmk_rc_ok;
}

int
based_process_sync_to_all(const char *op, int options, const char *section,
                          xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                          xmlNode **result_cib, xmlNode **answer)
{
    return sync_our_cib(req, true);
}

int
based_process_sync_to_one(const char *op, int options, const char *section,
                          xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                          xmlNode **result_cib, xmlNode **answer)
{
    return sync_our_cib(req, false);
}

int
based_process_upgrade(const char *op, int options, const char *section,
                      xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                      xmlNode **result_cib, xmlNode **answer)
{
    int rc = pcmk_rc_ok;

    *answer = NULL;

    if (pcmk__xe_get(req, PCMK__XA_CIB_SCHEMA_MAX) != NULL) {
        /* The originator of an upgrade request sends it to the DC, without
         * PCMK__XA_CIB_SCHEMA_MAX. If an upgrade is needed, the DC
         * re-broadcasts the request with PCMK__XA_CIB_SCHEMA_MAX, and each node
         * performs the upgrade (and notifies its local clients) here.
         */
        return cib__process_upgrade(op, options, section, req, input,
                                    existing_cib, result_cib, answer);

    } else {
        xmlNode *scratch = pcmk__xml_copy(NULL, *result_cib);
        const char *host = pcmk__xe_get(req, PCMK__XA_SRC);
        const char *original_schema = NULL;
        const char *new_schema = NULL;
        const char *client_id = pcmk__xe_get(req, PCMK__XA_CIB_CLIENTID);
        const char *call_opts = pcmk__xe_get(req, PCMK__XA_CIB_CALLOPT);
        const char *call_id = pcmk__xe_get(req, PCMK__XA_CIB_CALLID);

        original_schema = pcmk__xe_get(*result_cib, PCMK_XA_VALIDATE_WITH);
        if (original_schema == NULL) {
            pcmk__info("Rejecting upgrade request from %s: No "
                       PCMK_XA_VALIDATE_WITH,
                       host);
            return pcmk_rc_cib_corrupt;
        }

        rc = pcmk__update_schema(&scratch, NULL, true, true);
        new_schema = pcmk__xe_get(scratch, PCMK_XA_VALIDATE_WITH);

        if (pcmk__cmp_schemas_by_name(new_schema, original_schema) > 0) {
            xmlNode *up = pcmk__xe_create(NULL, __func__);

            rc = pcmk_rc_ok;
            pcmk__notice("Upgrade request from %s verified", host);

            pcmk__xe_set(up, PCMK__XA_T, PCMK__VALUE_CIB);
            pcmk__xe_set(up, PCMK__XA_CIB_OP, PCMK__CIB_REQUEST_UPGRADE);
            pcmk__xe_set(up, PCMK__XA_CIB_SCHEMA_MAX, new_schema);
            pcmk__xe_set(up, PCMK__XA_CIB_DELEGATED_FROM, host);
            pcmk__xe_set(up, PCMK__XA_CIB_CLIENTID, client_id);
            pcmk__xe_set(up, PCMK__XA_CIB_CALLOPT, call_opts);
            pcmk__xe_set(up, PCMK__XA_CIB_CALLID, call_id);

            pcmk__cluster_send_message(NULL, pcmk_ipc_based, up);

            pcmk__xml_free(up);

        } else if (rc == pcmk_rc_ok) {
            rc = pcmk_rc_schema_unchanged;
        }

        if (rc != pcmk_rc_ok) {
            // Notify originating peer so it can notify its local clients
            pcmk__node_status_t *origin = NULL;

            origin = pcmk__search_node_caches(0, host, NULL,
                                              pcmk__node_search_cluster_member);

            pcmk__info("Rejecting upgrade request from %s: %s "
                       QB_XS " rc=%d peer=%s", host, pcmk_rc_str(rc), rc,
                       ((origin != NULL)? origin->name : "lost"));

            if (origin) {
                xmlNode *up = pcmk__xe_create(NULL, __func__);

                pcmk__xe_set(up, PCMK__XA_T, PCMK__VALUE_CIB);
                pcmk__xe_set(up, PCMK__XA_CIB_OP, PCMK__CIB_REQUEST_UPGRADE);
                pcmk__xe_set(up, PCMK__XA_CIB_DELEGATED_FROM, host);
                pcmk__xe_set(up, PCMK__XA_CIB_ISREPLYTO, host);
                pcmk__xe_set(up, PCMK__XA_CIB_CLIENTID, client_id);
                pcmk__xe_set(up, PCMK__XA_CIB_CALLOPT, call_opts);
                pcmk__xe_set(up, PCMK__XA_CIB_CALLID, call_id);
                pcmk__xe_set_int(up, PCMK__XA_CIB_UPGRADE_RC,
                                 pcmk_rc2legacy(rc));
                if (!pcmk__cluster_send_message(origin, pcmk_ipc_based, up)) {
                    pcmk__warn("Could not send CIB upgrade result to %s", host);
                }
                pcmk__xml_free(up);
            }
        }
        pcmk__xml_free(scratch);
    }
    return rc;
}

void
send_sync_request(void)
{
    xmlNode *sync_me = pcmk__xe_create(NULL, "sync-me");
    pcmk__node_status_t *peer = NULL;

    pcmk__info("Requesting re-sync from all peers");
    sync_in_progress = 1;

    pcmk__xe_set(sync_me, PCMK__XA_T, PCMK__VALUE_CIB);
    pcmk__xe_set(sync_me, PCMK__XA_CIB_OP, PCMK__CIB_REQUEST_SYNC_TO_ONE);
    pcmk__xe_set(sync_me, PCMK__XA_CIB_DELEGATED_FROM, OUR_NODENAME);

    pcmk__cluster_send_message(peer, pcmk_ipc_based, sync_me);
    pcmk__xml_free(sync_me);
}

static xmlNode *
cib_msg_copy(xmlNode *msg)
{
    static const char *field_list[] = {
        PCMK__XA_T,
        PCMK__XA_CIB_CLIENTID,
        PCMK__XA_CIB_CALLOPT,
        PCMK__XA_CIB_CALLID,
        PCMK__XA_CIB_OP,
        PCMK__XA_CIB_ISREPLYTO,
        PCMK__XA_CIB_SECTION,
        PCMK__XA_CIB_HOST,
        PCMK__XA_CIB_RC,
        PCMK__XA_CIB_DELEGATED_FROM,
        PCMK__XA_CIB_UPDATE,
        PCMK__XA_CIB_CLIENTNAME,
        PCMK__XA_CIB_USER,
        PCMK__XA_CIB_NOTIFY_TYPE,
        PCMK__XA_CIB_NOTIFY_ACTIVATE,
    };

    xmlNode *copy = pcmk__xe_create(NULL, PCMK__XE_COPY);

    for (int lpc = 0; lpc < PCMK__NELEM(field_list); lpc++) {
        const char *field = field_list[lpc];
        const char *value = pcmk__xe_get(msg, field);

        pcmk__xe_set(copy, field, value);
    }

    return copy;
}

int
sync_our_cib(xmlNode *request, bool all)
{
    int rc = pcmk_rc_ok;
    char *digest = NULL;
    const char *host = pcmk__xe_get(request, PCMK__XA_SRC);
    const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);
    pcmk__node_status_t *peer = NULL;
    xmlNode *replace_request = NULL;
    xmlNode *wrapper = NULL;

    CRM_CHECK(the_cib != NULL, return EINVAL);
    CRM_CHECK(all || (host != NULL), return EINVAL);

    pcmk__debug("Syncing CIB to %s", (all? "all peers" : host));

    replace_request = cib_msg_copy(request);

    if (host != NULL) {
        pcmk__xe_set(replace_request, PCMK__XA_CIB_ISREPLYTO, host);
    }
    if (all) {
        pcmk__xe_remove_attr(replace_request, PCMK__XA_CIB_HOST);
    }

    pcmk__xe_set(replace_request, PCMK__XA_CIB_OP, PCMK__CIB_REQUEST_REPLACE);

    // @TODO Keep for tracing, or drop?
    pcmk__xe_set(replace_request, PCMK__XA_ORIGINAL_CIB_OP, op);

    pcmk__xe_set_bool(replace_request, PCMK__XA_CIB_UPDATE, true);

    pcmk__xe_set(replace_request, PCMK_XA_CRM_FEATURE_SET, CRM_FEATURE_SET);
    digest = pcmk__digest_xml(the_cib, true);
    pcmk__xe_set(replace_request, PCMK_XA_DIGEST, digest);

    wrapper = pcmk__xe_create(replace_request, PCMK__XE_CIB_CALLDATA);
    pcmk__xml_copy(wrapper, the_cib);

    if (!all) {
        peer = pcmk__get_node(0, host, NULL, pcmk__node_search_cluster_member);
    }
    if (!pcmk__cluster_send_message(peer, pcmk_ipc_based, replace_request)) {
        rc = ENOTCONN;
    }
    pcmk__xml_free(replace_request);
    free(digest);
    return rc;
}
