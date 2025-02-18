/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include <sys/param.h>
#include <sys/types.h>

#include <glib.h>
#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>

#include <crm/common/xml.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/xml_internal.h>
#include <crm/cluster/internal.h>

#include <pacemaker-based.h>

/* Maximum number of diffs to ignore while waiting for a resync */
#define MAX_DIFF_RETRY 5

bool based_is_primary = false;

xmlNode *the_cib = NULL;

int
cib_process_shutdown_req(const char *op, int options, const char *section, xmlNode * req,
                         xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                         xmlNode ** answer)
{
    const char *host = crm_element_value(req, PCMK__XA_SRC);

    *answer = NULL;

    if (crm_element_value(req, PCMK__XA_CIB_ISREPLYTO) == NULL) {
        crm_info("Peer %s is requesting to shut down", host);
        return pcmk_ok;
    }

    if (cib_shutdown_flag == FALSE) {
        crm_err("Peer %s mistakenly thinks we wanted to shut down", host);
        return -EINVAL;
    }

    crm_info("Exiting after %s acknowledged our shutdown request", host);
    terminate_cib(CRM_EX_OK);
    return pcmk_ok;
}

// @COMPAT: Remove when PCMK__CIB_REQUEST_NOOP is removed
int
cib_process_noop(const char *op, int options, const char *section, xmlNode *req,
                 xmlNode *input, xmlNode *existing_cib, xmlNode **result_cib,
                 xmlNode **answer)
{
    crm_trace("Processing \"%s\" event", op);
    *answer = NULL;
    return pcmk_ok;
}

int
cib_process_readwrite(const char *op, int options, const char *section, xmlNode * req,
                      xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                      xmlNode ** answer)
{
    int result = pcmk_ok;

    crm_trace("Processing \"%s\" event", op);

    // @COMPAT Pacemaker Remote clients <3.0.0 may send this
    if (pcmk__str_eq(op, PCMK__CIB_REQUEST_IS_PRIMARY, pcmk__str_none)) {
        if (based_is_primary) {
            result = pcmk_ok;
        } else {
            result = -EPERM;
        }
        return result;
    }

    if (pcmk__str_eq(op, PCMK__CIB_REQUEST_PRIMARY, pcmk__str_none)) {
        if (!based_is_primary) {
            crm_info("We are now in R/W mode");
            based_is_primary = true;
        } else {
            crm_debug("We are still in R/W mode");
        }

    } else if (based_is_primary) {
        crm_info("We are now in R/O mode");
        based_is_primary = false;
    }

    return result;
}

/* Set to 1 when a sync is requested, incremented when a diff is ignored,
 * reset to 0 when a sync is received
 */
static int sync_in_progress = 0;

void
send_sync_request(const char *host)
{
    xmlNode *sync_me = pcmk__xe_create(NULL, "sync-me");
    pcmk__node_status_t *peer = NULL;

    crm_info("Requesting re-sync from %s", (host? host : "all peers"));
    sync_in_progress = 1;

    crm_xml_add(sync_me, PCMK__XA_T, PCMK__VALUE_CIB);
    crm_xml_add(sync_me, PCMK__XA_CIB_OP, PCMK__CIB_REQUEST_SYNC_TO_ONE);
    crm_xml_add(sync_me, PCMK__XA_CIB_DELEGATED_FROM, OUR_NODENAME);

    if (host != NULL) {
        peer = pcmk__get_node(0, host, NULL, pcmk__node_search_cluster_member);
    }
    pcmk__cluster_send_message(peer, pcmk_ipc_based, sync_me);
    pcmk__xml_free(sync_me);
}

int
cib_process_ping(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                 xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    const char *host = crm_element_value(req, PCMK__XA_SRC);
    const char *seq = crm_element_value(req, PCMK__XA_CIB_PING_ID);
    char *digest = pcmk__digest_xml(the_cib, true);

    xmlNode *wrapper = NULL;

    crm_trace("Processing \"%s\" event %s from %s", op, seq, host);
    *answer = pcmk__xe_create(NULL, PCMK__XE_PING_RESPONSE);

    crm_xml_add(*answer, PCMK_XA_CRM_FEATURE_SET, CRM_FEATURE_SET);
    crm_xml_add(*answer, PCMK__XA_DIGEST, digest);
    crm_xml_add(*answer, PCMK__XA_CIB_PING_ID, seq);

    wrapper = pcmk__xe_create(*answer, PCMK__XE_CIB_CALLDATA);

    if (the_cib != NULL) {
        pcmk__if_tracing(
            {
                /* Append additional detail so the receiver can log the
                 * differences
                 */
                pcmk__xml_copy(wrapper, the_cib);
            },
            {
                // Always include at least the version details
                const char *name = (const char *) the_cib->name;
                xmlNode *shallow = pcmk__xe_create(wrapper, name);

                pcmk__xe_copy_attrs(shallow, the_cib, pcmk__xaf_none);
            }
        );
    }

    crm_info("Reporting our current digest to %s: %s for %s.%s.%s",
             host, digest,
             crm_element_value(existing_cib, PCMK_XA_ADMIN_EPOCH),
             crm_element_value(existing_cib, PCMK_XA_EPOCH),
             crm_element_value(existing_cib, PCMK_XA_NUM_UPDATES));

    free(digest);

    return pcmk_ok;
}

int
cib_process_sync(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                 xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    return sync_our_cib(req, TRUE);
}

int
cib_process_upgrade_server(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                           xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    int rc = pcmk_ok;

    *answer = NULL;

    if (crm_element_value(req, PCMK__XA_CIB_SCHEMA_MAX) != NULL) {
        /* The originator of an upgrade request sends it to the DC, without
         * PCMK__XA_CIB_SCHEMA_MAX. If an upgrade is needed, the DC
         * re-broadcasts the request with PCMK__XA_CIB_SCHEMA_MAX, and each node
         * performs the upgrade (and notifies its local clients) here.
         */
        return cib_process_upgrade(
            op, options, section, req, input, existing_cib, result_cib, answer);

    } else {
        xmlNode *scratch = pcmk__xml_copy(NULL, existing_cib);
        const char *host = crm_element_value(req, PCMK__XA_SRC);
        const char *original_schema = NULL;
        const char *new_schema = NULL;
        const char *client_id = crm_element_value(req, PCMK__XA_CIB_CLIENTID);
        const char *call_opts = crm_element_value(req, PCMK__XA_CIB_CALLOPT);
        const char *call_id = crm_element_value(req, PCMK__XA_CIB_CALLID);

        crm_trace("Processing \"%s\" event", op);
        original_schema = crm_element_value(existing_cib,
                                            PCMK_XA_VALIDATE_WITH);
        if (original_schema == NULL) {
            crm_info("Rejecting upgrade request from %s: No "
                     PCMK_XA_VALIDATE_WITH, host);
            return -pcmk_err_cib_corrupt;
        }

        rc = pcmk__update_schema(&scratch, NULL, true, true);
        rc = pcmk_rc2legacy(rc);
        new_schema = crm_element_value(scratch, PCMK_XA_VALIDATE_WITH);

        if (pcmk__cmp_schemas_by_name(new_schema, original_schema) > 0) {
            xmlNode *up = pcmk__xe_create(NULL, __func__);

            rc = pcmk_ok;
            crm_notice("Upgrade request from %s verified", host);

            crm_xml_add(up, PCMK__XA_T, PCMK__VALUE_CIB);
            crm_xml_add(up, PCMK__XA_CIB_OP, PCMK__CIB_REQUEST_UPGRADE);
            crm_xml_add(up, PCMK__XA_CIB_SCHEMA_MAX, new_schema);
            crm_xml_add(up, PCMK__XA_CIB_DELEGATED_FROM, host);
            crm_xml_add(up, PCMK__XA_CIB_CLIENTID, client_id);
            crm_xml_add(up, PCMK__XA_CIB_CALLOPT, call_opts);
            crm_xml_add(up, PCMK__XA_CIB_CALLID, call_id);

            pcmk__cluster_send_message(NULL, pcmk_ipc_based, up);

            pcmk__xml_free(up);

        } else if(rc == pcmk_ok) {
            rc = -pcmk_err_schema_unchanged;
        }

        if (rc != pcmk_ok) {
            // Notify originating peer so it can notify its local clients
            pcmk__node_status_t *origin = NULL;

            origin = pcmk__search_node_caches(0, host, NULL,
                                              pcmk__node_search_cluster_member);

            crm_info("Rejecting upgrade request from %s: %s "
                     QB_XS " rc=%d peer=%s", host, pcmk_strerror(rc), rc,
                     (origin? origin->name : "lost"));

            if (origin) {
                xmlNode *up = pcmk__xe_create(NULL, __func__);

                crm_xml_add(up, PCMK__XA_T, PCMK__VALUE_CIB);
                crm_xml_add(up, PCMK__XA_CIB_OP, PCMK__CIB_REQUEST_UPGRADE);
                crm_xml_add(up, PCMK__XA_CIB_DELEGATED_FROM, host);
                crm_xml_add(up, PCMK__XA_CIB_ISREPLYTO, host);
                crm_xml_add(up, PCMK__XA_CIB_CLIENTID, client_id);
                crm_xml_add(up, PCMK__XA_CIB_CALLOPT, call_opts);
                crm_xml_add(up, PCMK__XA_CIB_CALLID, call_id);
                crm_xml_add_int(up, PCMK__XA_CIB_UPGRADE_RC, rc);
                if (!pcmk__cluster_send_message(origin, pcmk_ipc_based, up)) {
                    crm_warn("Could not send CIB upgrade result to %s", host);
                }
                pcmk__xml_free(up);
            }
        }
        pcmk__xml_free(scratch);
    }
    return rc;
}

int
cib_process_sync_one(const char *op, int options, const char *section, xmlNode * req,
                     xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                     xmlNode ** answer)
{
    return sync_our_cib(req, FALSE);
}

int
cib_server_process_diff(const char *op, int options, const char *section, xmlNode * req,
                        xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                        xmlNode ** answer)
{
    int rc = pcmk_ok;

    if (sync_in_progress > MAX_DIFF_RETRY) {
        /* Don't ignore diffs forever; the last request may have been lost.
         * If the diff fails, we'll ask for another full resync.
         */
        sync_in_progress = 0;
    }

    // The primary instance should never ignore a diff
    if (sync_in_progress && !based_is_primary) {
        int diff_add_updates = 0;
        int diff_add_epoch = 0;
        int diff_add_admin_epoch = 0;

        int diff_del_updates = 0;
        int diff_del_epoch = 0;
        int diff_del_admin_epoch = 0;

        cib_diff_version_details(input,
                                 &diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates,
                                 &diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);

        sync_in_progress++;
        crm_notice("Not applying diff %d.%d.%d -> %d.%d.%d (sync in progress)",
                   diff_del_admin_epoch, diff_del_epoch, diff_del_updates,
                   diff_add_admin_epoch, diff_add_epoch, diff_add_updates);
        return -pcmk_err_diff_resync;
    }

    rc = cib_process_diff(op, options, section, req, input, existing_cib, result_cib, answer);
    crm_trace("result: %s (%d), %s", pcmk_strerror(rc), rc,
              (based_is_primary? "primary": "secondary"));

    if ((rc == -pcmk_err_diff_resync) && !based_is_primary) {
        pcmk__xml_free(*result_cib);
        *result_cib = NULL;
        send_sync_request(NULL);

    } else if (rc == -pcmk_err_diff_resync) {
        rc = -pcmk_err_diff_failed;
        if (options & cib_force_diff) {
            crm_warn("Not requesting full refresh in R/W mode");
        }
    }

    return rc;
}

int
cib_process_replace_svr(const char *op, int options, const char *section, xmlNode * req,
                        xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                        xmlNode ** answer)
{
    int rc =
        cib_process_replace(op, options, section, req, input, existing_cib, result_cib, answer);

    if ((rc == pcmk_ok) && pcmk__xe_is(input, PCMK_XE_CIB)) {
        sync_in_progress = 0;
    }
    return rc;
}

/* @COMPAT: Remove when PCMK__CIB_REQUEST_ABS_DELETE is removed
 * (At least external client code <3.0.0 can send it)
 */
int
cib_process_delete_absolute(const char *op, int options, const char *section, xmlNode * req,
                            xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                            xmlNode ** answer)
{
    return -EINVAL;
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
        const char *value = crm_element_value(msg, field);

        if (value != NULL) {
            crm_xml_add(copy, field, value);
        }
    }

    return copy;
}

int
sync_our_cib(xmlNode * request, gboolean all)
{
    int result = pcmk_ok;
    char *digest = NULL;
    const char *host = crm_element_value(request, PCMK__XA_SRC);
    const char *op = crm_element_value(request, PCMK__XA_CIB_OP);
    pcmk__node_status_t *peer = NULL;
    xmlNode *replace_request = NULL;
    xmlNode *wrapper = NULL;

    CRM_CHECK(the_cib != NULL, return -EINVAL);
    CRM_CHECK(all || (host != NULL), return -EINVAL);

    crm_debug("Syncing CIB to %s", all ? "all peers" : host);

    replace_request = cib_msg_copy(request);

    if (host != NULL) {
        crm_xml_add(replace_request, PCMK__XA_CIB_ISREPLYTO, host);
    }
    if (all) {
        pcmk__xe_remove_attr(replace_request, PCMK__XA_CIB_HOST);
    }

    crm_xml_add(replace_request, PCMK__XA_CIB_OP, PCMK__CIB_REQUEST_REPLACE);

    // @TODO Keep for tracing, or drop?
    crm_xml_add(replace_request, PCMK__XA_ORIGINAL_CIB_OP, op);

    pcmk__xe_set_bool_attr(replace_request, PCMK__XA_CIB_UPDATE, true);

    crm_xml_add(replace_request, PCMK_XA_CRM_FEATURE_SET, CRM_FEATURE_SET);
    digest = pcmk__digest_xml(the_cib, true);
    crm_xml_add(replace_request, PCMK__XA_DIGEST, digest);

    wrapper = pcmk__xe_create(replace_request, PCMK__XE_CIB_CALLDATA);
    pcmk__xml_copy(wrapper, the_cib);

    if (!all) {
        peer = pcmk__get_node(0, host, NULL, pcmk__node_search_cluster_member);
    }
    if (!pcmk__cluster_send_message(peer, pcmk_ipc_based, replace_request)) {
        result = -ENOTCONN;
    }
    pcmk__xml_free(replace_request);
    free(digest);
    return result;
}

int
cib_process_commit_transaction(const char *op, int options, const char *section,
                               xmlNode *req, xmlNode *input,
                               xmlNode *existing_cib, xmlNode **result_cib,
                               xmlNode **answer)
{
    /* On success, our caller will activate *result_cib locally, trigger a
     * replace notification if appropriate, and sync *result_cib to all nodes.
     * On failure, our caller will free *result_cib.
     */
    int rc = pcmk_rc_ok;
    const char *client_id = crm_element_value(req, PCMK__XA_CIB_CLIENTID);
    const char *origin = crm_element_value(req, PCMK__XA_SRC);
    pcmk__client_t *client = pcmk__find_client_by_id(client_id);

    rc = based_commit_transaction(input, client, origin, result_cib);

    if (rc != pcmk_rc_ok) {
        char *source = based_transaction_source_str(client, origin);

        crm_err("Could not commit transaction for %s: %s",
                source, pcmk_rc_str(rc));
        free(source);
    }
    return pcmk_rc2legacy(rc);
}

int
cib_process_schemas(const char *op, int options, const char *section, xmlNode *req,
                    xmlNode *input, xmlNode *existing_cib, xmlNode **result_cib,
                    xmlNode **answer)
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
        crm_warn("No data specified in request");
        return -EPROTO;
    }

    after_ver = crm_element_value(data, PCMK_XA_VERSION);
    if (after_ver == NULL) {
        crm_warn("No version specified in request");
        return -EPROTO;
    }

    /* The client requested all schemas after the latest one we know about, which
     * means the client is fully up-to-date.  Return a properly formatted reply
     * with no schemas.
     */
    if (pcmk__str_eq(after_ver, pcmk__highest_schema_name(), pcmk__str_none)) {
        return pcmk_ok;
    }

    schemas = pcmk__schema_files_later_than(after_ver);

    for (GList *iter = schemas; iter != NULL; iter = iter->next) {
        pcmk__build_schema_xml_node(*answer, iter->data, &already_included);
    }

    g_list_free_full(schemas, free);
    g_list_free_full(already_included, free);
    return pcmk_ok;
}
