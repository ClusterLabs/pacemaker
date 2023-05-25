/*
 * Copyright 2004-2023 the Pacemaker project contributors
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

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>

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
    const char *host = crm_element_value(req, F_ORIG);

    *answer = NULL;

    if (crm_element_value(req, F_CIB_ISREPLY) == NULL) {
        crm_info("Peer %s is requesting to shut down", host);
        return pcmk_ok;
    }

    if (cib_shutdown_flag == FALSE) {
        crm_err("Peer %s mistakenly thinks we wanted to shut down", host);
        return -EINVAL;
    }

    crm_info("Peer %s has acknowledged our shutdown request", host);
    terminate_cib(__func__, 0);
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
    xmlNode *sync_me = create_xml_node(NULL, "sync-me");

    crm_info("Requesting re-sync from %s", (host? host : "all peers"));
    sync_in_progress = 1;

    crm_xml_add(sync_me, F_TYPE, "cib");
    crm_xml_add(sync_me, F_CIB_OPERATION, PCMK__CIB_REQUEST_SYNC_TO_ONE);
    crm_xml_add(sync_me, F_CIB_DELEGATED,
                stand_alone? "localhost" : crm_cluster->uname);

    send_cluster_message(host ? crm_get_peer(0, host) : NULL, crm_msg_cib, sync_me, FALSE);
    free_xml(sync_me);
}

int
cib_process_ping(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                 xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    const char *host = crm_element_value(req, F_ORIG);
    const char *seq = crm_element_value(req, F_CIB_PING_ID);
    char *digest = calculate_xml_versioned_digest(the_cib, FALSE, TRUE, CRM_FEATURE_SET);

    crm_trace("Processing \"%s\" event %s from %s", op, seq, host);
    *answer = create_xml_node(NULL, XML_CRM_TAG_PING);

    crm_xml_add(*answer, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);
    crm_xml_add(*answer, XML_ATTR_DIGEST, digest);
    crm_xml_add(*answer, F_CIB_PING_ID, seq);

    pcmk__if_tracing(
        {
            // Append additional detail so the receiver can log the differences
            add_message_xml(*answer, F_CIB_CALLDATA, the_cib);
        },
        {
            // Always include at least the version details
            const char *tag = TYPE(the_cib);
            xmlNode *shallow = create_xml_node(NULL, tag);

            copy_in_properties(shallow, the_cib);
            add_message_xml(*answer, F_CIB_CALLDATA, shallow);
            free_xml(shallow);
        }
    );

    crm_info("Reporting our current digest to %s: %s for %s.%s.%s",
             host, digest,
             crm_element_value(existing_cib, XML_ATTR_GENERATION_ADMIN),
             crm_element_value(existing_cib, XML_ATTR_GENERATION),
             crm_element_value(existing_cib, XML_ATTR_NUMUPDATES));

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

    if(crm_element_value(req, F_CIB_SCHEMA_MAX)) {
        /* The originator of an upgrade request sends it to the DC, without
         * F_CIB_SCHEMA_MAX. If an upgrade is needed, the DC re-broadcasts the
         * request with F_CIB_SCHEMA_MAX, and each node performs the upgrade
         * (and notifies its local clients) here.
         */
        return cib_process_upgrade(
            op, options, section, req, input, existing_cib, result_cib, answer);

    } else {
        int new_version = 0;
        int current_version = 0;
        xmlNode *scratch = copy_xml(existing_cib);
        const char *host = crm_element_value(req, F_ORIG);
        const char *value = crm_element_value(existing_cib, XML_ATTR_VALIDATION);
        const char *client_id = crm_element_value(req, F_CIB_CLIENTID);
        const char *call_opts = crm_element_value(req, F_CIB_CALLOPTS);
        const char *call_id = crm_element_value(req, F_CIB_CALLID);

        crm_trace("Processing \"%s\" event", op);
        if (value != NULL) {
            current_version = get_schema_version(value);
        }

        rc = update_validation(&scratch, &new_version, 0, TRUE, TRUE);
        if (new_version > current_version) {
            xmlNode *up = create_xml_node(NULL, __func__);

            rc = pcmk_ok;
            crm_notice("Upgrade request from %s verified", host);

            crm_xml_add(up, F_TYPE, "cib");
            crm_xml_add(up, F_CIB_OPERATION, PCMK__CIB_REQUEST_UPGRADE);
            crm_xml_add(up, F_CIB_SCHEMA_MAX, get_schema_name(new_version));
            crm_xml_add(up, F_CIB_DELEGATED, host);
            crm_xml_add(up, F_CIB_CLIENTID, client_id);
            crm_xml_add(up, F_CIB_CALLOPTS, call_opts);
            crm_xml_add(up, F_CIB_CALLID, call_id);

            if (cib_legacy_mode() && based_is_primary) {
                rc = cib_process_upgrade(
                    op, options, section, up, input, existing_cib, result_cib, answer);

            } else {
                send_cluster_message(NULL, crm_msg_cib, up, FALSE);
            }

            free_xml(up);

        } else if(rc == pcmk_ok) {
            rc = -pcmk_err_schema_unchanged;
        }

        if (rc != pcmk_ok) {
            // Notify originating peer so it can notify its local clients
            crm_node_t *origin = pcmk__search_cluster_node_cache(0, host);

            crm_info("Rejecting upgrade request from %s: %s "
                     CRM_XS " rc=%d peer=%s", host, pcmk_strerror(rc), rc,
                     (origin? origin->uname : "lost"));

            if (origin) {
                xmlNode *up = create_xml_node(NULL, __func__);

                crm_xml_add(up, F_TYPE, "cib");
                crm_xml_add(up, F_CIB_OPERATION, PCMK__CIB_REQUEST_UPGRADE);
                crm_xml_add(up, F_CIB_DELEGATED, host);
                crm_xml_add(up, F_CIB_ISREPLY, host);
                crm_xml_add(up, F_CIB_CLIENTID, client_id);
                crm_xml_add(up, F_CIB_CALLOPTS, call_opts);
                crm_xml_add(up, F_CIB_CALLID, call_id);
                crm_xml_add_int(up, F_CIB_UPGRADE_RC, rc);
                if (send_cluster_message(origin, crm_msg_cib, up, TRUE)
                    == FALSE) {
                    crm_warn("Could not send CIB upgrade result to %s", host);
                }
                free_xml(up);
            }
        }
        free_xml(scratch);
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
        free_xml(*result_cib);
        *result_cib = NULL;
        send_sync_request(NULL);

    } else if (rc == -pcmk_err_diff_resync) {
        rc = -pcmk_err_diff_failed;
        if (options & cib_force_diff) {
            crm_warn("Not requesting full refresh in R/W mode");
        }

    } else if ((rc != pcmk_ok) && !based_is_primary && cib_legacy_mode()) {
        crm_warn("Requesting full CIB refresh because update failed: %s"
                 CRM_XS " rc=%d", pcmk_strerror(rc), rc);

        pcmk__output_set_log_level(logger_out, LOG_INFO);
        logger_out->message(logger_out, "xml-patchset", input);
        free_xml(*result_cib);
        *result_cib = NULL;
        send_sync_request(NULL);
    }

    return rc;
}

int
cib_process_replace_svr(const char *op, int options, const char *section, xmlNode * req,
                        xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                        xmlNode ** answer)
{
    const char *tag = crm_element_name(input);
    int rc =
        cib_process_replace(op, options, section, req, input, existing_cib, result_cib, answer);
    if (rc == pcmk_ok && pcmk__str_eq(tag, XML_TAG_CIB, pcmk__str_casei)) {
        sync_in_progress = 0;
    }
    return rc;
}

// @COMPAT: Remove when PCMK__CIB_REQUEST_ABS_DELETE is removed
int
cib_process_delete_absolute(const char *op, int options, const char *section, xmlNode * req,
                            xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                            xmlNode ** answer)
{
    return -EINVAL;
}

int
sync_our_cib(xmlNode * request, gboolean all)
{
    int result = pcmk_ok;
    char *digest = NULL;
    const char *host = crm_element_value(request, F_ORIG);
    const char *op = crm_element_value(request, F_CIB_OPERATION);

    xmlNode *replace_request = NULL;

    CRM_CHECK(the_cib != NULL, return -EINVAL);
    CRM_CHECK(all || (host != NULL), return -EINVAL);

    replace_request = cib_msg_copy(request);
    CRM_CHECK(replace_request != NULL, return -EINVAL);

    crm_debug("Syncing CIB to %s", all ? "all peers" : host);

    if (host != NULL) {
        crm_xml_add(replace_request, F_CIB_ISREPLY, host);
    }
    if (all) {
        xml_remove_prop(replace_request, F_CIB_HOST);
    }

    crm_xml_add(replace_request, F_CIB_OPERATION, PCMK__CIB_REQUEST_REPLACE);
    crm_xml_add(replace_request, "original_" F_CIB_OPERATION, op);
    pcmk__xe_set_bool_attr(replace_request, F_CIB_GLOBAL_UPDATE, true);

    crm_xml_add(replace_request, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);
    digest = calculate_xml_versioned_digest(the_cib, FALSE, TRUE, CRM_FEATURE_SET);
    crm_xml_add(replace_request, XML_ATTR_DIGEST, digest);

    add_message_xml(replace_request, F_CIB_CALLDATA, the_cib);

    if (send_cluster_message
        (all ? NULL : crm_get_peer(0, host), crm_msg_cib, replace_request, FALSE) == FALSE) {
        result = -ENOTCONN;
    }
    free_xml(replace_request);
    free(digest);
    return result;
}
