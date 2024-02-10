/*
 * Copyright 2023-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <libxml/tree.h>

#include "pacemaker-based.h"

/*!
 * \internal
 * \brief Create a string describing the source of a commit-transaction request
 *
 * \param[in] client  CIB client
 * \param[in] origin  Host where the commit request originated
 *
 * \return String describing the request source
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
char *
based_transaction_source_str(const pcmk__client_t *client, const char *origin)
{
    if (client != NULL) {
        return crm_strdup_printf("client %s (%s)%s%s",
                                 pcmk__client_name(client),
                                 pcmk__s(client->id, "unidentified"),
                                 ((origin != NULL)? " on " : ""),
                                 pcmk__s(origin, ""));
    } else {
        return pcmk__str_copy(pcmk__s(origin, "unknown source"));
    }
}

/*!
 * \internal
 * \brief Process requests in a transaction
 *
 * Stop when a request fails or when all requests have been processed.
 *
 * \param[in,out] transaction  Transaction to process
 * \param[in]     client       CIB client
 * \param[in]     source       String describing the commit request source
 *
 * \return Standard Pacemaker return code
 */
static int
process_transaction_requests(xmlNodePtr transaction,
                             const pcmk__client_t *client, const char *source)
{
    for (xmlNode *request = pcmk__xe_first_child(transaction,
                                                 PCMK__XE_CIB_COMMAND, NULL,
                                                 NULL);
         request != NULL; request = crm_next_same_xml(request)) {

        const char *op = crm_element_value(request, PCMK__XA_CIB_OP);
        const char *host = crm_element_value(request, PCMK__XA_CIB_HOST);
        const cib__operation_t *operation = NULL;
        int rc = cib__get_operation(op, &operation);

        if (rc == pcmk_rc_ok) {
            if (!pcmk_is_set(operation->flags, cib__op_attr_transaction)
                || (host != NULL)) {

                rc = EOPNOTSUPP;
            } else {
                /* Commit-transaction is a privileged operation. If we reached
                 * this point, the request came from a privileged connection.
                 */
                rc = cib_process_request(request, TRUE, client);
                rc = pcmk_legacy2rc(rc);
            }
        }

        if (rc != pcmk_rc_ok) {
            crm_err("Aborting CIB transaction for %s due to failed %s request: "
                    "%s",
                    source, op, pcmk_rc_str(rc));
            crm_log_xml_info(request, "Failed request");
            return rc;
        }

        crm_trace("Applied %s request to transaction working CIB for %s",
                  op, source);
        crm_log_xml_trace(request, "Successful request");
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Commit a given CIB client's transaction to a working CIB copy
 *
 * \param[in]     transaction  Transaction to commit
 * \param[in]     client       CIB client
 * \param[in]     origin       Host where the commit request originated
 * \param[in,out] result_cib   Where to store result CIB
 *
 * \return Standard Pacemaker return code
 *
 * \note This function is expected to be called only by
 *       \p cib_process_commit_transaction().
 * \note \p result_cib is expected to be a copy of the current CIB as created by
 *       \p cib_perform_op().
 * \note The caller is responsible for activating and syncing \p result_cib on
 *       success, and for freeing it on failure.
 */
int
based_commit_transaction(xmlNodePtr transaction, const pcmk__client_t *client,
                         const char *origin, xmlNodePtr *result_cib)
{
    xmlNodePtr saved_cib = the_cib;
    int rc = pcmk_rc_ok;
    char *source = NULL;

    CRM_ASSERT(result_cib != NULL);

    CRM_CHECK(pcmk__xe_is(transaction, PCMK__XE_CIB_TRANSACTION),
              return pcmk_rc_no_transaction);

    /* *result_cib should be a copy of the_cib (created by cib_perform_op()). If
     * not, make a copy now. Change tracking isn't strictly required here
     * because:
     * * Each request in the transaction will have changes tracked and ACLs
     *   checked if appropriate.
     * * cib_perform_op() will infer changes for the commit request at the end.
     */
    CRM_CHECK((*result_cib != NULL) && (*result_cib != the_cib),
              *result_cib = pcmk__xml_copy(NULL, the_cib));

    source = based_transaction_source_str(client, origin);
    crm_trace("Committing transaction for %s to working CIB", source);

    // Apply all changes to a working copy of the CIB
    the_cib = *result_cib;

    rc = process_transaction_requests(transaction, client, origin);

    crm_trace("Transaction commit %s for %s",
              ((rc == pcmk_rc_ok)? "succeeded" : "failed"), source);

    /* Some request types (for example, erase) may have freed the_cib (the
     * working copy) and pointed it at a new XML object. In that case, it
     * follows that *result_cib (the working copy) was freed.
     *
     * Point *result_cib at the updated working copy stored in the_cib.
     */
    *result_cib = the_cib;

    // Point the_cib back to the unchanged original copy
    the_cib = saved_cib;

    free(source);
    return rc;
}
