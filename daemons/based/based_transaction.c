/*
 * Copyright 2023-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // EOPNOTSUPP
#include <stdbool.h>
#include <stddef.h>                 // NULL
#include <stdlib.h>                 // free

#include <libxml/tree.h>            // xmlNode

#include <crm/cib/internal.h>       // cib__*
#include <crm/common/internal.h>    // pcmk__client_t, pcmk__s, pcmk__xe_*, etc.
#include <crm/common/logging.h>     // CRM_CHECK
#include <crm/common/results.h>     // pcmk_rc_*

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
        return pcmk__assert_asprintf("client %s (%s)%s%s",
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
process_transaction_requests(xmlNode *transaction, const pcmk__client_t *client,
                             const char *source)
{
    for (xmlNode *request = pcmk__xe_first_child(transaction,
                                                 PCMK__XE_CIB_COMMAND, NULL,
                                                 NULL);
         request != NULL;
         request = pcmk__xe_next(request, PCMK__XE_CIB_COMMAND)) {

        const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);
        const char *host = pcmk__xe_get(request, PCMK__XA_CIB_HOST);
        const cib__operation_t *operation = NULL;
        int rc = cib__get_operation(op, &operation);

        if (rc == pcmk_rc_ok) {
            if (!pcmk__is_set(operation->flags, cib__op_attr_transaction)
                || (host != NULL)) {

                rc = EOPNOTSUPP;
            } else {
                /* Commit-transaction is a privileged operation. If we reached
                 * this point, the request came from a privileged connection.
                 */
                rc = based_process_request(request, true, client);
            }
        }

        if (rc != pcmk_rc_ok) {
            pcmk__err("Aborting CIB transaction for %s due to failed %s "
                      "request: %s",
                      source, op, pcmk_rc_str(rc));
            pcmk__log_xml_info(request, "Failed request");
            return rc;
        }

        pcmk__trace("Applied %s request to transaction working CIB for %s", op,
                    source);
        pcmk__log_xml_trace(request, "Successful request");
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
 *       \p based_process_commit_transact().
 * \note \p result_cib is expected to be a copy of the current CIB as created by
 *       \p cib_perform_op().
 * \note The caller is responsible for activating and syncing \p result_cib on
 *       success, and for freeing it on failure.
 */
int
based_commit_transaction(xmlNode *transaction, const pcmk__client_t *client,
                         const char *origin, xmlNode **result_cib)
{
    xmlNode *saved_cib = the_cib;
    int rc = pcmk_rc_ok;
    char *source = NULL;

    pcmk__assert(result_cib != NULL);

    CRM_CHECK(pcmk__xe_is(transaction, PCMK__XE_CIB_TRANSACTION),
              return pcmk_rc_no_transaction);

    /* *result_cib should be a copy of the_cib (created by cib_perform_op()). If
     * not, make a copy now. Change tracking isn't strictly required here
     * because each request in the transaction will have changes tracked and
     * ACLs checked if appropriate.
     */
    CRM_CHECK((*result_cib != NULL) && (*result_cib != the_cib),
              *result_cib = pcmk__xml_copy(NULL, the_cib));

    source = based_transaction_source_str(client, origin);
    pcmk__trace("Committing transaction for %s to working CIB", source);

    // Apply all changes to a working copy of the CIB
    the_cib = *result_cib;

    rc = process_transaction_requests(transaction, client, origin);

    pcmk__trace("Transaction commit %s for %s",
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
