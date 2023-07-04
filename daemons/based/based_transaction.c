/*
 * Copyright 2023 the Pacemaker project contributors
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

struct request_data {
    pcmk__client_t *client;
    xmlNodePtr request;
    bool privileged;
};

/* Table of uncommitted CIB transactions
 * key: client ID (const char *), value: GQueue of struct request_data
 */
static GHashTable *transactions = NULL;

/*!
 * \internal
 * \brief Create a new a CIB request data object
 *
 * \param[in] client      CIB client
 * \param[in] request     CIB request
 * \param[in] privileged  If \p true, the request has write privileges
 */
static struct request_data *
create_request_data(pcmk__client_t *client, xmlNodePtr request,
                    bool privileged)
{
    struct request_data *data = calloc(1, sizeof(struct request_data));

    if (data == NULL) {
        return NULL;
    }

    /* Caller owns client and request. The client's transaction is always
     * discarded before the client is freed, so we can safely use it when
     * processing requests in the transaction. The request is freed before we
     * use it, so make a copy.
     */
    data->client = client;
    data->request = copy_xml(request);
    data->privileged = privileged;

    return data;
}

/*!
 * \internal
 * \brief Free a CIB request data object
 *
 * \param[in,out] data  Request data object to free
 */
static void
free_request_data(gpointer data)
{
    struct request_data *req_data = (struct request_data *) data;

    if (req_data != NULL) {
        // req_data doesn't own req_data->client
        free_xml(req_data->request);
        free(req_data);
    }
}

/*!
 * \internal
 * \brief Free a CIB transaction and the requests it contains
 *
 * \param[in,out] data  Transaction to free
 */
static inline void
free_transaction(gpointer data)
{
    g_queue_free_full((GQueue *) data, (GDestroyNotify) free_request_data);
}

/*!
 * \internal
 * \brief Get a CIB client's uncommitted transaction, if any
 *
 * \param[in] client  Client to look up
 *
 * \return The client's uncommitted transaction, if any
 *
 * \note The caller must not free the return value directly. Transactions must
 *       be freed by \p based_discard_transaction() or by
 *       \p based_free_transaction_table().
 */
static inline GQueue *
get_transaction(const pcmk__client_t *client)
{
    if (transactions == NULL) {
        return NULL;
    }
    return g_hash_table_lookup(transactions, client->id);
}

/*!
 * \internal
 * \brief Create a new transaction for a given CIB client
 *
 * \param[in] client  Client to initiate a transaction for
 *
 * \return Standard Pacemaker return code
 */
int
based_init_transaction(const pcmk__client_t *client)
{
    CRM_ASSERT(client != NULL);

    if (client->id == NULL) {
        crm_warn("Can't initiate transaction for client without id");
        return EINVAL;
    }

    // A client can have at most one transaction at a time
    if (get_transaction(client) != NULL) {
        return pcmk_rc_already;
    }

    crm_trace("Initiating transaction for client %s (%s)",
              pcmk__client_name(client), client->id);

    if (transactions == NULL) {
        transactions = pcmk__strkey_table(NULL, free_transaction);
    }
    g_hash_table_insert(transactions, client->id, g_queue_new());
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Validate that a CIB request is supported in a transaction
 *
 * \param[in] request  CIB request
 *
 * \return Standard Pacemaker return code
 */
static int
validate_transaction_request(const xmlNode *request)
{
    const char *op = crm_element_value(request, F_CIB_OPERATION);
    const char *host = crm_element_value(request, F_CIB_HOST);

    const cib_operation_t *operation = NULL;
    int rc = cib__get_operation(op, &operation);

    if (rc != pcmk_rc_ok) {
        // cib_get_operation() logs error
        return rc;
    }

    if (!pcmk_is_set(operation->flags, cib_op_attr_transaction)) {
        crm_err("Operation '%s' is not supported in CIB transaction", op);
        return EOPNOTSUPP;
    }

    if (!pcmk__str_eq(host, OUR_NODENAME,
                      pcmk__str_casei|pcmk__str_null_matches)) {
        crm_err("Operation targeting another node (%s) is not supported in CIB "
                "transaction",
                host);
        return EOPNOTSUPP;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Add a new CIB request to an existing transaction
 *
 * \param[in] client      Client whose transaction to extend
 * \param[in] request     CIB request
 * \param[in] privileged  If \p true, the request has write privileges
 *
 * \return Standard Pacemaker return code
 */
int
based_extend_transaction(pcmk__client_t *client, xmlNodePtr request,
                         bool privileged)
{
    struct request_data *data = NULL;
    GQueue *transaction = NULL;
    int rc = pcmk_rc_ok;

    CRM_ASSERT((client != NULL) && (request != NULL));

    transaction = get_transaction(client);
    if (transaction == NULL) {
        return pcmk_rc_no_transaction;
    }

    rc = validate_transaction_request(request);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    data = create_request_data(client, request, privileged);
    if (data == NULL) {
        return ENOMEM;
    }

    g_queue_push_tail(transaction, data);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Free a CIB client's transaction (if any) and its requests
 *
 * \param[in] client  Client whose transaction to discard
 */
void
based_discard_transaction(const pcmk__client_t *client)
{
    bool found = false;

    CRM_ASSERT(client != NULL);

    if (transactions != NULL) {
        found = g_hash_table_remove(transactions, client->id);
    }

    crm_trace("%s for client %s (%s)",
              (found? "Found and removed transaction" : "No transaction found"),
              pcmk__client_name(client),
              pcmk__s(client->id, "unidentified"));
}

/*!
 * \internal
 * \brief Process requests in a transaction
 *
 * Stop when a request fails or when all requests have been processed.
 *
 * \param[in,out] transaction  Transaction to process
 * \param[in]     client_name  Client name (for logging only)
 * \param[in]     client_id    Client ID (for logging only)
 *
 * \return Standard Pacemaker return code
 */
static int
process_transaction_requests(GQueue *transaction, const char *client_name,
                             const char *client_id)
{
    for (struct request_data *data = g_queue_pop_head(transaction);
         data != NULL; data = g_queue_pop_head(transaction)) {

        const char *op = crm_element_value(data->request, F_CIB_OPERATION);

        int rc = cib_process_request(data->request, data->privileged,
                                     data->client);

        rc = pcmk_legacy2rc(rc);
        if (rc != pcmk_rc_ok) {
            crm_err("Aborting CIB transaction for client %s (%s) due to failed "
                    "%s request: %s",
                    client_name, client_id, op, pcmk_rc_str(rc));
            crm_log_xml_info(data->request, "Failed request");
            free_request_data(data);
            return rc;
        }

        crm_trace("Applied %s request to transaction working CIB for client %s "
                  "(%s)",
                  op, client_name, client_id);
        crm_log_xml_trace(data->request, "Successful request");
        free_request_data(data);
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Commit a given CIB client's transaction to a working CIB copy
 *
 * \param[in]     client      Client whose transaction to commit
 * \param[in,out] result_cib  Where to store result CIB
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
based_commit_transaction(const pcmk__client_t *client, xmlNodePtr *result_cib)
{
    GQueue *transaction = NULL;
    const char *client_name = NULL;
    const char *client_id = NULL;
    xmlNodePtr saved_cib = the_cib;
    int rc = pcmk_rc_ok;

    CRM_ASSERT((client != NULL) && (result_cib != NULL));

    /* *result_cib should be a copy of the_cib (created by cib_perform_op()). If
     * not, make a copy now. Change tracking isn't strictly required here
     * because:
     * * Each request in the transaction will have changes tracked and ACLs
     *   checked if appropriate.
     * * cib_perform_op() will infer changes for the commit request at the end.
     */
    CRM_CHECK((*result_cib != NULL) && (*result_cib != the_cib),
              *result_cib = copy_xml(the_cib));

    transaction = get_transaction(client);
    if (transaction == NULL) {
        return pcmk_rc_no_transaction;
    }

    client_name = pcmk__client_name(client);
    client_id = pcmk__s(client->id, "unidentified");

    crm_trace("Committing transaction for client %s (%s) to working CIB",
              client_name, client_id);

    // Apply all changes to a working copy of the CIB
    the_cib = *result_cib;

    rc = process_transaction_requests(transaction, client_name, client_id);

    crm_trace("Transaction commit %s for client %s (%s); discarding queue",
              ((rc != pcmk_rc_ok)? "succeeded" : "failed"), client_name,
              client_id);

    // Free the transaction and (if aborted) free any remaining requests
    based_discard_transaction(client);

    /* Some request types (for example, erase) may have freed the_cib (the
     * working copy) and pointed it at a new XML object. In that case, it
     * follows that *result_cib (the working copy) was freed.
     *
     * Point *result_cib at the updated working copy stored in the_cib.
     */
    *result_cib = the_cib;

    // Point the_cib back to the unchanged original copy
    the_cib = saved_cib;

    return rc;
}

/*!
 * \internal
 * \brief Free the transaction table and any uncommitted transactions
 */
void
based_free_transaction_table(void)
{
    if (transactions != NULL) {
        g_hash_table_destroy(transactions);
    }
}
