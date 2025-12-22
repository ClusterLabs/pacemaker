/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef BASED_MESSAGES__H
#define BASED_MESSAGES__H

#include <stdbool.h>

#include <libxml/tree.h>            // xmlNode *

extern bool based_is_primary;
extern xmlNode *the_cib;

int based_process_abs_delete(const char *op, int options, const char *section,
                             xmlNode *req, xmlNode *input,
                             xmlNode *existing_cib, xmlNode **result_cib,
                             xmlNode **answer);

int based_process_apply_patch(const char *op, int options, const char *section,
                              xmlNode *req, xmlNode *input,
                              xmlNode *existing_cib, xmlNode **result_cib,
                              xmlNode **answer);

int cib_process_shutdown_req(const char *op, int options, const char *section,
                             xmlNode *req, xmlNode *input,
                             xmlNode *existing_cib, xmlNode **result_cib,
                             xmlNode **answer);

int cib_process_noop(const char *op, int options, const char *section,
                     xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                     xmlNode **result_cib, xmlNode **answer);

int cib_process_ping(const char *op, int options, const char *section,
                     xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                     xmlNode **result_cib, xmlNode **answer);

int cib_process_readwrite(const char *op, int options, const char *section,
                          xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                          xmlNode **result_cib, xmlNode **answer);

int cib_process_replace_svr(const char *op, int options, const char *section,
                            xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                            xmlNode **result_cib, xmlNode **answer);

int cib_process_sync(const char *op, int options, const char *section,
                     xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                     xmlNode **result_cib, xmlNode **answer);

int cib_process_sync_one(const char *op, int options, const char *section,
                         xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                         xmlNode **result_cib, xmlNode **answer);

int cib_process_upgrade_server(const char *op, int options, const char *section,
                               xmlNode *req, xmlNode *input,
                               xmlNode *existing_cib, xmlNode **result_cib,
                               xmlNode **answer);

int cib_process_commit_transaction(const char *op, int options,
                                   const char *section, xmlNode *req,
                                   xmlNode *input, xmlNode *existing_cib,
                                   xmlNode **result_cib, xmlNode **answer);

int cib_process_schemas(const char *op, int options, const char *section,
                        xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                        xmlNode **result_cib, xmlNode **answer);

void send_sync_request(void);
int sync_our_cib(xmlNode *request, bool all);

#endif // BASED_MESSAGES__H
