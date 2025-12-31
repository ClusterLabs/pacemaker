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
                             xmlNode *req, xmlNode *input, xmlNode **cib,
                             xmlNode **answer);

int based_process_apply_patch(const char *op, int options, const char *section,
                              xmlNode *req, xmlNode *input, xmlNode **cib,
                              xmlNode **answer);

int based_process_commit_transact(const char *op, int options,
                                  const char *section, xmlNode *req,
                                  xmlNode *input, xmlNode **cib,
                                  xmlNode **answer);

int based_process_is_primary(const char *op, int options, const char *section,
                             xmlNode *req, xmlNode *input, xmlNode **cib,
                             xmlNode **answer);

int based_process_noop(const char *op, int options, const char *section,
                       xmlNode *req, xmlNode *input, xmlNode **cib,
                       xmlNode **answer);

int based_process_ping(const char *op, int options, const char *section,
                       xmlNode *req, xmlNode *input, xmlNode **cib,
                       xmlNode **answer);

int based_process_primary(const char *op, int options, const char *section,
                          xmlNode *req, xmlNode *input, xmlNode **cib,
                          xmlNode **answer);

int based_process_replace(const char *op, int options, const char *section,
                          xmlNode *req, xmlNode *input, xmlNode **cib,
                          xmlNode **answer);

int based_process_schemas(const char *op, int options, const char *section,
                          xmlNode *req, xmlNode *input, xmlNode **cib,
                          xmlNode **answer);

int based_process_secondary(const char *op, int options, const char *section,
                            xmlNode *req, xmlNode *input, xmlNode **cib,
                            xmlNode **answer);

int based_process_shutdown(const char *op, int options, const char *section,
                           xmlNode *req, xmlNode *input, xmlNode **cib,
                           xmlNode **answer);

int based_process_sync_to_all(const char *op, int options, const char *section,
                              xmlNode *req, xmlNode *input, xmlNode **cib,
                              xmlNode **answer);

int based_process_sync_to_one(const char *op, int options, const char *section,
                              xmlNode *req, xmlNode *input, xmlNode **cib,
                              xmlNode **answer);

int based_process_upgrade(const char *op, int options, const char *section,
                          xmlNode *req, xmlNode *input, xmlNode **cib,
                          xmlNode **answer);

void send_sync_request(void);
int sync_our_cib(xmlNode *request, bool all);

#endif // BASED_MESSAGES__H
