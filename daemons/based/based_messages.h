/*
 * Copyright 2004-2026 the Pacemaker project contributors
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

int based_process_abs_delete(xmlNode *req, xmlNode *input, xmlNode **cib,
                             xmlNode **answer);

int based_process_apply_patch(xmlNode *req, xmlNode *input, xmlNode **cib,
                              xmlNode **answer);

int based_process_commit_transact(xmlNode *req, xmlNode *input, xmlNode **cib,
                                  xmlNode **answer);

int based_process_is_primary(xmlNode *req, xmlNode *input, xmlNode **cib,
                             xmlNode **answer);

int based_process_noop(xmlNode *req, xmlNode *input, xmlNode **cib,
                       xmlNode **answer);

int based_process_ping(xmlNode *req, xmlNode *input, xmlNode **cib,
                       xmlNode **answer);

int based_process_primary(xmlNode *req, xmlNode *input, xmlNode **cib,
                          xmlNode **answer);

int based_process_schemas(xmlNode *req, xmlNode *input, xmlNode **cib,
                          xmlNode **answer);

int based_process_secondary(xmlNode *req, xmlNode *input, xmlNode **cib,
                            xmlNode **answer);

int based_process_shutdown(xmlNode *req, xmlNode *input, xmlNode **cib,
                           xmlNode **answer);

int based_process_sync(xmlNode *req, xmlNode *input, xmlNode **cib,
                       xmlNode **answer);

int based_process_upgrade(xmlNode *req, xmlNode *input, xmlNode **cib,
                          xmlNode **answer);

int sync_our_cib(xmlNode *request, bool all);

#endif // BASED_MESSAGES__H
