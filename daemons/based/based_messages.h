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

int based_process_abs_delete(const char *section, xmlNode *req, xmlNode *input,
                             xmlNode **cib, xmlNode **answer);

int based_process_apply_patch(const char *section, xmlNode *req, xmlNode *input,
                              xmlNode **cib, xmlNode **answer);

int based_process_commit_transact(const char *section, xmlNode *req,
                                  xmlNode *input, xmlNode **cib,
                                  xmlNode **answer);

int based_process_is_primary(const char *section, xmlNode *req, xmlNode *input,
                             xmlNode **cib, xmlNode **answer);

int based_process_noop(const char *section, xmlNode *req, xmlNode *input,
                       xmlNode **cib, xmlNode **answer);

int based_process_ping(const char *section, xmlNode *req, xmlNode *input,
                       xmlNode **cib, xmlNode **answer);

int based_process_primary(const char *section, xmlNode *req, xmlNode *input,
                          xmlNode **cib, xmlNode **answer);

int based_process_schemas(const char *section, xmlNode *req, xmlNode *input,
                          xmlNode **cib, xmlNode **answer);

int based_process_secondary(const char *section, xmlNode *req, xmlNode *input,
                            xmlNode **cib, xmlNode **answer);

int based_process_shutdown(const char *section, xmlNode *req, xmlNode *input,
                           xmlNode **cib, xmlNode **answer);

int based_process_sync(const char *section, xmlNode *req, xmlNode *input,
                       xmlNode **cib, xmlNode **answer);

int based_process_upgrade(const char *section, xmlNode *req, xmlNode *input,
                          xmlNode **cib, xmlNode **answer);

int sync_our_cib(xmlNode *request, bool all);

#endif // BASED_MESSAGES__H
