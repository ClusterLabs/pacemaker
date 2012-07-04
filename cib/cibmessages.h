/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CIB_MESSAGES__H
#  define CIB_MESSAGES__H

#  include <crm/cib/ops.h>
extern xmlNode *createCibRequest(gboolean isLocal, const char *operation, const char *section,
                                 const char *verbose, xmlNode * data);

extern int cib_process_shutdown_req(const char *op, int options, const char *section,
                                                xmlNode * req, xmlNode * input,
                                                xmlNode * existing_cib, xmlNode ** result_cib,
                                                xmlNode ** answer);

extern int cib_process_default(const char *op, int options, const char *section,
                                           xmlNode * req, xmlNode * input, xmlNode * existing_cib,
                                           xmlNode ** result_cib, xmlNode ** answer);

extern int cib_process_quit(const char *op, int options, const char *section,
                                        xmlNode * req, xmlNode * input, xmlNode * existing_cib,
                                        xmlNode ** result_cib, xmlNode ** answer);

extern int cib_process_ping(const char *op, int options, const char *section,
                                        xmlNode * req, xmlNode * input, xmlNode * existing_cib,
                                        xmlNode ** result_cib, xmlNode ** answer);

extern int cib_process_readwrite(const char *op, int options, const char *section,
                                             xmlNode * req, xmlNode * input, xmlNode * existing_cib,
                                             xmlNode ** result_cib, xmlNode ** answer);

extern int cib_process_replace_svr(const char *op, int options, const char *section,
                                               xmlNode * req, xmlNode * input,
                                               xmlNode * existing_cib, xmlNode ** result_cib,
                                               xmlNode ** answer);

extern int cib_server_process_diff(const char *op, int options, const char *section,
                                               xmlNode * req, xmlNode * input,
                                               xmlNode * existing_cib, xmlNode ** result_cib,
                                               xmlNode ** answer);

extern int cib_process_sync(const char *op, int options, const char *section,
                                        xmlNode * req, xmlNode * input, xmlNode * existing_cib,
                                        xmlNode ** result_cib, xmlNode ** answer);

extern int cib_process_sync_one(const char *op, int options, const char *section,
                                            xmlNode * req, xmlNode * input, xmlNode * existing_cib,
                                            xmlNode ** result_cib, xmlNode ** answer);

extern int cib_process_delete_absolute(const char *op, int options, const char *section,
                                                   xmlNode * req, xmlNode * input,
                                                   xmlNode * existing_cib, xmlNode ** result_cib,
                                                   xmlNode ** answer);

#endif
