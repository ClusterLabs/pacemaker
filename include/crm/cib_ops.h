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
#ifndef CIB_OPS__H
#  define CIB_OPS__H

#  include <sys/param.h>
#  include <stdio.h>
#  include <sys/types.h>
#  include <unistd.h>

#  include <stdlib.h>
#  include <errno.h>
#  include <fcntl.h>

#  include <time.h>

#  include <crm/crm.h>
#  include <crm/cib.h>
#  include <crm/msg_xml.h>
#  include <crm/common/xml.h>

enum cib_errors

cib_process_query(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                  xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

enum cib_errors

cib_process_erase(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                  xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

enum cib_errors

cib_process_bump(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                 xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

enum cib_errors

cib_process_replace(const char *op, int options, const char *section, xmlNode * req,
                    xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                    xmlNode ** answer);

enum cib_errors

cib_process_create(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                   xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

enum cib_errors

cib_process_modify(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                   xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

enum cib_errors

cib_process_delete(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                   xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

enum cib_errors

cib_process_diff(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                 xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

enum cib_errors

cib_process_upgrade(const char *op, int options, const char *section, xmlNode * req,
                    xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                    xmlNode ** answer);

enum cib_errors

cib_process_xpath(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                  xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

enum cib_errors cib_update_counter(xmlNode * xml_obj, const char *field, gboolean reset);
extern xmlNode *diff_cib_object(xmlNode * old_cib, xmlNode * new_cib, gboolean suppress);
extern gboolean apply_cib_diff(xmlNode * old, xmlNode * diff, xmlNode ** new);
extern gboolean cib_config_changed(xmlNode * last, xmlNode * next, xmlNode ** diff);
extern gboolean update_results(xmlNode * failed, xmlNode * target, const char *operation,
                               int return_code);

#endif
