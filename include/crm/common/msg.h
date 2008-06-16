/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef CRM_COMMON_MSG__H
#define CRM_COMMON_MSG__H

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <clplumbing/ipc.h>

extern xmlNode *createPingAnswerFragment(const char *from,
					   const char *status);


extern gboolean process_hello_message(xmlNode *hello,
				      char **uuid,
				      char **client_name,
				      char **major_version,
				      char **minor_version);

#endif
