/* $Id: cibmessages.h,v 1.3 2004/03/24 09:59:04 andrew Exp $ */
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
#ifndef CIB_MESSAGES__H
#define CIB_MESSAGES__H

extern xmlNodePtr cib_process_request(const char *op,
				      const xmlNodePtr fragment,
				      const xmlNodePtr options,
				      enum cib_result *result);

extern xmlNodePtr createCibRequest(gboolean isLocal, const char *operation,
				   const char *section, const char *verbose,
				   xmlNodePtr data);


#endif
