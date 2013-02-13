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

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>

#include <crm/crm.h>
#include <crm/common/xml.h>

extern FILE *msg_cib_strm;

extern void cib_pre_notify(int options, const char *op, xmlNode * existing, xmlNode * update);

extern void cib_post_notify(int options, const char *op, xmlNode * update,
                            int result, xmlNode * new_obj);

extern void cib_diff_notify(int options, const char *client, const char *call_id, const char *op,
                            xmlNode * update, int result, xmlNode * old_cib);

extern void cib_replace_notify(const char *origin, xmlNode * update, int result, xmlNode * diff);
