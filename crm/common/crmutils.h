/* $Id: crmutils.h,v 1.6 2004/04/02 12:08:36 andrew Exp $ */
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
#ifndef CRM_UTILS__H
#define CRM_UTILS__H


#include <hb_api.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/GSource.h>

extern gboolean tickle_apphb_template(gpointer data);

extern void register_pid(
	const char *pid_file,
	gboolean do_fork,
	void (*shutdown)(int nsig));

extern long get_running_pid(const char *pid_file, gboolean* anypidfile);

extern int init_status(const char *pid_file, const char *client_name);

extern int init_stop(const char *pid_file);

extern gboolean register_with_ha(
	ll_cluster_t *hb_cluster, const char *client_name,
	gboolean (*dispatch_method)(int fd, gpointer user_data),
	void (*message_callback)(const struct ha_msg* msg, void* private_data),
	GDestroyNotify cleanup_method);

extern void register_with_apphb(
	const char *client_name,
	gboolean(*tickle_fn)(gpointer data));

extern char *crm_itoa(int an_int);

#endif
