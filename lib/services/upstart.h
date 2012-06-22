/* 
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
 *
 * File: upstart-dbus.c
 * Copyright (C) 2010 Senko Rasic <senko.rasic@dobarkod.hr>
 * Copyright (c) 2010 Ante Karamatic <ivoks@init.hr>
 */
#ifndef _UPSTART_DBUS_H_
#define _UPSTART_DBUS_H_

#include <glib.h>

typedef enum {
	UPSTART_JOB_START,
	UPSTART_JOB_STOP,
	UPSTART_JOB_RESTART
} UpstartJobCommand;

G_GNUC_INTERNAL gchar **upstart_get_all_jobs(void);
G_GNUC_INTERNAL gboolean upstart_job_do(const gchar *name, UpstartJobCommand cmd);
G_GNUC_INTERNAL gboolean upstart_job_is_running (const gchar *name);

#endif /* _UPSTART_DBUS_H_ */

