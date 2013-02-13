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
 * Copyright (C) 2012 Andrew Beekhof <andrew@beekhof.net>
 */

G_GNUC_INTERNAL GList *systemd_unit_listall(void);
G_GNUC_INTERNAL int systemd_unit_exec(svc_action_t * op, gboolean synchronous);
G_GNUC_INTERNAL gboolean systemd_unit_exists(const gchar * name);
G_GNUC_INTERNAL gboolean systemd_unit_running(const gchar * name);
G_GNUC_INTERNAL void systemd_cleanup(void);
