/*
 * Copyright 2012-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef SYSTEMD__H
#  define SYSTEMD__H

#  include <glib.h>
#  include "crm/services.h"

G_GNUC_INTERNAL GList *systemd_unit_listall(void);

G_GNUC_INTERNAL
int services__execute_systemd(svc_action_t *op);

G_GNUC_INTERNAL gboolean systemd_unit_exists(const gchar * name);
G_GNUC_INTERNAL void systemd_cleanup(void);

#endif  /* SYSTEMD__H */
