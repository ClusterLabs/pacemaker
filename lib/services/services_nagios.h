/*
 * Copyright 2010-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef SERVICES_NAGIOS__H
#  define SERVICES_NAGIOS__H

G_GNUC_INTERNAL
int services__nagios_prepare(svc_action_t *op);

G_GNUC_INTERNAL
enum ocf_exitcode services__nagios2ocf(int exit_status);

G_GNUC_INTERNAL
GList *services__list_nagios_agents(void);

G_GNUC_INTERNAL
gboolean services__nagios_agent_exists(const char *agent);

G_GNUC_INTERNAL
int services__get_nagios_metadata(const char *type, char **output);

#endif
