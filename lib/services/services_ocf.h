/*
 * Copyright 2010-2011 Red Hat, Inc.
 * Later changes copyright 2012-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__SERVICES_SERVICES_OCF__H
#define PCMK__SERVICES_SERVICES_OCF__H

#include <glib.h>               // G_GNUC_INTERNAL, GList, gboolean

#include <crm/common/results.h> // enum ocf_exitcode
#include <crm/services.h>       // svc_action_t

#ifdef __cplusplus
extern "C" {
#endif

G_GNUC_INTERNAL
GList *services__list_ocf_providers(void);

G_GNUC_INTERNAL
GList *resources_os_list_ocf_agents(const char *provider);

G_GNUC_INTERNAL
gboolean services__ocf_agent_exists(const char *provider, const char *agent);

G_GNUC_INTERNAL
int services__ocf_prepare(svc_action_t *op);

G_GNUC_INTERNAL
enum ocf_exitcode services__ocf2ocf(int exit_status);

#ifdef __cplusplus
}
#endif

#endif  // PCMK__SERVICES_SERVICES_OCF__H
