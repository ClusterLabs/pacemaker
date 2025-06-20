/*
 * Copyright 2012-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__SERVICES_SYSTEMD__H
#define PCMK__SERVICES_SYSTEMD__H

#include <glib.h>
#include "crm/services.h"

#ifdef __cplusplus
extern "C" {
#endif

G_GNUC_INTERNAL GList *systemd_unit_listall(void);

G_GNUC_INTERNAL
int services__systemd_prepare(svc_action_t *op);

G_GNUC_INTERNAL
enum ocf_exitcode services__systemd2ocf(int exit_status);

G_GNUC_INTERNAL
int services__execute_systemd(svc_action_t *op);

G_GNUC_INTERNAL
bool systemd_unit_exists(const char *name);

G_GNUC_INTERNAL void systemd_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // PCMK__SERVICES_SYSTEMD__H
