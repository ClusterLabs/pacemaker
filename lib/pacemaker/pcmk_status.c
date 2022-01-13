/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stddef.h>

#include <crm/cib/internal.h>
#include <crm/common/output.h>
#include <crm/common/results.h>
#include <crm/stonith-ng.h>
#include <pacemaker.h>
#include <pacemaker-internal.h>

/* This is an internal-only function that is planned to be deprecated and removed.
 * It should only ever be called from crm_mon.
 */
int
pcmk__output_simple_status(pcmk__output_t *out, pe_working_set_t *data_set)
{
    int nodes_online = 0;
    int nodes_standby = 0;
    int nodes_maintenance = 0;
    char *offline_nodes = NULL;
    size_t offline_nodes_len = 0;
    bool no_dc = false;
    bool offline = false;
    bool has_warnings = false;

    if (data_set->dc_node == NULL) {
        has_warnings = true;
        no_dc = true;
    }

    for (GList *iter = data_set->nodes; iter != NULL; iter = iter->next) {
        pe_node_t *node = (pe_node_t *) iter->data;

        if (node->details->standby && node->details->online) {
            nodes_standby++;
        } else if (node->details->maintenance && node->details->online) {
            nodes_maintenance++;
        } else if (node->details->online) {
            nodes_online++;
        } else {
            char *s = crm_strdup_printf("offline node: %s", node->details->uname);
            /* coverity[leaked_storage] False positive */
            pcmk__add_word(&offline_nodes, &offline_nodes_len, s);
            free(s);
            has_warnings = true;
            offline = true;
        }
    }

    if (has_warnings) {
        out->info(out, "CLUSTER WARN: %s%s%s",
                  no_dc ? "No DC" : "",
                  no_dc && offline ? ", " : "",
                  (offline? offline_nodes : ""));
        free(offline_nodes);
    } else {
        char *nodes_standby_s = NULL;
        char *nodes_maint_s = NULL;

        if (nodes_standby > 0) {
            nodes_standby_s = crm_strdup_printf(", %d standby node%s", nodes_standby,
                                                pcmk__plural_s(nodes_standby));
        }

        if (nodes_maintenance > 0) {
            nodes_maint_s = crm_strdup_printf(", %d maintenance node%s",
                                              nodes_maintenance,
                                              pcmk__plural_s(nodes_maintenance));
        }

        out->info(out, "CLUSTER OK: %d node%s online%s%s, "
                       "%d resource instance%s configured",
                  nodes_online, pcmk__plural_s(nodes_online),
                  nodes_standby_s != NULL ? nodes_standby_s : "",
                  nodes_maint_s != NULL ? nodes_maint_s : "",
                  data_set->ninstances, pcmk__plural_s(data_set->ninstances));

        free(nodes_standby_s);
        free(nodes_maint_s);
    }

    if (has_warnings) {
        return pcmk_rc_error;
    } else {
        return pcmk_rc_ok;
    }
    /* coverity[leaked_storage] False positive */
}
