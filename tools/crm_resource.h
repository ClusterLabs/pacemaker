/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>
#include <stdbool.h>

#include <crm/crm.h>

#include <crm/services.h>
#include <crm/common/xml.h>
#include <crm/common/mainloop.h>
#include <crm/common/output_internal.h>
#include <crm/common/scheduler_internal.h>

#include <crm/cib.h>
#include <crm/common/attrs_internal.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <pacemaker-internal.h>

#define ATTR_SET_ELEMENT "attr_set_element"

typedef struct node_info_s {
    const char *node_name;
    bool promoted;
} node_info_t;

typedef struct {
    char *attr_set_type;
    char *attr_set_id;
    char *attr_name;
    char *attr_value;
    char *given_rsc_id;
    char *found_attr_id;
    pcmk_resource_t *rsc;
} attr_update_data_t;

enum resource_check_flags {
    rsc_remain_stopped  = (1 << 0),
    rsc_unpromotable    = (1 << 1),
    rsc_unmanaged       = (1 << 2),
    rsc_locked          = (1 << 3),
    rsc_node_health     = (1 << 4),
};

typedef struct resource_checks_s {
    pcmk_resource_t *rsc;   // Resource being checked
    uint32_t flags;         // Group of enum resource_check_flags
    const char *lock_node;  // Node that resource is shutdown-locked to, if any
} resource_checks_t;

resource_checks_t *cli_check_resource(pcmk_resource_t *rsc, char *role_s,
                                      char *managed);

/* ban */
int cli_resource_prefer(pcmk__output_t *out, const char *rsc_id, const char *host,
                        const char *move_lifetime, cib_t * cib_conn, int cib_options,
                        gboolean promoted_role_only, const char *promoted_role);
int cli_resource_ban(pcmk__output_t *out, const char *rsc_id, const char *host,
                     const char *move_lifetime, cib_t *cib_conn, int cib_options,
                     gboolean promoted_role_only, const char *promoted_role);
int cli_resource_clear(const char *rsc_id, const char *host, GList *allnodes,
                       cib_t * cib_conn, int cib_options, bool clear_ban_constraints, gboolean force);
int cli_resource_clear_all_expired(xmlNode *root, cib_t *cib_conn, int cib_options,
                                   const char *rsc, const char *node, gboolean promoted_role_only);

/* print */
void cli_resource_print_cts(pcmk_resource_t *rsc, pcmk__output_t *out);
void cli_resource_print_cts_constraints(pcmk_scheduler_t *scheduler);

int cli_resource_print(const pcmk_resource_t *rsc, pcmk_scheduler_t *scheduler,
                       bool expanded);
int cli_resource_print_operations(const char *rsc_id, const char *host_uname,
                                  bool active, pcmk_scheduler_t *scheduler);

/* runtime */
int cli_resource_check(pcmk__output_t *out, pcmk_resource_t *rsc,
                       pcmk_node_t *node);
int cli_resource_fail(pcmk_ipc_api_t *controld_api, const char *host_uname,
                      const char *rsc_id, pcmk_scheduler_t *scheduler);
GList *cli_resource_search(pcmk_resource_t *rsc, const char *requested_name,
                             pcmk_scheduler_t *scheduler);
int cli_resource_delete(pcmk_ipc_api_t *controld_api, const char *host_uname,
                        const pcmk_resource_t *rsc, const char *operation,
                        const char *interval_spec, bool just_failures,
                        pcmk_scheduler_t *scheduler, gboolean force);
int cli_cleanup_all(pcmk_ipc_api_t *controld_api, const char *node_name,
                    const char *operation, const char *interval_spec,
                    pcmk_scheduler_t *scheduler);
int cli_resource_restart(pcmk__output_t *out, pcmk_resource_t *rsc,
                         const pcmk_node_t *node, const char *move_lifetime,
                         guint timeout_ms, cib_t *cib, int cib_options,
                         gboolean promoted_role_only, gboolean force);
int cli_resource_move(const pcmk_resource_t *rsc, const char *rsc_id,
                      const char *host_name, const char *move_lifetime,
                      cib_t *cib, int cib_options, pcmk_scheduler_t *scheduler,
                      gboolean promoted_role_only, gboolean force);
crm_exit_t cli_resource_execute_from_params(pcmk__output_t *out, const char *rsc_name,
                                            const char *rsc_class, const char *rsc_prov,
                                            const char *rsc_type, const char *rsc_action,
                                            GHashTable *params, GHashTable *override_hash,
                                            guint timeout_ms,
                                            int resource_verbose,
                                            gboolean force, int check_level);
crm_exit_t cli_resource_execute(pcmk_resource_t *rsc,
                                const char *requested_name,
                                const char *rsc_action, GHashTable *override_hash,
                                guint timeout_ms, cib_t *cib,
                                pcmk_scheduler_t *scheduler,
                                int resource_verbose, gboolean force, int check_level);

int cli_resource_update_attribute(pcmk_resource_t *rsc,
                                  const char *requested_name,
                                  const char *attr_set, const char *attr_set_type,
                                  const char *attr_id, const char *attr_name,
                                  const char *attr_value, gboolean recursive,
                                  cib_t *cib, gboolean force);
int cli_resource_delete_attribute(pcmk_resource_t *rsc,
                                  const char *requested_name,
                                  const char *attr_set, const char *attr_set_type,
                                  const char *attr_id, const char *attr_name,
                                  cib_t *cib, int cib_options, gboolean force);

int update_scheduler_input(pcmk_scheduler_t *scheduler, xmlNode **xml);
int wait_till_stable(pcmk__output_t *out, guint timeout_ms, cib_t * cib);

bool resource_is_running_on(pcmk_resource_t *rsc, const char *host);

void crm_resource_register_messages(pcmk__output_t *out);
