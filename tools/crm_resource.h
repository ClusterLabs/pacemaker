/*
 * Copyright 2004-2022 the Pacemaker project contributors
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

#include <crm/msg_xml.h>
#include <crm/services.h>
#include <crm/common/xml.h>
#include <crm/common/mainloop.h>
#include <crm/common/output_internal.h>

#include <crm/cib.h>
#include <crm/common/attrd_internal.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <pacemaker-internal.h>

typedef struct node_info_s {
    const char *node_name;
    bool promoted;
} node_info_t;

enum resource_check_flags {
    rsc_remain_stopped  = (1 << 0),
    rsc_unpromotable    = (1 << 1),
    rsc_unmanaged       = (1 << 2),
    rsc_locked          = (1 << 3),
};

typedef struct resource_checks_s {
    pe_resource_t *rsc;     // Resource being checked
    uint32_t flags;         // Group of enum resource_check_flags
    const char *lock_node;  // Node that resource is shutdown-locked to, if any
} resource_checks_t;

resource_checks_t *cli_check_resource(pe_resource_t *rsc, char *role_s, char *managed);

/* ban */
int cli_resource_prefer(pcmk__output_t *out, const char *rsc_id, const char *host,
                        const char *move_lifetime, cib_t * cib_conn, int cib_options,
                        gboolean promoted_role_only);
int cli_resource_ban(pcmk__output_t *out, const char *rsc_id, const char *host,
                     const char *move_lifetime, GList *allnodes, cib_t * cib_conn,
                     int cib_options, gboolean promoted_role_only);
int cli_resource_clear(const char *rsc_id, const char *host, GList *allnodes,
                       cib_t * cib_conn, int cib_options, bool clear_ban_constraints, gboolean force);
int cli_resource_clear_all_expired(xmlNode *root, cib_t *cib_conn, int cib_options,
                                   const char *rsc, const char *node, gboolean promoted_role_only);

/* print */
void cli_resource_print_cts(pe_resource_t * rsc, pcmk__output_t *out);
void cli_resource_print_cts_constraints(pe_working_set_t * data_set);

int cli_resource_print(pe_resource_t *rsc, pe_working_set_t *data_set, bool expanded);
int cli_resource_print_operations(const char *rsc_id, const char *host_uname,
                                  bool active, pe_working_set_t * data_set);

/* runtime */
int cli_resource_check(pcmk__output_t *out, pe_resource_t *rsc);
int cli_resource_fail(pcmk_ipc_api_t *controld_api, const char *host_uname,
                      const char *rsc_id, pe_working_set_t *data_set);
GList *cli_resource_search(pe_resource_t *rsc, const char *requested_name,
                             pe_working_set_t *data_set);
int cli_resource_delete(pcmk_ipc_api_t *controld_api, const char *host_uname,
                        pe_resource_t *rsc, const char *operation,
                        const char *interval_spec, bool just_failures,
                        pe_working_set_t *data_set, gboolean force);
int cli_cleanup_all(pcmk_ipc_api_t *controld_api, const char *node_name,
                    const char *operation, const char *interval_spec,
                    pe_working_set_t *data_set);
int cli_resource_restart(pcmk__output_t *out, pe_resource_t *rsc, pe_node_t *node,
                         const char *move_lifetime, int timeout_ms, cib_t *cib,
                         int cib_options, gboolean promoted_role_only, gboolean force);
int cli_resource_move(pe_resource_t *rsc, const char *rsc_id, const char *host_name,
                      const char *move_lifetime, cib_t *cib, int cib_options,
                      pe_working_set_t *data_set, gboolean promoted_role_only,
                      gboolean force);
crm_exit_t cli_resource_execute_from_params(pcmk__output_t *out, const char *rsc_name,
                                            const char *rsc_class, const char *rsc_prov,
                                            const char *rsc_type, const char *rsc_action,
                                            GHashTable *params, GHashTable *override_hash,
                                            int timeout_ms, int resource_verbose,
                                            gboolean force, int check_level);
crm_exit_t cli_resource_execute(pe_resource_t *rsc, const char *requested_name,
                                const char *rsc_action, GHashTable *override_hash,
                                int timeout_ms, cib_t *cib, pe_working_set_t *data_set,
                                int resource_verbose, gboolean force, int check_level);

int cli_resource_update_attribute(pe_resource_t *rsc, const char *requested_name,
                                  const char *attr_set, const char *attr_set_type,
                                  const char *attr_id, const char *attr_name,
                                  const char *attr_value, gboolean recursive,
                                  cib_t *cib, int cib_options,
                                  pe_working_set_t *data_set, gboolean force);
int cli_resource_delete_attribute(pe_resource_t *rsc, const char *requested_name,
                                  const char *attr_set, const char *attr_set_type,
                                  const char *attr_id, const char *attr_name,
                                  cib_t *cib, int cib_options,
                                  pe_working_set_t *data_set, gboolean force);

int update_working_set_xml(pe_working_set_t *data_set, xmlNode **xml);
int wait_till_stable(pcmk__output_t *out, int timeout_ms, cib_t * cib);

bool resource_is_running_on(pe_resource_t *rsc, const char *host);

void crm_resource_register_messages(pcmk__output_t *out);
