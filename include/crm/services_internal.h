/*
 * Copyright 2010-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_SERVICES_INTERNAL__H
#define PCMK__CRM_SERVICES_INTERNAL__H

#include <crm/services.h>       // svc_action_t

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \brief Callback function type for systemd job completion
 *
 * Applications may register a function to be called when a systemd job
 * completes. The callback's arguments are:
 *
 * \param[in] job_id    Systemd job ID
 * \param[in] bus_path  Systemd DBus path
 * \param[in] unit_name Systemd unit name
 * \param[in] result    One of:
 *                      done - job executed successfully
 *                      canceled - job was canceled before finishing
 *                      timeout - timeout was reached before job finished
 *                      failed - job failed
 *                      dependency - job depends on another job that failed
 *                      skipped - job doesn't apply to unit's current state
 * \param[in] user_data Data supplied when the callback was registered
 */
typedef void (*svc__systemd_callback_t)(int job_id, const char *bus_path,
                                        const char *unit_name, const char *result,
                                        void *user_data);

/*!
 * \brief Create a new resource action
 *
 * \param[in]     name        Name of resource
 * \param[in]     standard    Resource agent standard
 * \param[in]     provider    Resource agent provider
 * \param[in]     agent       Resource agent name
 * \param[in]     action      Name of action
 * \param[in]     interval_ms How often to repeat action (if 0, execute once)
 * \param[in]     timeout     Error if not complete within this time (ms)
 * \param[in,out] params      Action parameters
 * \param[in]     flags       Group of enum svc_action_flags
 *
 * \return NULL if not enough memory, otherwise newly allocated action instance
 *         (if its rc member is not PCMK_OCF_UNKNOWN, the action is invalid)
 *
 * \note This function assumes ownership of (and may free) \p params.
 * \note The caller is responsible for freeing the return value using
 *       services_action_free().
 */
svc_action_t *services__create_resource_action(const char *name,
                                               const char *standard,
                                               const char *provider,
                                               const char *agent,
                                               const char *action,
                                               guint interval_ms,
                                               int timeout, GHashTable *params,
                                               enum svc_action_flags flags);

void services__set_systemd_callback(svc__systemd_callback_t callback,
                                    void *user_data);

const char *services__exit_reason(const svc_action_t *action);
char *services__grab_stdout(svc_action_t *action);
char *services__grab_stderr(svc_action_t *action);

void services__set_result(svc_action_t *action, int agent_status,
                          enum pcmk_exec_status exec_status,
                          const char *exit_reason);

void services__format_result(svc_action_t *action, int agent_status,
                             enum pcmk_exec_status exec_status,
                             const char *format, ...) G_GNUC_PRINTF(4, 5);

int services__finalize_async_op(svc_action_t *op);

const char *services__systemd_unit_name(svc_action_t *action);

svc_action_t *services__systemd_get_inflight_op(const char *unit_name);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_SERVICES_INTERNAL__H
