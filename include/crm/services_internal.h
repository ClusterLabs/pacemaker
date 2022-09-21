/*
 * Copyright 2010-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__SERVICES_INTERNAL__H
#  define PCMK__SERVICES_INTERNAL__H

#ifdef __cplusplus
extern "C" {
#endif

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

const char *services__exit_reason(svc_action_t *action);
char *services__grab_stdout(svc_action_t *action);
char *services__grab_stderr(svc_action_t *action);

void services__set_result(svc_action_t *action, int agent_status,
                          enum pcmk_exec_status exec_status,
                          const char *exit_reason);

void services__format_result(svc_action_t *action, int agent_status,
                             enum pcmk_exec_status exec_status,
                             const char *format, ...) G_GNUC_PRINTF(4, 5);

#  ifdef __cplusplus
}
#  endif

#endif                          /* PCMK__SERVICES_INTERNAL__H */
