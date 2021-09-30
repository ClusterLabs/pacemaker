/*
 * Copyright 2010-2021 the Pacemaker project contributors
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

/**
 * \brief Create a new resource action
 *
 * \param[in] name        Name of resource
 * \param[in] standard    Resource agent standard (ocf, lsb, etc.)
 * \param[in] provider    Resource agent provider
 * \param[in] agent       Resource agent name
 * \param[in] action      action (start, stop, monitor, etc.)
 * \param[in] interval_ms How often to repeat this action (if 0, execute once)
 * \param[in] timeout     Consider action failed if it does not complete in this many milliseconds
 * \param[in] params      Action parameters
 *
 * \return NULL if not enough memory, otherwise newly allocated action instance
 *         (if its rc member is not PCMK_OCF_UNKNOWN, the action is invalid)
 *
 * \post After the call, 'params' is owned, and later free'd by the svc_action_t result
 * \note The caller is responsible for freeing the return value using
 *       services_action_free().
 */
svc_action_t *services__create_resource_action(const char *name, const char *standard,
                                      const char *provider, const char *agent,
                                      const char *action, guint interval_ms,
                                      int timeout /* ms */, GHashTable *params,
                                      enum svc_action_flags flags);

const char *services__exit_reason(svc_action_t *action);

#  ifdef __cplusplus
}
#  endif

#endif                          /* PCMK__SERVICES_INTERNAL__H */
