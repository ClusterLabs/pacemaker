/*
 * Copyright 2018-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__FENCING_PRIVATE__H
#  define PCMK__FENCING_PRIVATE__H

G_GNUC_INTERNAL
int stonith__execute(stonith_action_t *action);

// Utilities from st_rhcs.c

G_GNUC_INTERNAL
int stonith__list_rhcs_agents(stonith_key_value_t **devices);

G_GNUC_INTERNAL
int stonith__rhcs_metadata(const char *agent, int timeout, char **output);

G_GNUC_INTERNAL
bool stonith__agent_is_rhcs(const char *agent);

G_GNUC_INTERNAL
int stonith__rhcs_validate(stonith_t *st, int call_options, const char *target,
                           const char *agent, GHashTable *params,
                           const char *host_arg, int timeout,
                           char **output, char **error_output);

#ifdef HAVE_STONITH_STONITH_H
// Utilities from st_lha.c

G_GNUC_INTERNAL
int stonith__list_lha_agents(stonith_key_value_t **devices);

G_GNUC_INTERNAL
int stonith__lha_metadata(const char *agent, int timeout, char **output);

G_GNUC_INTERNAL
bool stonith__agent_is_lha(const char *agent);

G_GNUC_INTERNAL
int stonith__lha_validate(stonith_t *st, int call_options, const char *target,
                          const char *agent, GHashTable *params,
                          int timeout, char **output, char **error_output);
#endif

#endif  // PCMK__FENCING_PRIVATE__H
