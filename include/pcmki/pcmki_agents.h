/*
 * Copyright 2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMK__PCMKI_PCMKI_AGENTS__H
#define PCMK__PCMKI_PCMKI_AGENTS__H

#include <crm/common/output_internal.h>

int pcmk__list_alternatives(pcmk__output_t *out, const char *agent_spec);
int pcmk__list_agents(pcmk__output_t *out, char *agent_spec);
int pcmk__list_providers(pcmk__output_t *out, const char *agent_spec);
int pcmk__list_standards(pcmk__output_t *out);

#endif /* PCMK__PCMKI_PCMKI_AGENTS__H */
