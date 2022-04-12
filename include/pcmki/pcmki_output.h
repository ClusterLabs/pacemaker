/*
 * Copyright 2019-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMK__PCMKI_PCMKI_OUTPUT__H
#  define PCMK__PCMKI_PCMKI_OUTPUT__H

#  include <libxml/tree.h>
#  include <crm/common/output_internal.h>

#ifdef __cplusplus
extern "C" {
#endif

/* This function registers only the formatted output messages that are a part
 * of libpacemaker.  It is not to be confused with pcmk__register_messages,
 * which is a part of formatted output support and registers a whole table of
 * messages at a time.
 */
void pcmk__register_lib_messages(pcmk__output_t *out);

int pcmk__cluster_status_text(pcmk__output_t *out, va_list args);

#ifdef __cplusplus
}
#endif

#endif
