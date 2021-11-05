/*
 * Copyright 2019-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMKI_OUTPUT_H
#  define PCMKI_OUTPUT_H

#ifdef __cplusplus
extern "C" {
#endif

#  include <libxml/tree.h>
#  include <crm/common/output_internal.h>

extern pcmk__supported_format_t pcmk__out_formats[];

int pcmk__out_prologue(pcmk__output_t **out, xmlNodePtr *xml);
void pcmk__out_epilogue(pcmk__output_t *out, xmlNodePtr *xml, int retval);

/* This function registers only the formatted output messages that are a part
 * of libpacemaker.  It is not to be confused with pcmk__register_messages,
 * which is a part of formatted output support and registers a whole table of
 * messages at a time.
 */
void pcmk__register_lib_messages(pcmk__output_t *out);

int pcmk__cluster_status_text(pcmk__output_t *out, va_list args);

pcmk__output_t *pcmk__new_logger(void);

#ifdef __cplusplus
}
#endif

#endif
