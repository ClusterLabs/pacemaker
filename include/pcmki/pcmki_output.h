/*
 * Copyright 2019 the Pacemaker project contributors
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

#  include <crm/common/output.h>
#  include <libxml/tree.h>

extern pcmk__supported_format_t pcmk__out_formats[];

int pcmk__out_prologue(pcmk__output_t **out, xmlNodePtr *xml);
void pcmk__out_epilogue(pcmk__output_t *out, xmlNodePtr *xml, int retval);

#ifdef __cplusplus
}
#endif

#endif
