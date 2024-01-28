/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include "crmcommon_private.h"

static pcmk__message_entry_t fmt_functions[] = {
    { NULL, NULL, NULL }
};

/*!
 * \internal
 * \brief Register the formatting functions for option lists
 *
 * \param[in,out] out  Output object
 */
void
pcmk__register_option_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
