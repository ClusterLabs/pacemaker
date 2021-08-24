/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__COMMON_RESULTS_INTERNAL__H
#define PCMK__COMMON_RESULTS_INTERNAL__H

#include <glib.h>               // GQuark

/* Error domains for use with g_set_error */

GQuark pcmk__rc_error_quark(void);
GQuark pcmk__exitc_error_quark(void);

#define PCMK__RC_ERROR       pcmk__rc_error_quark()
#define PCMK__EXITC_ERROR    pcmk__exitc_error_quark()

#endif // PCMK__COMMON_RESULTS_INTERNAL__H
