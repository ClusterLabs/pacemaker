/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_SCHED_ALLOCATE__H
#  define PCMK__PCMKI_PCMKI_SCHED_ALLOCATE__H

#  include <glib.h>
#  include <crm/common/xml.h>
#  include <crm/pengine/status.h>
#  include <crm/pengine/complex.h>
#  include <crm/common/xml_internal.h>
#  include <crm/pengine/internal.h>
#  include <crm/common/xml.h>
#  include <pcmki/pcmki_scheduler.h>

void pcmk__log_transition_summary(const char *filename);

#endif
