/*
 * Copyright 2019-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <crm/crm.h>
#include <crm/common/output_internal.h>
#include <crm/common/xml.h>

#include "crm_mon.h"

G_GNUC_PRINTF(4, 5)
static void
crm_mon_xml_begin_list(pcmk__output_t *out, const char *singular_noun, const char *plural_noun,
                       const char *format, ...) {
    va_list ap;
    const char *name = NULL;
    char *buf = NULL;
    int len;

    va_start(ap, format);
    len = vasprintf(&buf, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    if (!strcmp(buf, "Active Resources") || !strcmp(buf, "Full List of Resources") ||
        !strcmp(buf, "Inactive Resources")) {
        name = "resources";
    } else if (!strcmp(buf, "Cluster Summary")) {
        name = "summary";
    } else if (!strcmp(buf, "Failed Resource Actions")) {
        name = "failures";
    } else if (!strcmp(buf, "Fencing History")) {
        name = "fence_history";
    } else if (!strcmp(buf, "Migration Summary") || !strcmp(buf, "Operations")) {
        name = "node_history";
    } else if (!strcmp(buf, "Negative Location Constraints")) {
        name = "bans";
    } else if (!strcmp(buf, "Node Attributes")) {
        name = "node_attributes";
    } else if (!strcmp(buf, "Tickets")) {
        name = "tickets";
    } else {
        name = buf;
    }

    pcmk__output_xml_create_parent(out, name);
    free(buf);
}

pcmk__output_t *
crm_mon_mk_xml_output(char **argv) {
    pcmk__output_t *retval = pcmk__mk_xml_output(argv);

    if (retval == NULL) {
        return NULL;
    }

    retval->begin_list = crm_mon_xml_begin_list;

    return retval;
}
