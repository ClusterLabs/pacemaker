/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/curses_internal.h>
#include <crm/pengine/common.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/pe_types.h>
#include <crm/stonith-ng.h>
#include <crm/common/internal.h>
#include <crm/common/util.h>

#include "crm_mon.h"

void
blank_screen(void)
{
#if CURSES_ENABLED
    int lpc = 0;

    for (lpc = 0; lpc < LINES; lpc++) {
        move(lpc, 0);
        clrtoeol();
    }
    move(0, 0);
    refresh();
#endif
}

static int
compare_attribute(gconstpointer a, gconstpointer b)
{
    int rc;

    rc = strcmp((const char *)a, (const char *)b);

    return rc;
}

GList *
append_attr_list(GList *attr_list, char *name)
{
    int i;
    const char *filt_str[] = FILTER_STR;

    CRM_CHECK(name != NULL, return attr_list);

    /* filtering automatic attributes */
    for (i = 0; filt_str[i] != NULL; i++) {
        if (g_str_has_prefix(name, filt_str[i])) {
            return attr_list;
        }
    }

    return g_list_insert_sorted(attr_list, name, compare_attribute);
}

void
crm_mon_get_parameters(pe_resource_t *rsc, pe_working_set_t * data_set)
{
    get_rsc_attributes(rsc->parameters, rsc, NULL, data_set);
    if(rsc->children) {
        GListPtr gIter = NULL;

        for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            crm_mon_get_parameters(gIter->data, data_set);
        }
    }
}

/*!
 * \internal
 * \brief Return resource display options corresponding to command-line choices
 *
 * \return Bitmask of pe_print_options suitable for resource print functions
 */
unsigned int
get_resource_display_options(unsigned int mon_ops)
{
    int print_opts = 0;

    if (is_set(mon_ops, mon_op_print_pending)) {
        print_opts |= pe_print_pending;
    }
    if (is_set(mon_ops, mon_op_print_clone_detail)) {
        print_opts |= pe_print_clone_details|pe_print_implicit;
    }
    if (is_not_set(mon_ops, mon_op_inactive_resources)) {
        print_opts |= pe_print_clone_active;
    }
    if (is_set(mon_ops, mon_op_print_brief)) {
        print_opts |= pe_print_brief;
    }
    return print_opts;
}
