/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef PCMK_CRMRESOURCE_CRM_RESOURCE__H
#  define PCMK_CRMRESOURCE_CRM_RESOURCE__H

#include <crm_internal.h>
#include <crm/crm.h>

#include <crm/msg_xml.h>
#include <crm/services.h>
#include <crm/common/xml.h>
#include <crm/common/mainloop.h>

#include <crm/cib.h>
#include <crm/attrd.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include "../pengine/pengine.h"
#include "fake_transition.h"

extern bool print_pending;

extern bool scope_master;
extern bool do_force;
extern bool BE_QUIET;
extern bool do_trace;

extern int cib_options;
extern int crmd_replies_needed;

extern char *move_lifetime;

extern const char *attr_set_type;

resource_t *find_rsc_or_clone(const char *rsc, pe_working_set_t * data_set);

/* ban */
int cli_resource_prefer(const char *rsc_id, const char *host, cib_t * cib_conn);
int cli_resource_ban(const char *rsc_id, const char *host, GListPtr allnodes, cib_t * cib_conn);
int cli_resource_clear(const char *rsc_id, const char *host, GListPtr allnodes, cib_t * cib_conn);

/* print */
void cli_resource_print_cts(resource_t * rsc);
void cli_resource_print_raw(resource_t * rsc);
void cli_resource_print_cts_constraints(pe_working_set_t * data_set);
void cli_resource_print_location(resource_t * rsc, const char *prefix);
void cli_resource_print_colocation(resource_t * rsc, bool dependents, bool recursive, int offset);

int cli_resource_print(const char *rsc, pe_working_set_t * data_set, bool expanded);
int cli_resource_print_list(pe_working_set_t * data_set, bool raw);
int cli_resource_print_attribute(const char *rsc, const char *attr, pe_working_set_t * data_set);
int cli_resource_print_property(const char *rsc, const char *attr, pe_working_set_t * data_set);
int cli_resource_print_operations(const char *rsc_id, const char *host_uname, bool active, pe_working_set_t * data_set);

/* runtime */
void cli_resource_check(cib_t * cib, resource_t *rsc);
int cli_resource_fail(crm_ipc_t * crmd_channel, const char *host_uname, const char *rsc_id, pe_working_set_t * data_set);
int cli_resource_search(const char *rsc, pe_working_set_t * data_set);
int cli_resource_delete(cib_t *cib_conn, crm_ipc_t * crmd_channel, const char *host_uname, resource_t * rsc, pe_working_set_t * data_set);
int cli_resource_restart(resource_t * rsc, const char *host, int timeout_ms, cib_t * cib);
int cli_resource_move(const char *rsc_id, const char *host_name, cib_t * cib, pe_working_set_t *data_set);
int cli_resource_execute(const char *rsc_id, const char *rsc_action, GHashTable *override_hash, cib_t * cib, pe_working_set_t *data_set);

int cli_resource_update_attribute(const char *rsc_id, const char *attr_set, const char *attr_id,
                                  const char *attr_name, const char *attr_value, bool recursive,
                                  cib_t * cib, pe_working_set_t * data_set);
int cli_resource_delete_attribute(const char *rsc_id, const char *attr_set, const char *attr_id,
                                  const char *attr_name, cib_t * cib, pe_working_set_t * data_set);

int update_working_set_xml(pe_working_set_t *data_set, xmlNode **xml);
int wait_till_stable(int timeout_ms, cib_t * cib);

extern xmlNode *do_calculations(pe_working_set_t * data_set, xmlNode * xml_input, crm_time_t * now);
extern void cleanup_alloc_calculations(pe_working_set_t * data_set);

#define CMD_ERR(fmt, args...) do {		\
	crm_warn(fmt, ##args);			\
	fprintf(stderr, fmt"\n", ##args);		\
    } while(0)

#endif  /* PCMK_CRMRESOURCE_CRM_RESOURCE__H */
