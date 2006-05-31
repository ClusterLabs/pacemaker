/* $Id: common.c,v 1.1 2006/05/31 14:59:12 andrew Exp $ */
/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <portability.h>
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>

#include <glib.h>

#include <status.h>
#include <common.h>

gboolean was_processing_error = FALSE;
gboolean was_processing_warning = FALSE;
gboolean was_config_error = FALSE;
gboolean was_config_warning = FALSE;

const char *
fail2text(enum action_fail_response fail)
{
	const char *result = "<unknown>";
	switch(fail)
	{
		case action_fail_ignore:
			result = "ignore";
			break;
		case action_fail_block:
			result = "block";
			break;
		case action_fail_recover:
			result = "recover";
			break;
		case action_fail_migrate:
			result = "migrate";
			break;
		case action_fail_fence:
			result = "fence";
			break;
	}
	return result;
}



enum action_tasks
text2task(const char *task) 
{
	if(safe_str_eq(task, CRMD_ACTION_STOP)) {
		return stop_rsc;
	} else if(safe_str_eq(task, CRMD_ACTION_STOPPED)) {
		return stopped_rsc;
	} else if(safe_str_eq(task, CRMD_ACTION_START)) {
		return start_rsc;
	} else if(safe_str_eq(task, CRMD_ACTION_STARTED)) {
		return started_rsc;
	} else if(safe_str_eq(task, CRM_OP_SHUTDOWN)) {
		return shutdown_crm;
	} else if(safe_str_eq(task, CRM_OP_FENCE)) {
		return stonith_node;
	} else if(safe_str_eq(task, CRMD_ACTION_MON)) {
		return monitor_rsc;
	} else if(safe_str_eq(task, CRMD_ACTION_NOTIFY)) {
		return action_notify;
	} else if(safe_str_eq(task, CRMD_ACTION_NOTIFIED)) {
		return action_notified;
	} else if(safe_str_eq(task, CRMD_ACTION_PROMOTE)) {
		return action_promote;
	} else if(safe_str_eq(task, CRMD_ACTION_DEMOTE)) {
		return action_demote;
	} else if(safe_str_eq(task, CRMD_ACTION_PROMOTED)) {
		return action_promoted;
	} else if(safe_str_eq(task, CRMD_ACTION_DEMOTED)) {
		return action_demoted;
	} else if(safe_str_eq(task, CRMD_ACTION_CANCEL)) {
		return no_action;
	} else if(safe_str_eq(task, CRMD_ACTION_DELETE)) {
		return no_action;
	} else if(safe_str_eq(task, CRMD_ACTION_STATUS)) {
		return no_action;
	} else if(safe_str_eq(task, CRM_OP_PROBED)) {
		return no_action;
	} else if(safe_str_eq(task, CRM_OP_LRM_REFRESH)) {
		return no_action;	
	} 
	pe_err("Unsupported action: %s", task);
	return no_action;
}


const char *
task2text(enum action_tasks task)
{
	const char *result = "<unknown>";
	switch(task)
	{
		case no_action:
			result = "no_action";
			break;
		case stop_rsc:
			result = CRMD_ACTION_STOP;
			break;
		case stopped_rsc:
			result = CRMD_ACTION_STOPPED;
			break;
		case start_rsc:
			result = CRMD_ACTION_START;
			break;
		case started_rsc:
			result = CRMD_ACTION_STARTED;
			break;
		case shutdown_crm:
			result = CRM_OP_SHUTDOWN;
			break;
		case stonith_node:
			result = CRM_OP_FENCE;
			break;
		case monitor_rsc:
			result = CRMD_ACTION_MON;
			break;
		case action_notify:
			result = CRMD_ACTION_NOTIFY;
			break;
		case action_notified:
			result = CRMD_ACTION_NOTIFIED;
			break;
		case action_promote:
			result = CRMD_ACTION_PROMOTE;
			break;
		case action_promoted:
			result = CRMD_ACTION_PROMOTED;
			break;
		case action_demote:
			result = CRMD_ACTION_DEMOTE;
			break;
		case action_demoted:
			result = CRMD_ACTION_DEMOTED;
			break;
	}
	
	return result;
}

const char *
role2text(enum rsc_role_e role) 
{
	CRM_CHECK(role >= RSC_ROLE_UNKNOWN, return RSC_ROLE_UNKNOWN_S);
	CRM_CHECK(role < RSC_ROLE_MAX, return RSC_ROLE_UNKNOWN_S);
	switch(role) {
		case RSC_ROLE_UNKNOWN:
			return RSC_ROLE_UNKNOWN_S;
		case RSC_ROLE_STOPPED:
			return RSC_ROLE_STOPPED_S;
		case RSC_ROLE_STARTED:
			return RSC_ROLE_STARTED_S;
		case RSC_ROLE_SLAVE:
			return RSC_ROLE_SLAVE_S;
		case RSC_ROLE_MASTER:
			return RSC_ROLE_MASTER_S;
	}
	return RSC_ROLE_UNKNOWN_S;
}

enum rsc_role_e
text2role(const char *role) 
{
	if(safe_str_eq(role, RSC_ROLE_STOPPED_S)) {
		return RSC_ROLE_STOPPED;
	} else if(safe_str_eq(role, RSC_ROLE_STARTED_S)) {
		return RSC_ROLE_STARTED;
	} else if(safe_str_eq(role, RSC_ROLE_SLAVE_S)) {
		return RSC_ROLE_SLAVE;
	} else if(safe_str_eq(role, RSC_ROLE_MASTER_S)) {
		return RSC_ROLE_MASTER;
	} else if(safe_str_eq(role, RSC_ROLE_UNKNOWN_S)) {
		return RSC_ROLE_UNKNOWN;
	}
	crm_err("Unknown role: %s", role);
	return RSC_ROLE_UNKNOWN;
}

int
merge_weights(int w1, int w2) 
{
	int result = w1 + w2;

	if(w1 <= -INFINITY || w2 <= -INFINITY) {
		if(w1 >= INFINITY || w2 >= INFINITY) {
			crm_debug_2("-INFINITY + INFINITY == -INFINITY");
		}
		return -INFINITY;

	} else if(w1 >= INFINITY || w2 >= INFINITY) {
		return INFINITY;
	}

	/* detect wrap-around */
	if(result > 0) {
		if(w1 <= 0 && w2 < 0) {
			result = -INFINITY;
		}
		
	} else if(w1 > 0 && w2 > 0) {
		result = INFINITY;
	}

	/* detect +/- INFINITY */
	if(result >= INFINITY) {
		result = INFINITY;
		
	} else if(result <= -INFINITY) {
		result = -INFINITY;
	}

	crm_debug_5("%d + %d = %d", w1, w2, result);
	return result;
}


int
char2score(const char *score) 
{
	int score_f = 0;
	
	if(score == NULL) {
		
	} else if(safe_str_eq(score, MINUS_INFINITY_S)) {
		score_f = -INFINITY;
		
	} else if(safe_str_eq(score, INFINITY_S)) {
		score_f = INFINITY;
		
	} else if(safe_str_eq(score, "+"INFINITY_S)) {
		score_f = INFINITY;
		
	} else {
		score_f = crm_parse_int(score, NULL);
		if(score_f > 0 && score_f > INFINITY) {
			score_f = INFINITY;
			
		} else if(score_f < 0 && score_f < -INFINITY) {
			score_f = -INFINITY;
		}
	}
	
	return score_f;
}


char *
score2char(int score) 
{

	if(score >= INFINITY) {
		return crm_strdup("+"INFINITY_S);

	} else if(score <= -INFINITY) {
		return crm_strdup("-"INFINITY_S);
	} 
	return crm_itoa(score);
}


void
add_hash_param(GHashTable *hash, const char *name, const char *value)
{
	CRM_CHECK(hash != NULL, return);

	crm_debug_3("adding: name=%s value=%s", crm_str(name), crm_str(value));
	if(name == NULL || value == NULL) {
		return;

	} else if(safe_str_eq(value, "#default")) {
		return;
		
	} else if(g_hash_table_lookup(hash, name) == NULL) {
		g_hash_table_insert(hash, crm_strdup(name), crm_strdup(value));
	}
}

