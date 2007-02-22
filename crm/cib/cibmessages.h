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
#ifndef CIB_MESSAGES__H
#define CIB_MESSAGES__H


extern crm_data_t *createCibRequest(
	gboolean isLocal, const char *operation, const char *section,
	const char *verbose, crm_data_t *data);

extern enum cib_errors 
cib_process_shutdown_req(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_default(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_quit(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_ping(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_query(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_erase(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_bump(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_replace(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_modify(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_readwrite(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_diff(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_sync(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_sync_one(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_delete(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

extern enum cib_errors cib_process_change(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer);

#endif
