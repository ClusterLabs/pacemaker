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

#include <hb_config.h>

#include <tengine.h>

extern void te_input_free(te_input_t *fsa_data);
extern te_input_t* te_input_copy(te_input_t *fsa_data);
extern te_input_t* te_input_new(enum te_data_type type, void *data);

extern te_input_t *new_input_command(HA_Message *msg, crm_data_t *xml);

extern te_input_t *new_input_complete(const char *text, crm_data_t *xml,
				      te_reason_t reason, te_fsa_input_t input);

extern te_input_t *new_input_cib(HA_Message *msg, crm_data_t *xml,
				 int call_id, int rc, void *user_data);

extern te_input_t *new_input_null(void);


const char* te_data_null_type(void);
const char* te_data_null_name(void);
void te_data_null_free(te_input_t *fsa_data);
void te_data_null_copy(te_input_t *a_copy, te_input_t *fsa_data);
const char* te_data_command_type(void);
const char* te_data_command_name(void);
void te_data_command_free(te_input_t *fsa_data);
void te_data_command_copy(te_input_t *a_copy, te_input_t *fsa_data);
const char* te_data_cib_type(void);
const char* te_data_cib_name(void);
void te_data_cib_free(te_input_t *fsa_data);
void te_data_cib_copy(te_input_t *a_copy, te_input_t *fsa_data);
const char* te_data_complete_type(void);
const char* te_data_complete_name(void);
void te_data_complete_free(te_input_t *fsa_data);
void te_data_complete_copy(te_input_t *a_copy, te_input_t *fsa_data);

GListPtr input_queue = NULL;

te_data_op_t te_ops_null = {
	te_data_null_type,
	te_data_null_name,
	te_data_null_free,
	te_data_null_copy
};

te_data_op_t te_ops_cib = {
	te_data_cib_type,
	te_data_cib_name,
	te_data_cib_free,
	te_data_cib_copy
};

te_data_op_t te_ops_complete = {
	te_data_complete_type,
	te_data_complete_name,
	te_data_complete_free,
	te_data_complete_copy
};

te_data_op_t te_ops_command = {
	te_data_command_type,
	te_data_command_name,
	te_data_command_free,
	te_data_command_copy
};


void te_input_free(te_input_t *fsa_data)
{
	if(fsa_data == NULL) {
		return;
	}
	fsa_data->ops->free(fsa_data);
	crm_free(fsa_data);
}

te_input_t* te_input_copy(te_input_t *fsa_data)
{
	te_input_t *a_copy = NULL;
	CRM_CHECK(fsa_data != NULL); if(crm_assert_failed) {return NULL;}
	crm_malloc0(a_copy, sizeof(te_input_t));
	*a_copy = *fsa_data;
	a_copy->data = NULL;
	a_copy->ops->copy(fsa_data);
}

te_input_t* te_input_new(
	te_fsa_input_t input, enum te_data_type type, void *data)
{
	static int input_id = 0;
	te_input_t *a_copy = NULL;
	crm_malloc0(a_copy, sizeof(te_input_t));
	a_copy->id = input_id++;
	a_copy->origin = origin;
	a_copy->input = input;
	a_copy->data = data;
	switch(type) {
		case te_data_cib:
			a_copy->ops = &te_ops_cib;
			break;
		case te_data_complete:
			a_copy->ops = &te_ops_complete;
			break;
		case te_data_command:
			a_copy->ops = &te_ops_command;
			break;
		case te_data_null:
			a_copy->ops = &te_ops_null;
			break;
	}
}

const char* te_data_null_type(void)
{
	return te_data_null;
}

const char* te_data_null_name(void)
{
	return "Null";
}

void te_data_null_free(te_input_t *fsa_data)
{
}

void te_data_null_copy(te_input_t *a_copy, te_input_t *fsa_data)
{
	a_copy->data = NULL;	
}

const char* te_data_command_type(void)
{
	return te_data_command;
}

const char* te_data_command_name(void)
{
	return "DC Command";
}

void te_data_command_free(te_input_t *fsa_data)
{
	struct te_data_command_s *data = fsa_data->data;
	CRM_CHECK(fsa_data->ops->type() == te_data_command);
	ha_msg_del(data->msg);
	free_xml(data->xml);
	crm_free(data);
}

void te_data_command_copy(te_input_t *a_copy, te_input_t *fsa_data)
{
	struct te_data_command_s *data = fsa_data->data;
	struct te_data_command_s *copy_data = NULL;
	CRM_CHECK(fsa_data->ops->type() == te_data_command);
	crm_malloc0(a_copy->data, sizeof(struct te_data_command_s));
	copy_data = a_copy->data;

	copy_data->msg = ha_msg_copy(data->msg);
	copy_data->xml = copy_xml(data->xml);
}

const char* te_data_cib_type(void)
{
	return te_data_cib;
}

const char* te_data_cib_name(void)
{
	return "CIB Callback";
}

void te_data_cib_free(te_input_t *fsa_data)
{
	struct te_data_cib_s *data = fsa_data->data;
	CRM_CHECK(fsa_data->ops->type() == te_data_cib);
	ha_msg_del(data->msg);
	free_xml(data->xml);
	crm_free(data);
}

void te_data_cib_copy(te_input_t *a_copy, te_input_t *fsa_data)
{
	struct te_data_cib_s *data = fsa_data->data;
	struct te_data_cib_s *copy_data = NULL;
	CRM_CHECK(fsa_data->ops->type() == te_data_cib);
	crm_malloc0(a_copy->data, sizeof(struct te_data_cib_s));
	copy_data = a_copy->data;

	*copy_data = *data;
	copy_data->msg = ha_msg_copy(data->msg);
	copy_data->xml = copy_xml(data->xml);
}

const char* te_data_complete_type(void)
{
	return te_data_complete;
}

const char* te_data_complete_name(void)
{
	return "Transition Complete";
}

void te_data_complete_free(te_input_t *fsa_data)
{
	struct te_data_complete_s *data = fsa_data->data;
	CRM_CHECK(fsa_data->ops->type() == te_data_complete);
	ha_msg_del(data->msg);
	free_xml(data->xml);
	crm_free(data);
}

void te_data_complete_copy(te_input_t *a_copy, te_input_t *fsa_data)
{
	struct te_data_complete_s *data = fsa_data->data;
	struct te_data_complete_s *copy_data = NULL;
	CRM_CHECK(fsa_data->ops->type() == te_data_complete);
	crm_malloc0(a_copy->data, sizeof(struct te_data_complete_s));
	copy_data = a_copy->data;

	*copy_data = *data;
	copy_data->xml = copy_xml(data->xml);
}

te_input_t *
new_input_command(HA_Message *msg, crm_data_t *xml)
{
	struct te_data_cib_s *copy_data = NULL;
	crm_malloc0(a_copy->data, sizeof(struct te_data_cib_s));
	copy_data = a_copy->data;
	copy_data->xml = copy_xml(xml);
	copy_data->msg = ha_msg_copy(msg);
	
	return te_input_new(te_data_command, copy_data);
}

te_input_t *
new_input_complete(const char *text, crm_data_t *xml,
		   te_reason_t reason)
{
	struct te_data_complete_s *copy_data = NULL;
	crm_malloc0(a_copy->data, sizeof(struct te_data_complete_s));
	copy_data = a_copy->data;
	copy_data->text   = text;
	copy_data->reason = reason;
	copy_data->xml    = copy_xml(xml);

	return te_input_new(te_data_complete, copy_data);
}

te_input_t *
new_input_cib(HA_Message *msg, crm_data_t *xml,
	      int call_id, int rc, void *user_data)
{
	struct te_data_cib_s *copy_data = NULL;
	crm_malloc0(a_copy->data, sizeof(struct te_data_cib_s));
	copy_data = a_copy->data;

	copy_data->rc        = rc;
	copy_data->call_id   = call_id;
	copy_data->user_data = user_data;
	copy_data->msg       = ha_msg_copy(msg);
	copy_data->xml       = copy_xml(xml);
	
	return te_input_new(te_data_cib, copy_data);
}

te_input_t *
new_input_null(const char *origin)
{
	return te_input_new(te_data_null, NULL, origin);
}

void
register_input(te_fsa_input_t input, te_input_t *input_data,
	       gboolean prepend, const char *origin) 
{
	input_data->origin = origin;
	input_data->input = input;
	crm_debug("%s raised FSA input %d (%s)",
		  origin, input_data->id, input_data->ops->name());
	
	if(prepend) {
		crm_debug_2("Prepending input");
		input_queue = g_list_prepend(input_queue, input_data);
	} else {
		input_queue = g_list_append(input_queue, input_data);
	}
	G_main_set_trigger(fsa_source);
}


void
register_input_copy(te_fsa_input_t input, te_input_t *input_data,
		    gboolean prepend, const char *origin) 
{
	te_input_t *a_copy = input_data->ops->copy(input);
	crm_debug("%s re-registering FSA input %d (%s/%s)",
		  origin, input_data->id,
		  input_data->ops->name(), input_data->origin);
	register_input(a_copy, prepend, origin);
}

te_input_t *
get_input(void)
{
	te_input_t* message = g_list_nth_data(input_queue, 0);
	input_queue = g_list_remove(input_queue, message);
	return message;
}
