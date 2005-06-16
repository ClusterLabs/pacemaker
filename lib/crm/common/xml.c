/* $Id: xml.c,v 1.17 2005/06/16 12:44:30 andrew Exp $ */
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
#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h> 

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/dmalloc_wrapper.h>


void dump_array(
	int log_level, const char *message, const char **array, int depth);

int print_spaces(char *buffer, int spaces);

int log_data_element(const char *function, const char *prefix, int log_level,
		     int depth, const crm_data_t *data, gboolean formatted);

int dump_data_element(
	int depth, char **buffer, const crm_data_t *data, gboolean formatted);

crm_data_t *parse_xml(const char *input, int *offset);
int get_tag_name(const char *input);
int get_attr_name(const char *input);
int get_attr_value(const char *input);
gboolean can_prune_leaf(crm_data_t *xml_node);

void diff_filter_context(int context, int upper_bound, int lower_bound,
		    crm_data_t *xml_node, crm_data_t *parent);
int in_upper_context(int depth, int context, crm_data_t *xml_node);

crm_data_t *
find_xml_node(crm_data_t *root, const char * search_path, gboolean must_find)
{
	if(must_find || root != NULL) {
		crm_validate_data(root);
	}
	
	if(search_path == NULL) {
		crm_warn("Will never find <NULL>");
		return NULL;
	}
	
	xml_child_iter(
		root, a_child, search_path,
/* 		crm_debug_5("returning node (%s).", xmlGetNodePath(a_child)); */
		crm_log_xml_debug_5(a_child, "contents\t%s");
		crm_log_xml_debug_5(root, "found in\t%s");
		crm_validate_data(a_child);
		return a_child;
		);

	if(must_find) {
		crm_warn("Could not find %s in %s.", search_path, xmlGetNodePath(root));
	} else if(root != NULL) {
		crm_debug_3("Could not find %s in %s.", search_path, xmlGetNodePath(root));
	} else {
		crm_debug_3("Could not find %s in <NULL>.", search_path);
	}
	
	
	return NULL;
}

crm_data_t*
find_xml_node_nested(crm_data_t *root, const char **search_path, int len)
{
	int	j;
	gboolean is_found = TRUE;
	crm_data_t *match =  NULL;
	crm_data_t *lastMatch = root;

	crm_validate_data(root);
	
	if(search_path == NULL || search_path[0] == NULL) {
		crm_warn("Will never find NULL");
		return NULL;
	}
	
	dump_array(LOG_DEBUG_5, "Looking for.", search_path, len);

	for (j=0; j < len; ++j) {
		if (search_path[j] == NULL) {
/* a NULL also means stop searching */
			break;
		}

		match = find_xml_node(lastMatch, search_path[j], FALSE);
		if(match == NULL) {
			is_found = FALSE;
			break;
		} else {
			lastMatch = match;
		}
	}

	if (is_found) {
		crm_debug_5("returning node (%s).",
			   xmlGetNodePath(lastMatch));

		crm_log_xml_debug_5(lastMatch, "found\t%s");
		crm_log_xml_debug_5(root, "in \t%s");
		
		crm_validate_data(lastMatch);
		return lastMatch;
	}

	dump_array(LOG_DEBUG_2,
		   "Could not find the full path to the node you specified.",
		   search_path, len);

	crm_debug_2("Closest point was node (%s) starting from %s.",
		    xmlGetNodePath(lastMatch), crm_element_name(root));

	return NULL;
    
}



const char *
get_xml_attr_nested(crm_data_t *parent,
		    const char **node_path, int length,
		    const char *attr_name, gboolean error)
{
	const char *attr_value = NULL;
	crm_data_t *attr_parent = NULL;

	if(error || parent != NULL) {
		crm_validate_data(parent);
	}
	
	if(parent == NULL) {
		crm_debug_3("Can not find attribute %s in NULL parent",attr_name);
		return NULL;
	} 

	if(attr_name == NULL || strlen(attr_name) == 0) {
		crm_err("Can not find attribute with no name in %s",
		       xmlGetNodePath(parent));
		return NULL;
	}
	
	if(length == 0) {
		attr_parent = parent;
		
	} else {
		attr_parent = find_xml_node_nested(parent, node_path, length);
		if(attr_parent == NULL && error) {
			crm_err("No node at the path you specified.");
			return NULL;
		}
	}
	
	attr_value = crm_element_value(attr_parent, attr_name);
	if((attr_value == NULL || strlen(attr_value) == 0) && error) {
		crm_err("No value present for %s at %s",
			attr_name, xmlGetNodePath(attr_parent));
		return NULL;
	}
	
	return attr_value;
}


crm_data_t*
find_entity(crm_data_t *parent, const char *node_name, const char *id)
{
	crm_validate_data(parent);
	xml_child_iter(
		parent, a_child, node_name,
		if(id == NULL 
		   || safe_str_eq(id,crm_element_value(a_child,XML_ATTR_ID))){
			crm_debug_4("returning node (%s).", 
				  xmlGetNodePath(a_child));
			return a_child;
		}
		);
	crm_debug_3("node <%s id=%s> not found in %s.",
		    node_name, id, xmlGetNodePath(parent));
	return NULL;
}

void
copy_in_properties(crm_data_t* target, const crm_data_t *src)
{
	crm_validate_data(src);
	crm_validate_data(target);
	if(src == NULL) {
		crm_warn("No node to copy properties from");
	} else if (target == NULL) {
		crm_err("No node to copy properties into");
	} else {
		xml_prop_iter(
			src, local_prop_name, local_prop_value,
			crm_xml_add(target, local_prop_name, local_prop_value);
			);
		crm_validate_data(target);
	}
	
	return;
}

crm_data_t*
add_node_copy(crm_data_t *new_parent, const crm_data_t *xml_node)
{
	crm_data_t *node_copy = NULL;
	
	crm_validate_data(new_parent);
	crm_validate_data(xml_node);
		
	if(xml_node != NULL && new_parent != NULL) {
		const char *name = crm_element_name(xml_node);
		CRM_DEV_ASSERT(
			HA_OK == ha_msg_addstruct(new_parent, name, xml_node));
		
		node_copy = find_entity(
			new_parent, crm_element_name(xml_node), ID(xml_node));
		crm_validate_data(node_copy);
		crm_update_parents(new_parent);
		crm_validate_data(new_parent);

	} else if(xml_node == NULL) {
		crm_err("Could not add copy of NULL node");

	} else {
		crm_err("Could not add copy of node to NULL parent");
	}
	
	crm_validate_data(node_copy);
	return node_copy;
}

const char *
crm_xml_add(crm_data_t* node, const char *name, const char *value)
{
	const char *parent_name = NULL;

	if(node != NULL) {
		parent_name = crm_element_name(node);
	}
	
	crm_debug_5("[%s] Setting %s to %s", crm_str(parent_name), name, value);

	if (name == NULL || strlen(name) <= 0) {
		
	} else if(node == NULL) {
		
	} else if(parent_name == NULL && strcmp(name, F_XML_TAGNAME) != 0) {
		
	} else if (value == NULL || strlen(value) <= 0) {
		xml_remove_prop(node, name);
		return NULL;
		
	} else {
		crm_validate_data(node);
		ha_msg_mod(node, name, value);
		return crm_element_value(node, name);
	}
	
	return NULL;
}

const char *
crm_xml_add_int(crm_data_t* node, const char *name, int value)
{
	const char *parent_name = NULL;

	if(node != NULL) {
		parent_name = crm_element_name(node);
	}

	crm_debug_5("[%s] Setting %s to %d", crm_str(parent_name), name, value);

	if (name == NULL || strlen(name) <= 0) {
		
	} else if(node == NULL) {
		
	} else if(parent_name == NULL && strcmp(name, F_XML_TAGNAME) != 0) {
		
	} else {
		crm_validate_data(node);
		ha_msg_mod_int(node, name, value);
		return crm_element_value(node, name);
	}

	return NULL;
}

crm_data_t*
create_xml_node(crm_data_t *parent, const char *name)
{
	const char *local_name = NULL;
	const char *parent_name = NULL;
	crm_data_t *ret_value = NULL;
	

	if (name == NULL || strlen(name) < 1) {
		ret_value = NULL;
	} else {
		local_name = name;
		ret_value = ha_msg_new(1);
		CRM_DEV_ASSERT(ret_value != NULL);
		
		crm_xml_add(ret_value, F_XML_TAGNAME, name);
		crm_validate_data(ret_value);
		if(parent) {
			crm_validate_data(parent);
			parent_name = crm_element_name(parent);
			crm_debug_5("Attaching %s to parent %s",
				   local_name, parent_name);
			CRM_DEV_ASSERT(HA_OK == ha_msg_addstruct(
					   parent, name, ret_value));
			crm_msg_del(ret_value);

			crm_update_parents(parent);
			crm_validate_data(parent);
			ret_value = parent->values[parent->nfields-1];
			crm_validate_data(ret_value);
		}
	}

	crm_debug_5("Created node [%s [%s]]",
		  crm_str(parent_name), crm_str(local_name));
/*	set_node_tstamp(ret_value); */
	return ret_value;
}

void
free_xml_from_parent(crm_data_t *parent, crm_data_t *a_node)
{
	CRM_DEV_ASSERT(parent != NULL);
	if(parent == NULL) {
		return;
	} else if(a_node == NULL) {
		return;
	}
	crm_validate_data(parent);
	cl_msg_remove_value(parent, a_node);	
	crm_validate_data(parent);
}


void
free_xml_fn(crm_data_t *a_node)
{
        if(a_node == NULL) {
		; /*  nothing to do */
	} else {
		int has_parent = 0;
		crm_validate_data(a_node);
		ha_msg_value_int(a_node, F_XML_PARENT, &has_parent);

		/* there is no way in hell we should be deleting anything
		 * with a parent and without the parent knowning
		 */
		CRM_DEV_ASSERT(has_parent == 0);
		if(has_parent == 0) {
			crm_validate_data(a_node);
			crm_msg_del(a_node);
		}
	}
	
	return;
}

void
set_node_tstamp(crm_data_t *a_node)
{
#if 0
	char *since_epoch = NULL;
	time_t a_time = time(NULL);
	
	crm_validate_data(a_node);

	if(a_time == (time_t)-1) {
		cl_perror("set_node_tstamp(): Invalid time returned");
		return;
	}
	
	crm_malloc0(since_epoch, 128*(sizeof(char)));
	if(since_epoch != NULL) {
		sprintf(since_epoch, "%ld", (unsigned long)a_time);
		ha_msg_mod(a_node, XML_ATTR_TSTAMP, since_epoch);
		crm_validate_data(a_node);
		crm_free(since_epoch);
	}
#endif
}

crm_data_t*
copy_xml(const crm_data_t *src_node)
{
	crm_data_t *new_xml = NULL;
	
	CRM_DEV_ASSERT(src_node != NULL);
	CRM_DEV_ASSERT(crm_element_name(src_node) != NULL);

	if(src_node == NULL) {
		crm_warn("Attempt to dup NULL XML");
		return NULL;
		
	} else if(crm_element_name(src_node) == NULL) {
		crm_log_xml_err(src_node, "Attempt to dup XML with no name");
		return NULL;
	}
	
	crm_validate_data(src_node);
	new_xml = ha_msg_copy(src_node);
	crm_set_element_parent(new_xml, NULL);
	crm_update_parents(new_xml);
	crm_validate_data(new_xml);
	return new_xml;
}


crm_data_t*
string2xml(const char *input)
{
	crm_data_t *output = parse_xml(input, NULL);
	if(output != NULL) {
		crm_update_parents(output);
		crm_validate_data(output);
	}
	return output;
}

crm_data_t *
stdin2xml(void) 
{
	int lpc = 0;
	int MAX_XML_BUFFER = 20000;
	
	int ch = 0;
	gboolean more = TRUE;
	gboolean inTag = FALSE;
	FILE *input = stdin;

	char *xml_buffer = NULL;
	crm_data_t *xml_obj = NULL;

	crm_malloc0(xml_buffer, sizeof(char)*(MAX_XML_BUFFER+1));
	
	while (more && lpc < MAX_XML_BUFFER) {
		ch = fgetc(input);
/* 		crm_debug_3("Got [%c]", ch); */
		switch(ch) {
			case EOF: 
			case 0:
				ch = 0;
				more = FALSE; 
				xml_buffer[lpc++] = ch;
				break;
			case '>':
			case '<':
				inTag = TRUE;
				if(ch == '>') { inTag = FALSE; }
				xml_buffer[lpc++] = ch;
				break;
			case '\n':
			case '\t':
			case ' ':
				ch = ' ';
				if(inTag) {
					xml_buffer[lpc++] = ch;
				} 
				break;
			default:
				xml_buffer[lpc++] = ch;
				break;
		}
	}
	
	xml_buffer[MAX_XML_BUFFER] = 0;
	xml_obj = string2xml(xml_buffer);
	crm_free(xml_buffer);

	crm_log_xml_debug_3(xml_obj, "Created fragment");
	return xml_obj;
}


crm_data_t*
file2xml(FILE *input)
{
	
	char *buffer = NULL;
	crm_data_t *new_obj = NULL;
	int start = 0, length = 0, read_len = 0;
	
	/* see how big the file is */
	start  = ftell(input);
	fseek(input, 0L, SEEK_END);
	length = ftell(input);
	fseek(input, 0L, start);
	
	if(start != ftell(input)) {
		crm_err("fseek not behaving");
		return NULL;
	}

	crm_debug_3("Reading %d bytes from file", length);
	crm_malloc0(buffer, sizeof(char) * (length+1));
	read_len = fread(buffer, sizeof(char), length, input);
	if(read_len != length) {
		crm_err("Calculated and read bytes differ: %d vs. %d",
			length, read_len);
	} else  if(length > 0) {
		new_obj = string2xml(buffer);
	} else {
		crm_warn("File contained no XML");
	}
	
	crm_free(buffer);
	return new_obj;
}

void
dump_array(int log_level, const char *message, const char **array, int depth)
{
	int j;
	
	if(message != NULL) {
		do_crm_log(log_level, __FILE__, __FUNCTION__, "%s", message);
	}

	do_crm_log(log_level, __FILE__, __FUNCTION__,  "Contents of the array:");
	if(array == NULL || array[0] == NULL || depth == 0) {
		do_crm_log(log_level, __FILE__, __FUNCTION__, "\t<empty>");
		return;
	}
	
	for (j=0; j < depth && array[j] != NULL; j++) {
		if (array[j] == NULL) { break; }
		do_crm_log(log_level, __FILE__, __FUNCTION__, "\t--> (%s).", array[j]);
	}
}

int
write_xml_file(crm_data_t *xml_node, const char *filename) 
{
	int res = 0;
	char *now_str = NULL;
	time_t now;

	crm_debug_3("Writing XML out to %s", filename);
	crm_validate_data(xml_node);
	if (xml_node == NULL) {
		return -1;
	}

	crm_validate_data(xml_node);
	crm_log_xml_debug_4(xml_node, "Writing out");
	crm_validate_data(xml_node);
	
	now = time(NULL);
	now_str = ctime(&now);
	now_str[24] = EOS; /* replace the newline */
	crm_xml_add(xml_node, "last_written", now_str);
	crm_validate_data(xml_node);
	
	{
		FILE *file_output_strm = fopen(filename, "w");
		char *buffer = dump_xml_formatted(xml_node);
		CRM_DEV_ASSERT(buffer != NULL && strlen(buffer) > 0);
		if(file_output_strm == NULL) {
			res = -1;
			crm_err("Cannot write to %s", filename);
			
		} else if(buffer != NULL && strlen(buffer) > 0) {
			res = fprintf(file_output_strm, "%s", buffer);
		}
		if(file_output_strm != NULL) {
			fflush(file_output_strm);
			fclose(file_output_strm);
		}
		
		crm_free(buffer);
	}
	crm_debug_3("Saved %d bytes to the Cib as XML", res);

	return res;
}

void
print_xml_formatted(int log_level, const char *function,
		    const crm_data_t *msg, const char *text)
{
	if(msg == NULL) {
		do_crm_log(log_level,NULL,function, "%s: NULL", crm_str(text));
		return;
	}

	crm_validate_data(msg);
	do_crm_log(log_level, NULL, function, "%s:", crm_str(text));
	log_data_element(function, NULL, log_level, 0, msg, TRUE);
	return;
}

crm_data_t *
get_message_xml(const HA_Message *msg, const char *field) 
{
	crm_data_t *xml_node = NULL;
	crm_data_t *tmp_node = NULL;
	crm_validate_data(msg);
	tmp_node = cl_get_struct(msg, field);
	if(tmp_node != NULL) {
		xml_node = copy_xml(tmp_node);
	}
	return xml_node;
}

gboolean
add_message_xml(HA_Message *msg, const char *field, const crm_data_t *xml) 
{
	crm_validate_data(xml);
	crm_validate_data(msg);
	ha_msg_addstruct(msg, field, xml);
	crm_update_parents(msg);
	return TRUE;
}


char *
dump_xml_formatted(const crm_data_t *an_xml_node)
{
	char *buffer     = NULL;
#if 0
	int       len        = 0;
	xmlChar  *xml_buffer = NULL;
	xmlDocPtr foo        = NULL;

	crm_data_t* xml_node  = NULL;

	xml_node  = copy_xml(an_xml_node);
	
	if (xml_node == NULL) {
		return NULL;
		
	} else {
		/* reset the doc pointer */
		crm_debug_5("Creating doc pointer for %s", xml_node->name);
		foo = xmlNewDoc("1.0");
		xmlDocSetRootElement(foo, xml_node);
		xmlSetTreeDoc(xml_node, foo);
		crm_debug_5("Doc pointer set for %s", xml_node->name);
	}

	crm_debug_5("Initializing Parser");
	xmlInitParser();
	crm_debug_5("Dumping data");
	xmlDocDumpFormatMemory(xml_node->doc, &xml_buffer, &len, 1);
	crm_debug_5("Cleaning up parser");
	xmlCleanupParser();

	crm_debug_5("Copying memory into crm_ space");
	if(xml_buffer != NULL && len > 0) {
		/* copy the text into crm_ memory */ 
		buffer = crm_strdup(xml_buffer);
		xmlFree(xml_buffer);
	}
	crm_debug_5("Buffer coppied");
	
	free_xml(xml_node);
#else
	char *mutable_ptr = NULL;
/* 	crm_malloc0(buffer, 2*(an_xml_node->stringlen)); */
	crm_malloc0(buffer, sizeof(char)*30000);
	mutable_ptr = buffer;
	
	crm_validate_data(an_xml_node);
	CRM_DEV_ASSERT(dump_data_element(
			       0, &mutable_ptr, an_xml_node, TRUE) >= 0);
	if(crm_assert_failed) {
		crm_crit("Could not dump the whole message");
	}
	crm_debug_4("Dumped: %s", buffer);
#endif
	return buffer;
}
	
char *
dump_xml_unformatted(const crm_data_t *an_xml_node)
{
	char *buffer     = NULL;
#if 0
	int       lpc	     = 0;
	int       len        = 0;
	xmlChar  *xml_buffer = NULL;
	xmlDocPtr foo        = NULL;

	crm_data_t* xml_node  = NULL;

	xml_node  = copy_xml(an_xml_node);
	
	if (xml_node == NULL) {
		return NULL;
		
	} else {
	  /* reset the doc pointer */
		crm_debug_5("Creating doc pointer for %s", xml_node->name);
		foo = xmlNewDoc("1.0");
		xmlDocSetRootElement(foo, xml_node);
		xmlSetTreeDoc(xml_node, foo);
		crm_debug_5("Doc pointer set for %s", xml_node->name);
	}

	crm_debug_5("Initializing Parser");
	xmlInitParser();
	crm_debug_5("Dumping data");
	xmlDocDumpFormatMemory(xml_node->doc, &xml_buffer, &len, 0);
	crm_debug_5("Cleaning up parser");
	xmlCleanupParser();

	crm_debug_5("Copying memory into crm_ space");
	if(xml_buffer != NULL && len > 0) {
		/* copy the text into crm_ memory */ 
		buffer = crm_strdup(xml_buffer);
		xmlFree(xml_buffer);
	}
	crm_debug_5("Buffer coppied");
	
	free_xml(xml_node);

	/* remove <?xml version="1.0"?> and the newline	 */
/* 	for(lpc = 0; lpc < len; lpc++) { */
/* 		if(buffer[lpc] == '\n') { */
/* 			buffer[lpc] = ' '; */
/* 			break; */
/* 		} else { */
/* 			buffer[lpc] = ' '; */
/* 		} */
/* 	} */
/* 	for(lpc = len - 2; lpc > 0 && lpc < len; lpc++) { */
	for(lpc = 0; lpc < len; lpc++) {
		if(buffer[lpc] == '\n') {
			crm_debug_3("Reset newline at %d", lpc);
			buffer[lpc] = ' ';
		}
	}
	crm_debug_3("Processed %d chars for newlines", lpc);
#else
	char *mutable_ptr = NULL;
/* 	crm_malloc0(buffer, 2*(an_xml_node->stringlen)); */
	crm_malloc0(buffer, sizeof(char)*20000);
	mutable_ptr = buffer;
	
	crm_validate_data(an_xml_node);
	CRM_DEV_ASSERT(dump_data_element(
			       0, &mutable_ptr, an_xml_node, TRUE) >= 0);
	if(crm_assert_failed) {
		crm_crit("Could not dump the whole message");
	}

	crm_debug_4("Dumped: %s", buffer);
#endif
	return buffer;
}

#define update_buffer_head(buffer, len) if(len < 0) {	\
		(*buffer) = EOS; return -1;		\
	} else {					\
		buffer += len;				\
	}


int
print_spaces(char *buffer, int depth) 
{
	int lpc = 0;
	int spaces = 2*depth;
	/* <= so that we always print 1 space - prevents problems with syslog */
	for(lpc = 0; lpc <= spaces; lpc++) {
		if(sprintf(buffer, "%c", ' ') < 1) {
			return -1;
		}
		buffer += 1;
	}
	return lpc;
}

int
log_data_element(
	const char *function, const char *prefix, int log_level, int depth,
	const crm_data_t *data, gboolean formatted) 
{
	int printed = 0;
	int child_result = 0;
	int has_children = 0;
	char print_buffer[1000];
	char *buffer = print_buffer;
	const char *name = crm_element_name(data);

	crm_debug_5("Dumping %s...", name);
	crm_validate_data(data);
	if(data == NULL) {
		crm_warn("No data to dump as XML");
		return 0;

	} else if(name == NULL && depth == 0) {
		xml_child_iter(
			data, a_child, NULL,
			child_result = log_data_element(
				function, prefix, log_level, depth, a_child, formatted);
			if(child_result < 0) {
				return child_result;
			}
			);
		return 0;

	} else if(name == NULL) {
		crm_err("Cannot dump NULL element at depth %d", depth);
		return -1;
	}
	
	if(formatted) {
		printed = print_spaces(buffer, depth);
		update_buffer_head(buffer, printed);
	}
	
	printed = sprintf(buffer, "<%s", name);
	update_buffer_head(buffer, printed);

	xml_prop_iter(
		data, prop_name, prop_value,

		if(safe_str_eq(F_XML_TAGNAME, prop_name)) {
			continue;
		} else if(safe_str_eq(F_XML_PARENT, prop_name)) {
			continue;
		}
		
		crm_debug_5("Dumping <%s %s=\"%s\"...",
			  name, prop_name, prop_value);
		printed = sprintf(buffer, " %s=\"%s\"", prop_name, prop_value);
		update_buffer_head(buffer, printed);
		);

	xml_child_iter(
		data, child, NULL,
		if(child != NULL) {
			has_children++;
			break;
		}
		);

	printed = sprintf(buffer, "%s>", has_children==0?"/":"");
	update_buffer_head(buffer, printed);
	do_crm_log(log_level,  function, NULL, "%s%s",
		   prefix?prefix:"", print_buffer);
	buffer = print_buffer;
	
	if(has_children == 0) {
		return 0;
	}
	
	xml_child_iter(
		data, a_child, NULL,
		child_result = log_data_element(
			function, prefix, log_level, depth+1, a_child, formatted);

		if(child_result < 0) { return -1; }
		);

	if(formatted) {
		printed = print_spaces(buffer, depth);
		update_buffer_head(buffer, printed);
	}
	do_crm_log(log_level, function, NULL, "%s%s</%s>",
		   prefix?prefix:"", print_buffer, name);
	crm_debug_5("Dumped %s...", name);

	return has_children;
}


int
dump_data_element(
	int depth, char **buffer,  const crm_data_t *data, gboolean formatted) 
{
	int printed = 0;
	int child_result = 0;
	int has_children = 0;
	const char *name = crm_element_name(data);

	crm_debug_5("Dumping %s...", name);
	crm_validate_data(data);
	if(buffer == NULL || *buffer == NULL) {
		crm_err("No buffer supplied to dump XML into");
		return -1;

	} else if(data == NULL) {
		crm_warn("No data to dump as XML");
		(*buffer)[0] = EOS;
		return 0;

	} else if(name == NULL && depth == 0) {
		xml_child_iter(
			data, a_child, NULL,
			child_result = dump_data_element(
				depth, buffer, a_child, formatted);
			if(child_result < 0) {
				return child_result;
			}
			);
		return 0;

	} else if(name == NULL) {
		crm_err("Cannot dump NULL element at depth %d", depth);
		return -1;
	}
	
	if(formatted) {
		printed = print_spaces(*buffer, depth);
		update_buffer_head(*buffer, printed);
	}
	
	printed = sprintf(*buffer, "<%s", name);
	update_buffer_head(*buffer, printed);

	xml_prop_iter(data, prop_name, prop_value,
			if(safe_str_eq(F_XML_TAGNAME, prop_name)) {
				continue;
			} else if(safe_str_eq(F_XML_PARENT, prop_name)) {
				continue;
			}
			crm_debug_5("Dumping <%s %s=\"%s\"...",
			  name, prop_name, prop_value);
			printed = sprintf(*buffer, " %s=\"%s\"", prop_name, prop_value);
			update_buffer_head(*buffer, printed);
		);
	
	xml_child_iter(
		data, child, NULL,
		if(child != NULL) {
			has_children++;
			break;
		}
		);

	printed = sprintf(*buffer, "%s>%s",
			  has_children==0?"/":"", formatted?"\n":"");
	update_buffer_head(*buffer, printed);

	if(has_children == 0) {
		return 0;
	}
	
	xml_child_iter(
		data, child, NULL,
		child_result = dump_data_element(
			depth+1, buffer, child, formatted);

		if(child_result < 0) { return -1; }
		);

	if(formatted) {
		printed = print_spaces(*buffer, depth);
		update_buffer_head(*buffer, printed);
	}
	printed = sprintf(*buffer, "</%s>%s", name, formatted?"\n":"");
	update_buffer_head(*buffer, printed);
	crm_debug_5("Dumped %s...", name);

	return has_children;
}

gboolean
xml_has_children(crm_data_t *xml_root)
{
	crm_validate_data(xml_root);

	xml_child_iter(
		xml_root, a_child, NULL,
		return TRUE;
		);
	return FALSE;
}


void
crm_validate_data(const crm_data_t *xml_root)
{
#ifndef XML_PARANOIA_CHECKS
	CRM_DEV_ASSERT(xml_root != NULL);
#else
	int lpc = 0;
	CRM_ASSERT(xml_root != NULL);
	CRM_ASSERT(crm_is_allocated(xml_root) == 1);
	CRM_ASSERT(xml_root->nfields < 500);
	
	for (lpc = 0; lpc < xml_root->nfields; lpc++) {
		void *child = xml_root->values[lpc];
		CRM_ASSERT(crm_is_allocated(xml_root->names[lpc]) == 1);

		if(child == NULL) {
			
		} else if(xml_root->types[lpc] == FT_STRUCT) {
			crm_validate_data(child);
			
		} else if(xml_root->types[lpc] == FT_STRING) {
			CRM_ASSERT(crm_is_allocated(child) == 1);
/* 		} else { */
/* 			CRM_DEV_ASSERT(FALSE); */
		}
	}
#endif
}


void
crm_set_element_parent(crm_data_t *data, crm_data_t *parent)
{
	crm_validate_data(data);
	if(parent != NULL) {
		ha_msg_mod_int(data, F_XML_PARENT, 1);
		
	} else {
		ha_msg_mod_int(data, F_XML_PARENT, 0);
	}
}

const char *
crm_element_value(const crm_data_t *data, const char *name)
{
	const char *value = NULL;
	crm_validate_data(data);
	value = cl_get_string(data, name);
	if(value != NULL) {
		CRM_DEV_ASSERT(crm_is_allocated(value) == 1);
	}
	return value;
}

char *
crm_element_value_copy(const crm_data_t *data, const char *name)
{
	const char *value = NULL;
	char *value_copy = NULL;
	crm_validate_data(data);
	value = cl_get_string(data, name);
	if(value != NULL) {
		CRM_DEV_ASSERT(crm_is_allocated(value) == 1);
	}
 	CRM_DEV_ASSERT(value != NULL);
	if(value != NULL) {
		value_copy = crm_strdup(value);
	}
	return value_copy;
}

const char *
crm_element_name(const crm_data_t *data)
{
	crm_validate_data(data);
	return cl_get_string(data, F_XML_TAGNAME);
}

void
xml_remove_prop(crm_data_t *obj, const char *name)
{
	if(crm_element_value(obj, name) != NULL) {
		cl_msg_remove(obj, name);
	}
}

void
crm_update_parents(crm_data_t *xml_root)
{
	crm_validate_data(xml_root);
	xml_child_iter(
		xml_root, a_child, NULL,
		crm_set_element_parent(a_child, xml_root);
		crm_update_parents(a_child);
		);
}



int
get_tag_name(const char *input) 
{
	int lpc = 0;
	char ch = 0;
	const char *error = NULL;
	gboolean do_special = FALSE;
	
	for(lpc = 0; error == NULL && lpc < (ssize_t)strlen(input); lpc++) {
		ch = input[lpc];
		crm_debug_5("Processing char %c [%d]", ch, lpc);

		switch(ch) {
			case 0:
				error = "unexpected EOS";
				break;
			case '?':
				if(lpc == 0) {
					/* weird xml tag that we dont care about */
					do_special = TRUE;
				} else {
					return lpc;
				}
				break;
			case '/':
			case '>':
			case '\t':
			case '\n':
			case ' ':
				if(!do_special) {
					return lpc;
				}
				break;
			default:
				if(do_special) {

				} else if('a' <= ch && ch <= 'z') {
				} else if('A' <= ch && ch <= 'Z') {
				} else if(ch == '_') {
				} else if(ch == '-') {
				} else {
					error = "bad character, not in [a-zA-Z_-]";
				}
 				break;
		}
	}
	crm_err("Error parsing token near %.15s: %s", input, crm_str(error));
	return -1;
}

int
get_attr_name(const char *input) 
{
	int lpc = 0;
	char ch = 0;
	const char *error = NULL;
	
	for(lpc = 0; error == NULL && lpc < (ssize_t)strlen(input); lpc++) {
		ch = input[lpc];
		crm_debug_5("Processing char %c[%d]", ch, lpc);

		switch(ch) {
			case 0:
				error = "unexpected EOS";
 				break;
			case '\t':
			case '\n':
			case ' ':
				error = "unexpected whitespace";
 				break;
			case '=':
				return lpc;
			default:
				if('a' <= ch && ch <= 'z') {
				} else if('A' <= ch && ch <= 'Z') {
				} else if(ch == '_') {
				} else if(ch == '-') {
				} else {
					error = "bad character, not in [a-zA-Z_-]";
				}
 				break;
		}
	}
	crm_err("Error parsing token near %.15s: %s", input, crm_str(error));
	return -1;
}

int
get_attr_value(const char *input) 
{
	int lpc = 0;
	char ch = 0;
	const char *error = NULL;
	
	for(lpc = 0; error == NULL && lpc < (ssize_t)strlen(input); lpc++) {
		ch = input[lpc];
		crm_debug_5("Processing char %c [%d]", ch, lpc);
		
		switch(ch) {
			case 0:
				error = "unexpected EOS";
 				break;
			case '\\':
				if(input[lpc+1] == '"') {
					/* skip over the next char */ 
					lpc++;
					break;
				}
				/*fall through*/
			case '"':
				return lpc;
			default:
 				break;
		}
	}
	crm_err("Error parsing token near %.15s: %s", input, crm_str(error));
	return -1;
}


crm_data_t*
parse_xml(const char *input, int *offset)
{
	int len = 0, lpc = 0;
	char ch = 0;
	char *tag_name = NULL;
	char *attr_name = NULL;
	char *attr_value = NULL;
	gboolean more = TRUE;
	const char *error = NULL;
	const char *our_input = input;
	crm_data_t *new_obj = NULL;

	if(input == NULL) {
		return NULL;
	}
	if(offset != NULL) {
		our_input = input + (*offset);
	}

	len = strlen(our_input);
	while(lpc < len) {
		if(our_input[lpc] != '<') {

		} else if(our_input[lpc+1] == '!') {
			crm_warn("XML Comments are not supported");
			crm_debug_5("Skipping char %c", our_input[lpc]);
			lpc++;
			
		} else if(our_input[lpc+1] == '?') {
			crm_debug_5("Skipping char %c", our_input[lpc]);
			lpc++;
		} else {
			lpc++;
			our_input += lpc;
			break;
		}
		crm_debug_5("Skipping char %c", our_input[lpc]);
		lpc++;
	}
	
	len = get_tag_name(our_input);
	if(len < 0) {
		return NULL;
	}
	crm_malloc0(tag_name, len+1);
	strncpy(tag_name, our_input, len+1);
	tag_name[len] = EOS;
	crm_debug_4("Processing tag %s", tag_name);
	
	new_obj = ha_msg_new(1);
	CRM_DEV_ASSERT(crm_is_allocated(new_obj) == 1);
	
	ha_msg_add(new_obj, F_XML_TAGNAME, tag_name);
	lpc = len;

	for(; more && error == NULL && lpc < (ssize_t)strlen(input); lpc++) {
			ch = our_input[lpc];
			crm_debug_5("Processing char %c[%d]", ch, lpc);
			switch(ch) {
				case 0:
					error = "unexpected EOS";
					break;
				case '/':
					if(our_input[lpc+1] == '>') {
						more = FALSE;
					}
					break;
				case '<':
					if(our_input[lpc+1] != '/') {
						crm_data_t *child = NULL;
						crm_debug_4("Start parsing child...");
						child = parse_xml(our_input, &lpc);
						if(child == NULL) {
							error = "error parsing child";
						} else {
							CRM_DEV_ASSERT(crm_is_allocated(child) == 1);
							ha_msg_addstruct(
								new_obj, crm_element_name(child), child);
							
							crm_debug_4("Finished parsing child: %s",
								  crm_element_name(child));
							ha_msg_del(child);
/* 							lpc++; /\* > *\/ */
						}

					} else {
						lpc += 2; /* </ */
						len = get_tag_name(our_input+lpc);
						if(len < 0) {
							error = "couldnt find tag";
						} else if(strncmp(our_input+lpc, tag_name, len) == 0) {
							more = FALSE;
							lpc += len;
/* 							lpc++; /\* > *\/ */
							if(our_input[lpc] != '>') {
								error = "clase tag cannot contain attrs";
							}
							crm_debug_4("Finished parsing ourselves: %s",
								  crm_element_name(new_obj));
							
						} else {
							error = "Mismatching close tag";
							crm_err("Expected: %s", tag_name);
						}
					}
					break;
				case '=':
					lpc++; /* = */
					/*fall through*/
				case '"':
					lpc++; /* " */
					len = get_attr_value(our_input+lpc);
					if(len < 0) {
						error = "couldnt find attr_value";
					} else {
						crm_malloc0(attr_value, len+1);
						strncpy(attr_value, our_input+lpc, len+1);
						attr_value[len] = EOS;
						lpc += len;
/* 						lpc++; /\* " *\/ */

						crm_debug_4("creating nvpair: <%s %s=\"%s\"...",
							  tag_name,
							  crm_str(attr_name),
							  crm_str(attr_value));
						
						ha_msg_add(new_obj, attr_name, attr_value);
						crm_free(attr_name);
						crm_free(attr_value);
					}
					break;
				case '>':
				case ' ':
				case '\t':
				case '\n':
					break;
				default:
					len = get_attr_name(our_input+lpc);
					if(len < 0) {
						error = "couldnt find attr_name";
					} else {
						crm_malloc0(attr_name, len+1);
						strncpy(attr_name, our_input+lpc, len+1);
						attr_name[len] = EOS;
						lpc += len;
						crm_debug_4("found attr name: %s", attr_name);
						lpc--; /* make sure the '=' is seen next time around */
					}
					break;
			}
	}
	
	if(error) {
		crm_err("Error parsing token: %s", error);
		crm_err("Error at or before: %s", our_input+lpc-3);
		return NULL;
	}
	
	crm_debug_4("Finished processing %s tag", tag_name);
	crm_free(tag_name);
	if(offset != NULL) {
		(*offset) += lpc;
	}
	
	CRM_DEV_ASSERT(crm_is_allocated(new_obj) == 1);
	return new_obj;
}

void
log_xml_diff(int log_level, crm_data_t *diff, const char *function)
{
	crm_data_t *added = find_xml_node(diff, "diff-added", FALSE);
	crm_data_t *removed = find_xml_node(diff, "diff-removed", FALSE);
	gboolean is_first = TRUE;
	
	xml_child_iter(
		removed, child, NULL,
		log_data_element(function, "-", log_level, 0, child, TRUE);
		if(is_first) {
			is_first = FALSE;
		} else {
			crm_log_maybe(log_level, " --- ");
		}
		
		);
/* 	crm_log_maybe(log_level, " === "); */

	is_first = TRUE;
	xml_child_iter(
		added, child, NULL,
		log_data_element(function, "+", log_level, 0, child, TRUE);
		if(is_first) {
			is_first = FALSE;
		} else {
			crm_log_maybe(log_level, " --- ");
		}
		);
}

gboolean
apply_xml_diff(crm_data_t *old, crm_data_t *diff, crm_data_t **new)
{
	gboolean result = TRUE;
	crm_data_t *added = find_xml_node(diff, "diff-added", FALSE);
	crm_data_t *removed = find_xml_node(diff, "diff-removed", FALSE);

	crm_data_t *intermediate = NULL;
	crm_data_t *diff_of_diff = NULL;

	int root_nodes_seen = 0;

	CRM_DEV_ASSERT(new != NULL);
	if(crm_assert_failed) { return FALSE; }

	crm_debug_2("Substraction Phase");
	xml_child_iter(removed, child_diff, NULL,
		       CRM_DEV_ASSERT(root_nodes_seen == 0);
		       if(root_nodes_seen == 0) {
			       *new = subtract_xml_object(old, child_diff, FALSE);
		       }
		       root_nodes_seen++;
		);
	if(root_nodes_seen == 0) {
		*new = copy_xml(old);
		
	} else if(root_nodes_seen > 1) {
		crm_err("(-) Diffs cannot contain more than one change set..."
			" saw %d", root_nodes_seen);
		result = FALSE;
	}

	root_nodes_seen = 0;
	crm_debug_2("Addition Phase");
	if(result) {
		xml_child_iter(added, child_diff, NULL,
			       CRM_DEV_ASSERT(root_nodes_seen == 0);
			       if(root_nodes_seen == 0) {
				       add_xml_object(NULL, *new, child_diff);
			       }
			       root_nodes_seen++;
			);
	}
	if(root_nodes_seen > 1) {
		crm_err("(+) Diffs cannot contain more than one change set..."
			" saw %d", root_nodes_seen);
		result = FALSE;

#if CRM_DEV_BUILD
	} else if(result) {
		crm_debug_2("Verification Phase");
		intermediate = diff_xml_object(old, *new, FALSE);
		diff_of_diff = diff_xml_object(intermediate, diff, TRUE);
		if(diff_of_diff != NULL) {
			crm_warn("Diff application failed!");
/* 			log_xml_diff(LOG_DEBUG, diff_of_diff, "diff:diff_of_diff"); */
			log_xml_diff(LOG_DEBUG, intermediate, "diff:actual_diff");
			result = FALSE;
		}
		crm_free(diff_of_diff);
		crm_free(intermediate);
#endif
		diff_of_diff = NULL;
		intermediate = NULL;
	}

	if(result == FALSE) {
		log_xml_diff(LOG_DEBUG, diff, "diff:input_diff");

		log_data_element("diff:input", NULL, LOG_DEBUG_2, 0, old, TRUE);
/* 		CRM_DEV_ASSERT(diff_of_diff != NULL); */
		result = FALSE;
	}

	return result;
}


crm_data_t *
diff_xml_object(crm_data_t *old, crm_data_t *new, gboolean suppress)
{
	crm_data_t *diff = NULL;
	crm_data_t *tmp1 = NULL;
	crm_data_t *added = NULL;
	crm_data_t *removed = NULL;
	
	tmp1 = subtract_xml_object(old, new, suppress);
	if(tmp1 != NULL) {
		diff = create_xml_node(NULL, "diff");
		if(can_prune_leaf(tmp1)) {
			ha_msg_del(tmp1);
			tmp1 = NULL;
		} else {
			removed = create_xml_node(diff, "diff-removed");
			added = create_xml_node(diff, "diff-added");
			add_node_copy(removed, tmp1);
		}
		free_xml(tmp1);
	}
	
	tmp1 = subtract_xml_object(new, old, suppress);
	if(tmp1 != NULL) {
		if(diff == NULL) {
			diff = create_xml_node(NULL, "diff");
		}
		if(can_prune_leaf(tmp1)) {
			ha_msg_del(tmp1);
			tmp1 = NULL;

		} else {
			if(removed == NULL) {
				removed = create_xml_node(diff, "diff-removed");
			}
			if(added == NULL) {
				added = create_xml_node(diff, "diff-added");
			}
			add_node_copy(added, tmp1);
		}
		free_xml(tmp1);
	}

	return diff;
}

gboolean
can_prune_leaf(crm_data_t *xml_node)
{
	gboolean can_prune = TRUE;
/* 	return FALSE; */
	
	xml_prop_iter(xml_node, prop_name, prop_value,
		      if(safe_str_eq(prop_name, XML_ATTR_ID)) {
			      continue;
		      } else if(safe_str_eq(prop_name, XML_ATTR_TSTAMP)) {
			      continue;
		      }		      
		      can_prune = FALSE;
		);
	xml_child_iter(xml_node, child, NULL,
		       if(can_prune_leaf(child)) {
			       cl_msg_remove_value(xml_node, child);
			       __counter--;
		       } else {
			       can_prune = FALSE;
		       }
		);
	return can_prune;
}


void
diff_filter_context(int context, int upper_bound, int lower_bound,
		    crm_data_t *xml_node, crm_data_t *parent) 
{
	crm_data_t *us = NULL;
	crm_data_t *new_parent = parent;
	const char *name = crm_element_name(xml_node);

	CRM_DEV_ASSERT(xml_node != NULL && name != NULL);
	if(crm_assert_failed) { return; }
	
	us = create_xml_node(parent, name);
	xml_prop_iter(xml_node, prop_name, prop_value,
		      lower_bound = context;
		      crm_xml_add(us, prop_name, prop_value);
		);
	if(lower_bound >= 0 || upper_bound >= 0) {
		crm_xml_add(us, XML_ATTR_ID, ID(xml_node));
		new_parent = us;

	} else {
		upper_bound = in_upper_context(0, context, xml_node);
		if(upper_bound >= 0) {
			crm_xml_add(us, XML_ATTR_ID, ID(xml_node));
			new_parent = us;
		} else {
			free_xml(us);
			us = NULL;
		}
	}

	xml_child_iter(us, child, NULL,
		       diff_filter_context(
			       context, upper_bound-1, lower_bound-1,
			       child, new_parent);
		);
}

int
in_upper_context(int depth, int context, crm_data_t *xml_node)
{
	gboolean has_attributes = FALSE;
	if(context == 0) {
		return 0;
	}
	
	xml_prop_iter(xml_node, prop_name, prop_value,
		      has_attributes = TRUE;
		      break;
		);
	
	if(has_attributes) {
		return depth;

	} else if(depth < context) {
		xml_child_iter(xml_node, child, NULL,
			       if(in_upper_context(depth+1, context, child)) {
				       return depth;
			       }
			);
	}
	return 0;       
}


crm_data_t *
subtract_xml_object(crm_data_t *left, crm_data_t *right, gboolean suppress)
{
	gboolean skip = FALSE;
	gboolean differences = FALSE;
	crm_data_t *diff = NULL;
	crm_data_t *child_diff = NULL;
	crm_data_t *right_child = NULL;
	const char *right_val = NULL;
	const char *name = NULL;

	int lpc = 0;
	const char *filter[] = {
		XML_ATTR_TSTAMP,
		"last_written",
		"debug_source",
		"origin"
	};

	if(left == NULL) {
		return NULL;
	} else if(right == NULL) {
		crm_debug_2("Processing <%s id=%s> (complete copy)",
			    crm_element_name(left), ID(left));
		return copy_xml(left);
	}
	
	name = crm_element_name(left);

	/* sanity check */
	CRM_DEV_ASSERT(name != NULL);
	if(crm_assert_failed) { return NULL; }

	CRM_DEV_ASSERT(safe_str_eq(crm_element_name(left),
				   crm_element_name(right)));
	if(crm_assert_failed) { return NULL; }
	
	CRM_DEV_ASSERT(safe_str_eq(ID(left), ID(right)));
	if(crm_assert_failed) { return NULL; }
	
	diff = create_xml_node(NULL, name);

	/* changes to name/value pairs */
	crm_debug_2("Processing <%s id=%s>", crm_str(name), ID(left));

	xml_prop_iter(left, prop_name, left_value,
		      skip = FALSE;
		      if(safe_str_eq(prop_name, XML_ATTR_ID)) {
			      skip = TRUE;
		      }
		      for(lpc = 0;
			  skip == FALSE && suppress && lpc < DIMOF(filter);
			  lpc++) {
			      if(safe_str_eq(prop_name, filter[lpc])) {
				      skip = TRUE;
			      }
		      }
		      
		      if(skip) { continue; }
		      
		      right_val = crm_element_value(right, prop_name);
		      if(right_val == NULL) {
			      differences = TRUE;
			      crm_xml_add(diff, prop_name, left_value);
			      crm_debug_3("\t%s: %s", crm_str(prop_name),
					  crm_str(left_value));
				      
		      } else if(safe_str_eq(left_value, right_val)) {
			      crm_debug_2("\t%s: %s (removed)",
					  crm_str(prop_name),
					  crm_str(left_value));
		      } else {
			      differences = TRUE;
			      crm_xml_add(diff, prop_name, left_value);
			      crm_debug_2("\t%s: %s->%s",
					  crm_str(prop_name),
					  crm_str(left_value),
					  right_val);
		      }
		);

	/* changes to child objects */
	xml_child_iter(
		left, left_child, NULL, 
		right_child = find_entity(
			right, crm_element_name(left_child), ID(left_child));
		child_diff = subtract_xml_object(
			left_child, right_child, suppress);
		if(child_diff != NULL) {
			differences = TRUE;
			add_node_copy(diff, child_diff);
			free_xml(child_diff);
		}
		);
	
	if(differences == FALSE) {
		free_xml(diff);
		crm_debug_2("\tNo changes");
		return NULL;
	}
	crm_xml_add(diff, XML_ATTR_ID, ID(left));
	return diff;
}

int
add_xml_object(crm_data_t *parent, crm_data_t *target, const crm_data_t *update)
{
	const char *object_id = NULL;
	const char *object_name = NULL;
	const char *right_val = NULL;
	
	int result = 0;

	CRM_DEV_ASSERT(update != NULL);
	if(crm_assert_failed) { return 0; }

	object_name = crm_element_name(update);
	object_id = ID(update);

	CRM_DEV_ASSERT(object_name != NULL);
	if(crm_assert_failed) { return 0; }
	
	if(target == NULL && object_id == NULL) {
		/*  placeholder object */
		target = find_xml_node(parent, object_name, FALSE);

	} else if(target == NULL) {
		target = find_entity(parent, object_name, object_id);
	}

	if(target == NULL) {
		target = add_node_copy(parent, update);
		crm_debug_2("Added  <%s id=%s>",
			    crm_str(object_name), crm_str(object_id));
		CRM_DEV_ASSERT(target != NULL);
		return 0;
		
	} 

	crm_debug_2("Found node <%s id=%s> to update",
		    crm_str(object_name), crm_str(object_id));
	
	xml_prop_iter(update, prop_name, left_value,
		      right_val = crm_element_value(target, prop_name);
		      if(right_val == NULL) {
			      crm_xml_add(target, prop_name, left_value);
			      crm_debug_2("\t%s: %s (added)",
					  crm_str(prop_name),
					  crm_str(left_value));
			      
		      } else if(safe_str_neq(left_value, right_val)) {
			      crm_xml_add(target, prop_name, left_value);
			      crm_debug_2("\t%s: %s->%s",
					  crm_str(prop_name),
					  crm_str(left_value),
					  right_val);
		      }
		);

	CRM_DEV_ASSERT(cl_is_allocated(object_name));
	if(object_id != NULL) {
		CRM_DEV_ASSERT(cl_is_allocated(object_id));
	}	

	crm_debug_3("Processing children of <%s id=%s>",
		    crm_str(object_name), crm_str(object_id));
	
	xml_child_iter(
		update, a_child, NULL, 
		int tmp_result = 0;
		crm_debug_3("Updating child <%s id=%s>",
			    crm_element_name(a_child), ID(a_child));
		
		tmp_result = add_xml_object(target, NULL, a_child);
		
		if(tmp_result < 0) {
			crm_err("Error updating child <%s id=%s>",
				crm_element_name(a_child), ID(a_child));
			
			/*  only the first error is likely to be interesting */
			if(result >= 0) {
				result = tmp_result;
			}
		}
		);

	crm_debug_3("Finished with <%s id=%s>",
		    crm_str(object_name), crm_str(object_id));
	return result;
}


gboolean
delete_xml_child(crm_data_t *parent, crm_data_t *child, crm_data_t *to_delete)
{
	gboolean can_delete = FALSE;
	const char *right_val = NULL;
	
	CRM_DEV_ASSERT(child != NULL);
	if(crm_assert_failed) { return FALSE; }
	
	CRM_DEV_ASSERT(to_delete != NULL);
	if(crm_assert_failed) { return FALSE; }
	
	if(safe_str_eq(crm_element_name(to_delete), crm_element_name(child))) {
		can_delete = TRUE;
	}
	xml_prop_iter(to_delete, prop_name, left_value,
		      if(can_delete == FALSE) {
			      break;
		      }
		      right_val = crm_element_value(child, prop_name);
		      if(safe_str_neq(left_value, right_val)) {
			      can_delete = FALSE;
		      }
		);
	
	if(can_delete && parent != NULL) {
		crm_log_xml_debug(child, "Delete match found...");
		cl_msg_remove_value(parent, child);
		
	} else if(can_delete) {
		crm_log_xml_debug(child, "Cannot delete the search root");
	}
	
	
	xml_child_iter(
		child, child_of_child, NULL,
		/* only delete the first one */
		if(can_delete) {
			break;
		}
		can_delete = delete_xml_child(child, child_of_child, to_delete);
		);
	
	return can_delete;
}
