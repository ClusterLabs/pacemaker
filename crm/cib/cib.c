/* $Id: cib.c,v 1.19 2004/03/22 14:20:49 andrew Exp $ */
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


#include <crm/common/crm.h>

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/cl_log.h>
#include <libxml/tree.h>

#include <crm/common/xmltags.h>
#include <crm/common/xmlvalues.h>
#include <crm/common/xmlutils.h>
#include <crm/common/msgutils.h>
#include <cib.h>
#include <cibio.h>
#include <cibmessages.h>

#include <crm/dmalloc_wrapper.h>


gboolean
startCib(const char *filename)
{
	xmlNodePtr cib = readCibXmlFile(filename);
	if (initializeCib(cib)) {
		cl_log(LOG_INFO,
		       "CIB Initialization completed successfully");
	} else { 
		free_xml(cib);
		cl_log(LOG_WARNING,
		       "CIB Initialization failed, "
		       "starting with an empty default.");
		activateCibXml(createEmptyCib(), filename);
	}
	return TRUE;
}


xmlNodePtr
get_cib_copy()
{
	return copy_xml_node_recursive(get_the_CIB(), 1);
}

/*
 * The caller should never free the return value
 */
xmlNodePtr
get_object_root(const char *object_type, xmlNodePtr the_root)
{
	const char *node_stack[2];
	xmlNodePtr tmp_node = NULL;
	FNIN();
	
	node_stack[0] = XML_CIB_TAG_CONFIGURATION;
	node_stack[1] = object_type;

	if(object_type == NULL || strlen(object_type) == 0) {
		FNRET(the_root);
		/* get the whole cib */
	} else if(strcmp(object_type, XML_CIB_TAG_STATUS) == 0) {
		node_stack[0] = XML_CIB_TAG_STATUS;
		node_stack[1] = NULL;
		/* these live in a different place */
	}
	
	tmp_node = find_xml_node_nested(the_root, node_stack, 2);
	if (tmp_node == NULL) {
		cl_log(LOG_ERR,
		       "[cib] Section cib[%s[%s]] not present",
		       node_stack[0],
		       node_stack[1]);
	}
	FNRET(tmp_node);
}

FILE *msg_cib_strm = NULL;

xmlNodePtr
process_cib_request(xmlNodePtr message, gboolean auto_reply)
{
	xmlNodePtr message_copy = copy_xml_node_recursive(message, 1);

#ifdef MSG_LOG
	if(msg_cib_strm == NULL) {
		msg_cib_strm = fopen("/tmp/cib.log", "w");
	}
	fprintf(msg_cib_strm, "[Input ]\t%s\n", dump_xml_node(message, FALSE));
	fflush(msg_cib_strm);
#endif
	
	xmlNodePtr data = processCibRequest(message_copy);

	xmlNodePtr options = find_xml_node(message_copy, XML_TAG_OPTIONS);

	const char *result = xmlGetProp(options, XML_ATTR_RESULT);

	CRM_DEBUG2("[cib] operation returned result %s", result);

	set_xml_property_copy(data, XML_ATTR_RESULT, result);


	if(auto_reply) {

		xmlNodePtr reply = create_reply(message_copy, data);
		free_xml(data);
		free_xml(message_copy);

#ifdef MSG_LOG
fprintf(msg_cib_strm, "[Reply ]\t%s\n",
			dump_xml_node(reply, FALSE));
		fflush(msg_cib_strm);
#endif
		return reply;

	}
	
#ifdef MSG_LOG
	fprintf(msg_cib_strm, "[Output]\t%s\n", dump_xml_node(data, FALSE));
	fflush(msg_cib_strm);
#endif
	free_xml(message_copy);
	return data;
}

xmlNodePtr
create_cib_fragment(xmlNodePtr update, const char *section)
{
	gboolean whole_cib = FALSE;
	xmlNodePtr fragment = create_xml_node(NULL, XML_TAG_FRAGMENT);
	xmlNodePtr cib = NULL;
	char *auto_section = pluralSection(update->name);
	
	if(update == NULL) {
		cl_log(LOG_ERR, "No update to create a fragment for");
		ha_free(auto_section);
		return NULL;
		
	} else if(section == NULL) {
		section = auto_section;

	} else if(strcmp(auto_section, section) != 0) {
		cl_log(LOG_ERR,
		       "Values for update (tag=%s) and section (%s)"
		       " were not consistent", update->name, section);
		ha_free(auto_section);
		return NULL;
		
	}

	if(strcmp(section, "all")==0 && strcmp(update->name, XML_TAG_CIB)==0) {
		whole_cib = TRUE;
	}
	
	
	set_xml_property_copy(fragment, XML_ATTR_SECTION, section);

	if(whole_cib == FALSE) {
		cib = createEmptyCib();
		xmlNodePtr object_root = get_object_root(section, cib);
		xmlAddChild(object_root, update);
	} else {
		cib = update;
	}
	
	xmlAddChild(fragment, cib);
	CRM_DEBUG("Fragment created");

	ha_free(auto_section);
	return fragment;
}

/*
 * This method adds a copy of xml_response_data
 */
xmlNodePtr
create_cib_request(xmlNodePtr msg_options,
		   xmlNodePtr msg_data,
		   const char *operation)
{
	xmlNodePtr request = NULL;
	FNIN();

	if(operation != NULL) {
		if(msg_options == NULL)
			msg_options = create_xml_node(NULL, XML_TAG_OPTIONS);
		
		set_xml_property_copy(msg_options, XML_ATTR_OP, operation);
	}
	
	request = create_request(msg_options,
				 msg_data,
				 NULL,
				 CRM_SYSTEM_CIB,
				 CRM_SYSTEM_CRMD,
				 NULL,
				 NULL);
	FNRET(request);
}


char *
pluralSection(const char *a_section)
{
	char *a_section_parent = NULL;
	if (a_section == NULL) {
		a_section_parent = ha_strdup("all");

	} else if(strcmp(a_section, XML_TAG_CIB) == 0) {
		a_section_parent = ha_strdup("all");

	} else if(strcmp(a_section, "node") == 0) {
		a_section_parent = ha_strdup("nodes");

	} else if(strcmp(a_section, "state") == 0) {
		a_section_parent = ha_strdup("status");

	} else if(strcmp(a_section, "constraint") == 0) {
		a_section_parent = ha_strdup("constraints");
		
	} else if(strcmp(a_section, "resource") == 0) {
		a_section_parent = ha_strdup("resources");

	} else {
		cl_log(LOG_ERR, "Unknown section %s", a_section);
		a_section_parent = ha_strdup("all");
	}
	
	CRM_DEBUG2("Plural is %s", a_section_parent);
	return a_section_parent;
}
