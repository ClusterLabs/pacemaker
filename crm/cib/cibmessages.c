/* $Id: cibmessages.c,v 1.20 2004/03/24 09:59:04 andrew Exp $ */
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
#include <time.h>

#include <crm/common/msgutils.h>
#include <crm/common/xmlutils.h>
#include <crm/cib.h>
#include <cibio.h>
#include <crm/common/xmltags.h>
#include <crm/common/xmlvalues.h>
#include <clplumbing/cl_log.h>
#include <cibprimatives.h>
#include <cibmessages.h>

#include <crm/dmalloc_wrapper.h>

xmlNodePtr createCibRequest(gboolean isLocal,
			    const char *operation,
			    const char *section,
			    const char *verbose,
			    xmlNodePtr data);

xmlNodePtr createCibAnswer(const char *crm_msg_reference,
			   const char *operation,
			   const char *section,
			   const char *status,
			   const char *verbose,
			   xmlNodePtr data,
			   xmlNodePtr failed);

void addCibSimpleAnswer(xmlNodePtr answer, const char *status);

enum cib_result updateList(xmlNodePtr local_cib,
		       xmlNodePtr update_command,
		       xmlNodePtr failed,
		       int operation,
		       const char *section);

xmlNodePtr createCibFragmentAnswer(const char *section, xmlNodePtr failed);

void replace_section(const char *section,
		     xmlNodePtr tmpCib,
		     xmlNodePtr command);

gboolean check_generation(xmlNodePtr newCib, xmlNodePtr oldCib);

gboolean conditional_add_failure(xmlNodePtr failed,
				 xmlNodePtr target,
				 int operation,
				 int return_code);

xmlNodePtr
cib_process_request(const char *op,
		    const xmlNodePtr fragment,
		    const xmlNodePtr options,
		    enum cib_result *result)
{

	const char *verbose        = NULL;
	const char *section        = NULL;
	const char *output_section = NULL;
	xmlNodePtr failed          = NULL;
	xmlNodePtr cib_answer      = NULL;

	gboolean update_the_cib = FALSE;
	int cib_update_op = CIB_OP_NONE;

	FNIN();
	
	*result = CIBRES_OK;
	verbose = xmlGetProp(options, XML_ATTR_VERBOSE);
	section = xmlGetProp(options, XML_ATTR_FILTER_TYPE);
	failed  = create_xml_node(NULL, XML_TAG_FAILED);

	cl_log(LOG_DEBUG, "[cib] Processing \"%s\" event", op);
	
	if(op == NULL) {
		*result = CIBRES_FAILED;
		cl_log(LOG_ERR, "No operation specified\n");
		
	} else if(strcmp("noop", op) == 0) {
		;
		
	} else if(strcmp("quit", op) == 0) {
		cl_log(LOG_WARNING,
		       "The CRMd has asked us to exit... complying");
		exit(0);
		
	} else if (strcmp(CRM_OPERATION_PING, op) == 0) {
		cib_answer =
			createPingAnswerFragment(CRM_SYSTEM_CIB, "ok");
		
	} else if (strcmp(CRM_OPERATION_BUMP, op) == 0) {
		xmlNodePtr tmpCib = copy_xml_node_recursive(get_the_CIB(), 1);
		CRM_DEBUG3("Handling a %s for section=%s of the cib",
			   CRM_OPERATION_BUMP, section);
		
		// modify the timestamp
		set_node_tstamp(tmpCib);
		char *new_value = NULL;
		char *old_value =
			xmlGetProp(get_the_CIB(), XML_ATTR_GENERATION);
		
		int int_value = -1;
		if(old_value != NULL) {
			new_value = (char*)ha_malloc(128*(sizeof(char)));
			int_value = atoi(old_value);
			sprintf(new_value, "%d", ++int_value);
		} else {
			new_value = ha_strdup("0");
		}

		cl_log(LOG_DEBUG, "Generation %d(%s)->%s",
		       int_value, old_value, new_value);
		
		set_xml_property_copy(tmpCib, XML_ATTR_GENERATION, new_value);
		ha_free(new_value);
		
		if(activateCibXml(tmpCib, CIB_FILENAME) >= 0) {
			verbose = "true"; 
		} else {
			*result = CIBRES_FAILED;
		}
		
		
	} else if (strcmp("query", op) == 0) {
		CRM_DEBUG2("Handling a query for section=%s of the cib",
			   section);
		/* force a pick-up of the relevant section before
		 * returning
		 */
		verbose = "true"; 
		
	} else if (strcmp(CRM_OPERATION_ERASE, op) == 0) {
		xmlNodePtr new_cib = createEmptyCib();

		// Preserve generation counters etc
		copy_in_properties(new_cib, get_the_CIB());
		
		if (activateCibXml(new_cib, CIB_FILENAME) < 0) {
			*result = CIBRES_FAILED;
		}

	} else if (strcmp(CRM_OPERATION_CREATE, op) == 0) {
		update_the_cib = TRUE;
		cib_update_op = CIB_OP_ADD;
		
	} else if (strcmp(CRM_OPERATION_UPDATE, op) == 0) {
		update_the_cib = TRUE;
		cib_update_op = CIB_OP_MODIFY;
		
	} else if (strcmp(CRM_OPERATION_DELETE, op) == 0) {
		update_the_cib = TRUE;
		cib_update_op = CIB_OP_DELETE;

	} else if (strcmp(CRM_OPERATION_FORWARD, op) == 0) {
		/* force a pick-up of the /entire/ CIB before
		 * returning
		 */
		section = NULL;
		verbose = "true"; 

		/* this will reply to the DC and leaves it up to it to direct
		 * the message appropriately
		 */
		
	} else if (strcmp(CRM_OPERATION_STORE, op) == 0) {
		xmlNodePtr cib_updates = NULL;
		xmlNodePtr tmpCib = copy_xml_node_recursive(get_the_CIB(), 1);
		
		CRM_DEBUG("Storing DC copy of the cib");
		cib_updates = find_xml_node(fragment, XML_TAG_CIB);

		/* copy in any version tags etc verbatum */
		copy_in_properties(tmpCib, cib_updates);
		
		/* replace the following sections verbatum */
		replace_section(XML_CIB_TAG_NODES,       tmpCib, fragment);
		replace_section(XML_CIB_TAG_RESOURCES,   tmpCib, fragment);
		replace_section(XML_CIB_TAG_CONSTRAINTS, tmpCib, fragment);
		
		/* incorporate the info from the DC and then send it back */
		updateList(tmpCib, fragment, failed,
			   CIB_OP_MODIFY,
			   XML_CIB_TAG_STATUS);

		if(check_generation(cib_updates, tmpCib) == FALSE)
			*result = CIBRES_FAILED_OLDUPDATE;
		else if (activateCibXml(tmpCib, CIB_FILENAME) < 0)
			*result = CIBRES_FAILED_ACTIVATION;

		/* Force a pick-up of the merged status section and send it
		 * back to the DC (but only if the DC asked for it by
		 * setting verbose=true)
		 */
//		verbose = "true"; 
		section = XML_CIB_TAG_STATUS;
		
	} else if (strcmp("replace", op) == 0) {
		CRM_DEBUG2("Replacing section=%s of the cib", section);
		xmlNodePtr tmpCib = find_xml_node(fragment, XML_TAG_CIB);
		section = xmlGetProp(fragment, XML_ATTR_SECTION);
		
		if (strcmp("all", section) == 0) {
			replace_section(XML_CIB_TAG_NODES,    tmpCib,fragment);
			replace_section(XML_CIB_TAG_RESOURCES,tmpCib,fragment);
			replace_section(XML_CIB_TAG_STATUS,   tmpCib,fragment);
			replace_section(XML_CIB_TAG_CONSTRAINTS,tmpCib,fragment);
		} else {
			replace_section(section, tmpCib, fragment);
		}

		/*if(check_generation(cib_updates, tmpCib) == FALSE)
			*result = "discarded old update";
			else */
		if (activateCibXml(tmpCib, CIB_FILENAME) < 0)
			*result = CIBRES_FAILED;
	} else {
		*result = CIBRES_FAILED_NOTSUPPORTED;
		cl_log(LOG_ERR, "Action [%s] is not supported by the CIB", op);
	}
    
	if (update_the_cib) {
		CRM_DEBUG("Backing up CIB");
		xmlNodePtr tmpCib = copy_xml_node_recursive(get_the_CIB(), 1);
		section = xmlGetProp(fragment, XML_ATTR_SECTION);

		CRM_DEBUG3("Updating section=%s of the cib (op=%s)",
			   section, op);

			// should we be doing this?
			// do logging
			
			// make changes to a temp copy then activate
		if(section == NULL) {
			cl_log(LOG_ERR, "No section specified in %s",
			       XML_ATTR_FILTER_TYPE);
			*result = CIBRES_FAILED_NOSECTION;

		} else if(strcmp("all", section) == 0
			  && cib_update_op == CIB_OP_DELETE) {
			// delete

			/* order is very important here */
			updateList(tmpCib, fragment, failed, cib_update_op,
				   XML_CIB_TAG_STATUS);
			updateList(tmpCib, fragment, failed, cib_update_op,
				   XML_CIB_TAG_CONSTRAINTS);
			updateList(tmpCib, fragment, failed, cib_update_op,
				   XML_CIB_TAG_RESOURCES);
			updateList(tmpCib, fragment, failed, cib_update_op,
				   XML_CIB_TAG_NODES);

		} else if(strcmp("all", section) == 0) {
			/* order is very important here */
			updateList(tmpCib, fragment, failed, cib_update_op,
				   XML_CIB_TAG_NODES);
			updateList(tmpCib, fragment, failed, cib_update_op,
				   XML_CIB_TAG_RESOURCES);
			updateList(tmpCib, fragment, failed, cib_update_op,
				   XML_CIB_TAG_CONSTRAINTS);
			updateList(tmpCib, fragment, failed, cib_update_op,
				   XML_CIB_TAG_STATUS);
		} else {
			*result = updateList(tmpCib, fragment, failed, cib_update_op, section);
		}
		
		CRM_DEBUG("Activating temporary CIB");
		/* if(check_generation(cib_updates, tmpCib) == FALSE) */
/* 			status = "discarded old update"; */
/* 		else  */
		if (activateCibXml(tmpCib, CIB_FILENAME) < 0) {
			*result = CIBRES_FAILED_ACTIVATION;
			
		} else if (failed->children != NULL) {
			*result = CIBRES_FAILED;

		}
		
		CRM_DEBUG2("CIB update status: %d", *result);
	}
	
	output_section = section;
	
	if (failed->children != NULL || *result != CIBRES_OK) {
		cib_answer = createCibFragmentAnswer(NULL /*"all"*/, failed);
	
	} else if (verbose != NULL && strcmp("true", verbose) == 0) {
		cib_answer = createCibFragmentAnswer(output_section, failed);

	}

	free_xml(failed);
	FNRET(cib_answer);
}

void
replace_section(const char *section, xmlNodePtr tmpCib, xmlNodePtr fragment)
{
	xmlNodePtr parent = NULL,
		cib_updates = NULL,
		new_section = NULL,
		old_section = NULL;
	FNIN();
	
	cib_updates = find_xml_node(fragment, XML_TAG_CIB);

	/* find the old and new versions of the section */
	new_section = get_object_root(section, cib_updates);
	old_section = get_object_root(section, tmpCib);

	parent = old_section->parent;

	/* unlink and free the old one */
	unlink_xml_node(old_section);
	free_xml(old_section);

	/* add the new copy */
	add_node_copy(parent, new_section);
	
	FNOUT();
}



enum cib_result
updateList(xmlNodePtr local_cib, xmlNodePtr update_fragment, xmlNodePtr failed,
	   int operation, const char *section)
{
	const char *type_check = NULL;
	xmlNodePtr cib_updates = NULL, xml_section = NULL, child = NULL;
	FNIN();
    
	cib_updates = find_xml_node(update_fragment, XML_TAG_CIB);
	xml_section = get_object_root(section, cib_updates);

	set_node_tstamp(get_object_root(section, local_cib));
	
	if (section == NULL || xml_section == NULL) {
		cl_log(LOG_ERR, "Section %s not found in message."
		       "  CIB update is corrupt, ignoring.", section);
		return CIBRES_FAILED_NOSECTION;
	}

	if(CIB_OP_NONE > operation > CIB_OP_MAX) {
		cl_log(LOG_ERR, "Invalid operation on section %s",
		       section);
	}
	
	if (strcmp(section, XML_CIB_TAG_NODES) == 0)
		type_check = XML_CIB_TAG_NODE;
	else if (strcmp(section, XML_CIB_TAG_RESOURCES) == 0)
		type_check = XML_CIB_TAG_RESOURCE;
	else if (strcmp(section, XML_CIB_TAG_CONSTRAINTS) == 0)
		type_check = XML_CIB_TAG_CONSTRAINT;
	else if (strcmp(section, XML_CIB_TAG_STATUS) == 0)
		type_check = XML_CIB_TAG_STATE;
	else {
		cl_log(LOG_ERR,
		       "Unknown section %s.CIB update is corrupt, ignoring.",
		       section);
		return CIBRES_FAILED_NOTSUPPORTED;
	}
    
	child = xml_section->children;
    
	while(child != NULL) {
		cl_log(LOG_DEBUG, "#-#-# Performing action %d on (%s=%s).",
		       operation, child->name, ID(child));
	
		if (strcmp(type_check, child->name) == 0
		    && strcmp(XML_CIB_TAG_NODE, child->name) == 0) {
			if (operation == CIB_OP_ADD)
				conditional_add_failure(
					failed, child, operation,
					addHaNode(local_cib, child));
			else if (operation == CIB_OP_MODIFY)
				conditional_add_failure(
					failed, child, operation,
					updateHaNode(local_cib, child));
			else 
				conditional_add_failure(
					failed, child, operation,
					delHaNode(local_cib, ID(child)));
		} else if (strcmp(type_check, child->name) == 0
			   && strcmp(XML_CIB_TAG_RESOURCE, child->name) == 0) {
			if (operation == CIB_OP_ADD)
				conditional_add_failure(
					failed, child, operation,
					addResource(local_cib, child));
			else if (operation == CIB_OP_MODIFY)
				conditional_add_failure(
					failed, child, operation,
					updateResource(local_cib, child));
			else 
				conditional_add_failure(
					failed, child, operation,
					delResource(local_cib, ID(child)));
		} else if (strcmp(type_check, child->name) == 0
			   && strcmp(XML_CIB_TAG_CONSTRAINT, child->name) == 0) {
			if (operation == CIB_OP_ADD)
				conditional_add_failure(
					failed, child, operation,
					addConstraint(local_cib, child));
			else if (operation == CIB_OP_MODIFY)
				conditional_add_failure(
					failed, child, operation,
					updateConstraint(local_cib, child));
			else 
				conditional_add_failure(
					failed, child, operation,
					delConstraint(local_cib,
						      ID(child)));
			
		} else if (strcmp(type_check, child->name) == 0
			   && strcmp(XML_CIB_TAG_STATE, child->name) == 0) {
			if (operation == CIB_OP_ADD)
				conditional_add_failure(
					failed, child, operation,
					addStatus(local_cib, child));
			else if (operation == CIB_OP_MODIFY)
				conditional_add_failure(
					failed, child, operation,
					updateStatus(local_cib, child));
			else 
				conditional_add_failure(
					failed, child, operation,
					delStatus(local_cib,
						  ID(child),
						  INSTANCE(child)));
		} else {
			cl_log(LOG_ERR,
			       "Object (%s) was not for claimed section (%s)."
			       "  CIB update is corrupt, ignoring.",
			       child->name, type_check);
		}
	
		cl_log(LOG_DEBUG, "#---#---# Action %d on (%s=%s) complete.",
		       operation, child->name, ID(child));
		child = child->next;
	}

	if (failed->children != NULL)
		return CIBRES_FAILED;
	else
		return CIBRES_OK;
	
}

xmlNodePtr
createCibFragmentAnswer(const char *section, xmlNodePtr failed)
{
	xmlNodePtr fragment = create_xml_node(NULL, XML_TAG_FRAGMENT);
	
	FNIN();
	
	set_xml_property_copy(fragment, XML_ATTR_SECTION, section);

	if (section == NULL
		   || strlen(section) == 0
		   || strcmp("all", section) == 0) {
		add_node_copy(fragment, get_the_CIB());
		
	} else {
		xmlNodePtr cib = create_xml_node(fragment, XML_TAG_CIB);
		add_node_copy(cib, get_object_root(section, get_the_CIB()));
		copy_in_properties(cib, get_the_CIB());
		
	}

	if (failed != NULL && failed->children != NULL) {
		xmlAddChild(fragment, copy_xml_node_recursive(failed, 1));
	}
		
	FNRET(fragment);
}


gboolean
check_generation(xmlNodePtr newCib, xmlNodePtr oldCib)
{
	char *new_value = xmlGetProp(newCib, XML_ATTR_GENERATION);
	char *old_value = xmlGetProp(oldCib, XML_ATTR_GENERATION);
	int int_new_value = -1;
	int int_old_value = -1;
	if(old_value != NULL) int_old_value = atoi(old_value);
	if(new_value != NULL) int_new_value = atoi(new_value);
	
	if(int_new_value >= int_old_value) {
		return TRUE;
	} else {
		cl_log(LOG_ERR, "Generation from update (%d) is older than %d",
		       int_new_value, int_old_value);
	}
	
	return FALSE;
}
 
gboolean
conditional_add_failure(xmlNodePtr failed,
			xmlNodePtr target,
			int operation,
			int return_code)
{
	FNIN();
	gboolean was_error = FALSE;
    
	if (return_code < 0)
	{
		const char *error_msg = cib_error2string(return_code);
		const char *operation_msg = cib_op2string(operation);
		was_error = TRUE;

		xmlNodePtr xml_node = create_xml_node(failed,
						      XML_FAIL_TAG_CIB);

		set_xml_property_copy(xml_node,
				      XML_FAILCIB_ATTR_ID,
				      ID(target));

		set_xml_property_copy(xml_node,
				      XML_FAILCIB_ATTR_OBJTYPE,
				      TYPE(target));

		set_xml_property_copy(xml_node,
				      XML_FAILCIB_ATTR_OP,
				      operation_msg);
	
		set_xml_property_copy(xml_node,
				      XML_FAILCIB_ATTR_REASON,
				      error_msg);

		cl_log(LOG_DEBUG,
		       "Action %s failed: %s (cde=%d)",
		       operation_msg,
		       error_msg,
		       return_code);
	
	}

	FNRET(was_error);
}

