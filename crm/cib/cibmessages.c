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
#include <crm/common/crmutils.h>
#include <crm/common/xmlutils.h>
#include <cibio.h>
#include <crm/common/xmltags.h>
#include <clplumbing/cl_log.h>
#include <cibprimatives.h>

xmlNodePtr createCibRequest(gboolean isLocal, const char *operation, const char *section,
			    const char *verbose, xmlNodePtr data);
xmlNodePtr processCibRequest(xmlNodePtr command);
xmlNodePtr createCibAnswer(const char *reference, const char *operation, const char *section,
			   const char *status, const char *verbose,
			   xmlNodePtr data, xmlNodePtr failed);
void addCibSimpleAnswer(xmlNodePtr answer, const char *status);
void addCibFragment(xmlNodePtr top, const char *section, xmlNodePtr data);
void updateList(xmlNodePtr local_cib, xmlNodePtr update_command, xmlNodePtr failed, int operation, const char *section);

xmlNodePtr createCibFragmentAnswer(const char *section, xmlNodePtr data, xmlNodePtr failed);

xmlNodePtr
createCibRequest(gboolean isLocal, const char *operation, const char *section,
		 const char *verbose, xmlNodePtr data)
{
    const char *reference = generateReference();
    xmlNodePtr root = NULL, cmd = xmlNewNode(NULL, XML_REQ_TAG_CIB);

    xmlSetProp(cmd, XML_MSG_ATTR_REFERENCE, reference);
    xmlSetProp(cmd, XML_CIB_ATTR_OP       , operation);
    xmlSetProp(cmd, XML_ATTR_VERBOSE      , verbose);
    if(section != NULL) xmlSetProp(cmd, XML_CIB_ATTR_SECTION  , section);

    addCibFragment(cmd, section, data);
    
    if(isLocal)
    {
//	xmlDocPtr doc = xmlNewDoc("1.0");
//	doc->children = xmlNewDocNode(doc, NULL, XML_REQ_TAG_CIB, NULL);
//	doc->children = cmd;
	root = cmd;
    }
    else
    {
	root = createCrmMsg(reference, NULL, "cib", cmd, TRUE);
    }
    
    return root;
}

#define CIB_OP_NONE   0
#define CIB_OP_ADD    1
#define CIB_OP_MODIFY 2
#define CIB_OP_DELETE 3


xmlNodePtr
processCibRequest(xmlNodePtr command)
{
    // sanity check
    if(command == NULL)
    {
	cl_log(LOG_INFO, "The (%s) received an empty message", "cib");
	return NULL;
    }
    else if(strcmp(XML_REQ_TAG_CIB, command->name) != 0)
    {
	cl_log(LOG_INFO, "The (%s) received an invalid message of type (%s)", "cib", command->name);
	return NULL;
    }

    const char *status    = "failed";
    xmlNodePtr data       = NULL;
    xmlNodePtr failed     = xmlNewNode(NULL, XML_TAG_FAILED);
    const char *op        = xmlGetProp(command, XML_CIB_ATTR_OP);
    const char *verbose   = xmlGetProp(command, XML_ATTR_VERBOSE);
    const char *section   = xmlGetProp(command, XML_CIB_ATTR_SECTION);
    const char *reference = xmlGetProp(command, XML_MSG_ATTR_REFERENCE);
    
    gboolean update_the_cib = FALSE;
    int cib_update_operation = CIB_OP_NONE;

    if(strcmp("noop", op) == 0) ;
    else if(strcmp("ping", op) == 0)
    {
	CRM_DEBUG("Handling a ping");
	status = "ok";
    }
    else if(strcmp("query", op) == 0)
    {
	CRM_DEBUG2("Handling a query for section=%s of the cib", section);
	if(section != NULL && strcmp("all", section) == 0)
	{
	    data = theCib();
	}
	else
	    data = getCibSection(section);

	if(data != NULL) status = "ok";
    }
    else if(strcmp("add", op) == 0)
    {
      update_the_cib = TRUE;
      cib_update_operation = CIB_OP_ADD;
    }
    else if(strcmp("update", op) == 0)
    {
      update_the_cib = TRUE;
      cib_update_operation = CIB_OP_MODIFY;
    }
    else if(strcmp("delete", op) == 0)
    {
      update_the_cib = TRUE;
      cib_update_operation = CIB_OP_DELETE;
    }
    else if(strcmp("replace", op) == 0)
    {
	CRM_DEBUG2("Replacing section=%s of the cib", section);
	if(strcmp("all", section) == 0)
	{
	    xmlNodePtr new_cib = findNode(command, XML_TAG_CIB);
	    if(activateCibXml(new_cib) < 0)
		status = "new activation failed";
	    else
		status = "ok";
	}
	else
	{
	    xmlNodePtr new_section = findNode(command, XML_TAG_CIB);
	    new_section = findNode(new_section, section);
	    if(new_section != NULL)
	    {
		// make changes to a temp copy then activate
		xmlNodePtr tmpCib = xmlLinkedCopyNoSiblings(theCib(), 1);
		xmlNodePtr old_section = findNode(tmpCib, section);
		xmlReplaceNode(old_section, new_section);
		status = "ok";
		if(activateCibXml(tmpCib) < 0)
		    status = "update activation failed";
		
	    }
	    else
	    {
		status = "section replacement failed";
	    }
	}
    }
    else
	status = "not supported";

    if(update_the_cib)
    {
	cl_log(LOG_DEBUG, "Updating section=%s of the cib (op=%s)", section, op);
	if(strcmp("all", section) == 0)
	{
	    // should we be doing this?
	    // do logging

	    // make changes to a temp copy then activate
	    xmlNodePtr tmpCib = xmlLinkedCopyNoSiblings(theCib(), 1);
	    if(cib_update_operation == CIB_OP_ADD || cib_update_operation == CIB_OP_MODIFY)
	    {
		updateList(tmpCib, command, failed, cib_update_operation, "nodes");
		updateList(tmpCib, command, failed, cib_update_operation, "resources");
		updateList(tmpCib, command, failed, cib_update_operation, "constraints");
		updateList(tmpCib, command, failed, cib_update_operation, "status");
	    }
	    else // delete
	    {
		updateList(tmpCib, command, failed, cib_update_operation, "status");
		updateList(tmpCib, command, failed, cib_update_operation, "constraints");
		updateList(tmpCib, command, failed, cib_update_operation, "resources");
		updateList(tmpCib, command, failed, cib_update_operation, "nodes");
	    }
	}
	else
	{
	    // make changes to a temp copy then activate
	    xmlNodePtr tmpCib = xmlLinkedCopyNoSiblings(theCib(), 1);
	    updateList(tmpCib, command, failed, cib_update_operation, section);
	    if(activateCibXml(tmpCib) < 0)
		status = "update activation failed";
	    else if(failed->children != NULL)
	    {
		status = "some updates failed";
		data = getCibSection(section);
	    }
	    else
		status = "ok";
	}
    }

//    if(data != NULL) status = "ok";

    CRM_DEBUG("Checking for verbosity");
    if(verbose != NULL && strcmp("true", verbose) == 0)
    {
	if(section != NULL || strcmp("all", section) == 0)
	    data = theCib();
	else
	    data = getCibSection(section);
    }
    
    CRM_DEBUG("Creating CIB answer");
    CRM_DEBUG2("Creating CIB answer for op=%s", op);
    xmlNodePtr cib_answer = createCibAnswer(reference,
					    op, section,
					    status, verbose,
					    data, failed);

    return cib_answer;
}

void
updateList(xmlNodePtr local_cib, xmlNodePtr update_command, xmlNodePtr failed, int operation, const char *section)
{
  xmlNodePtr xml_section = findNode(update_command, XML_TAG_CIB);
  xml_section = findNode(update_command, section);
  xmlNodePtr child = xml_section->children;
  
  while(child != NULL)
  {
      cl_log(LOG_DEBUG, "Performing action %d on (%s=%s).", operation, child->name, ID(child));
      
      if(strcmp(XML_CIB_TAG_NODE, child->name) == 0)
      {
	  if(operation == CIB_OP_ADD || operation == CIB_OP_MODIFY)
	      conditional_add_failure(failed, child, operation, updateHaNode(local_cib, child));
	  else 
	      conditional_add_failure(failed, child, operation, delHaNode(local_cib, ID(child)));
      }
      if(strcmp(XML_CIB_TAG_RESOURCE, child->name) == 0)
      {
	  if(operation == CIB_OP_ADD || operation == CIB_OP_MODIFY)
	      conditional_add_failure(failed, child, operation, updateResource(local_cib, child));
	  else 
	      conditional_add_failure(failed, child, operation, delResource(local_cib, ID(child)));
      }
      if(strcmp(XML_CIB_TAG_CONSTRAINT, child->name) == 0)
      {
	  if(operation == CIB_OP_ADD || operation == CIB_OP_MODIFY)
	      conditional_add_failure(failed, child, operation, updateConstraint(local_cib, child));
	  else 
	      conditional_add_failure(failed, child, operation, delConstraint(local_cib, ID(child)));
      }
      if(strcmp(XML_CIB_TAG_STATE, child->name) == 0)
      {
	  if(operation == CIB_OP_ADD || operation == CIB_OP_MODIFY)
	      conditional_add_failure(failed, child, operation, updateStatus(local_cib, child));
	  else 
	      conditional_add_failure(failed, child, operation, delStatus(local_cib, ID(child), INSTANCE(child)));
      }
      child = child->next;
    }

}

xmlNodePtr
createCibAnswer(const char *reference, const char *operation, const char *section,
		const char *status, const char *verbose,
		xmlNodePtr data, xmlNodePtr failed)
{
    xmlNodePtr root = NULL, wrapper = NULL, our_data = NULL;

    CRM_DEBUG2("Attempting to creating CIB answer for op=%s", operation);
    if(operation == NULL) return root;


    if(strcmp("ping", operation) == 0)
    {
	CRM_DEBUG("Creating CIB Ping answer");
	our_data = createPingAnswerFragment("cib", NULL, status);
	wrapper = createIpcMessage(reference, "cib", NULL, our_data, FALSE);
    }
    else if(failed == NULL && strcmp("true", verbose) == 0)
    {
	CRM_DEBUG("Creating CIB success answer");
	wrapper = createIpcMessage(reference, "cib", NULL, data, FALSE);
	xmlSetProp(wrapper, XML_CIB_ATTR_RESULT, status);	
    }
    else
    {
	CRM_DEBUG("Creating CIB failure answer");
	our_data = createCibFragmentAnswer(section, data, failed);
	wrapper = createIpcMessage(reference, "cib", NULL, our_data, FALSE);
    }

    CRM_DEBUG("Creating crm message");
    root = createCrmMsg(reference, "cib", NULL, wrapper, FALSE);
    return root;
}


xmlNodePtr
createCibFragmentAnswer(const char *section,
		     xmlNodePtr data, xmlNodePtr failed)
{
    xmlNodePtr fragment = xmlNewNode(NULL, XML_CIB_TAG_FRAGMENT);
    xmlSetProp(fragment, XML_CIB_ATTR_SECTION, section);

    addCibFragment(fragment, section, data);

    if(failed != NULL && failed->children != NULL)
    {
	xmlAddChild(fragment, failed);
    }
    return fragment;
}

void
addCibFragment(xmlNodePtr top, const char *section, xmlNodePtr data)
{    
    if(data != NULL)
    {
	if((strcmp("cib", data->name) == 0 && strcmp("all", section) == 0))
	{
	    CRM_DEBUG("Added entire cib to cib request");
	    xmlAddChild(top, data);
	}
	else if(strcmp(data->name, section) == 0)
	{
	    CRM_DEBUG2("Added section (%s) to cib request", data->name);
	    xmlNodePtr cib = xmlNewChild(top, NULL, XML_TAG_CIB, NULL);
	    xmlAddChild(cib, data);
	}
	else
	{
	    cl_log(LOG_INFO, "Mismatch between section (%s) and data supplied (%s)... ignoring.", section, data->name);
	}
    }
    else
	cl_log(LOG_INFO, "No data to add to cib message");

}


