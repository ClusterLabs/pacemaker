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
//#include <crm/common/crmutils.h>
#include <crm/common/xmlutils.h>
#include <cibio.h>
#include <crm/common/xmltags.h>
#include <crm/common/xmlvalues.h>
#include <clplumbing/cl_log.h>
#include <cibprimatives.h>

xmlNodePtr createCibRequest(gboolean isLocal, const char *operation, const char *section,
			    const char *verbose, xmlNodePtr data);
xmlNodePtr processCibRequest(xmlNodePtr command);
xmlNodePtr createCibAnswer(const char *reference, const char *operation, const char *section,
			   const char *status, const char *verbose,
			   xmlNodePtr data, xmlNodePtr failed);
void addCibSimpleAnswer(xmlNodePtr answer, const char *status);
void updateList(xmlNodePtr local_cib, xmlNodePtr update_command, xmlNodePtr failed, int operation, const char *section);

xmlNodePtr createCibFragmentAnswer(const char *section, xmlNodePtr data, xmlNodePtr failed);

/* xmlNodePtr */
/* createCibRequest(const char *operation, const char *section, */
/* 		 const char *verbose, xmlNodePtr data) */
/* { */
/* //    const char *reference = generateReference(); */
/*     xmlNodePtr cmd = xmlNewNode(NULL, XML_REQ_TAG_CIB); */

/* //    xmlSetProp(cmd, XML_MSG_ATTR_REFERENCE, reference); */
/*     xmlSetProp(cmd, XML_CIB_ATTR_OP       , operation); */
/*     xmlSetProp(cmd, XML_ATTR_VERBOSE      , verbose); */
/*     if(section != NULL) xmlSetProp(cmd, XML_CIB_ATTR_SECTION  , section); */

/*     addCibFragment(cmd, section, data); */
    
/*     FNRET(cmd); */
/* } */

#define CIB_OP_NONE   0
#define CIB_OP_ADD    1
#define CIB_OP_MODIFY 2
#define CIB_OP_DELETE 3


xmlNodePtr
processCibRequest(xmlNodePtr command)
{
    (void)_ha_msg_h_Id; // mumble mumble mumble
    
    // sanity check
    if(command == NULL)
    {
	cl_log(LOG_INFO, "The (%s) received an empty message", CRM_SYSTEM_CIB);
	FNRET(NULL);
    }
    else if(strcmp(XML_REQ_TAG_CIB, command->name) != 0)
    {
	cl_log(LOG_INFO, "The (%s) received an invalid message of type (%s)", CRM_SYSTEM_CIB, command->name);
	FNRET(NULL);
    }

    const char *status    = "failed";
    const char *op        = xmlGetProp(command, XML_CIB_ATTR_OP);
    const char *verbose   = xmlGetProp(command, XML_ATTR_VERBOSE);
    const char *section   = xmlGetProp(command, XML_CIB_ATTR_SECTION);
    xmlNodePtr failed     = xmlNewNode(NULL, XML_TAG_FAILED);
    xmlNodePtr cib_answer = xmlNewNode(NULL, XML_RESP_TAG_CIB);

    gboolean update_the_cib = FALSE;
    int cib_update_operation = CIB_OP_NONE;

    if(strcmp("noop", op) == 0) ;
    else if(strcmp("ping", op) == 0)
    {
	CRM_DEBUG("Handling a ping");
	status = "ok";
	xmlAddChild(cib_answer,
		    createPingAnswerFragment(CRM_SYSTEM_CIB, status));
    }
    else if(strcmp("query", op) == 0)
    {
	CRM_DEBUG2("Handling a query for section=%s of the cib", section);
	verbose = "true"; // force a pick-up of the relevant section before returning 
	if(cib_answer != NULL) status = "ok";
    }
    else if(strcmp("create", op) == 0)
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
    {
	status = "not supported";
	cl_log(LOG_ERR, "Action [%s] is not supported by the CIB", op);
    }
    
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
	    CRM_DEBUG("Backing up CIB");
	    xmlNodePtr tmpCib = xmlLinkedCopyNoSiblings(theCib(), 1);
	    CRM_DEBUG("Updating temporary CIB");
	    updateList(tmpCib, command, failed, cib_update_operation, section);
	    CRM_DEBUG("Activating temporary CIB");
	    if(activateCibXml(tmpCib) < 0)
		status = "update activation failed";
	    else if(failed->children != NULL)
		status = "some updates failed";
	    else
		status = "ok";

	    CRM_DEBUG2("CIB update status: %s", status);
	}
    }
    if(failed->children != NULL || strcmp("ok", status) != 0  )
	xmlAddChild(cib_answer,
		    createCibFragmentAnswer("all", getCibSection(NULL), failed));
    else if(strcmp("true", verbose) == 0)
	xmlAddChild(cib_answer,
		    createCibFragmentAnswer(section, getCibSection(section), failed));
    
    xmlSetProp(cib_answer, XML_CIB_ATTR_SECTION, section);
    xmlSetProp(cib_answer, XML_CIB_ATTR_RESULT, status);

    FNRET(cib_answer);
}

void
updateList(xmlNodePtr local_cib, xmlNodePtr update_command, xmlNodePtr failed, int operation, const char *section)
{
  xmlNodePtr xml_section = findNode(update_command, XML_TAG_CIB);
  xml_section = findNode(xml_section, section);
  xmlNodePtr child = xml_section->children;
  
  while(child != NULL)
  {
      cl_log(LOG_DEBUG, "#---#---# Performing action %d on (%s=%s).", operation, child->name, ID(child));
      
      if(strcmp(XML_CIB_TAG_NODE, child->name) == 0)
      {
	  if(operation == CIB_OP_ADD)
	      conditional_add_failure(failed, child, operation, addHaNode(local_cib, child));
	  else if(operation == CIB_OP_MODIFY)
	      conditional_add_failure(failed, child, operation, updateHaNode(local_cib, child));
	  else 
	      conditional_add_failure(failed, child, operation, delHaNode(local_cib, ID(child)));
      }
      if(strcmp(XML_CIB_TAG_RESOURCE, child->name) == 0)
      {
	  if(operation == CIB_OP_ADD)
	      conditional_add_failure(failed, child, operation, addResource(local_cib, child));
	  else if(operation == CIB_OP_MODIFY)
	      conditional_add_failure(failed, child, operation, updateResource(local_cib, child));
	  else 
	      conditional_add_failure(failed, child, operation, delResource(local_cib, ID(child)));
      }
      if(strcmp(XML_CIB_TAG_CONSTRAINT, child->name) == 0)
      {
	  if(operation == CIB_OP_ADD)
	      conditional_add_failure(failed, child, operation, addConstraint(local_cib, child));
	  else if(operation == CIB_OP_MODIFY)
	      conditional_add_failure(failed, child, operation, updateConstraint(local_cib, child));
	  else 
	      conditional_add_failure(failed, child, operation, delConstraint(local_cib, ID(child)));
      }
      if(strcmp(XML_CIB_TAG_STATE, child->name) == 0)
      {
	  if(operation == CIB_OP_ADD)
	      conditional_add_failure(failed, child, operation, addStatus(local_cib, child));
	  else if(operation == CIB_OP_MODIFY)
	      conditional_add_failure(failed, child, operation, updateStatus(local_cib, child));
	  else 
	      conditional_add_failure(failed, child, operation, delStatus(local_cib, ID(child), INSTANCE(child)));
      }
      cl_log(LOG_DEBUG, "#---#---# Action %d on (%s=%s) complete.", operation, child->name, ID(child));
      child = child->next;
    }

}

xmlNodePtr
createCibFragmentAnswer(const char *section, xmlNodePtr data, xmlNodePtr failed)
{
    xmlNodePtr fragment = xmlNewNode(NULL, XML_CIB_TAG_FRAGMENT);
    xmlSetProp(fragment, XML_CIB_ATTR_SECTION, section);

    if(data != NULL)
    {
	if(strcmp(CRM_SYSTEM_CIB, data->name) == 0 && strcmp("all", section) == 0)
	{
	    CRM_DEBUG("Added entire cib to cib request");
	    xmlAddChild(fragment, data);
	}
	else if(strcmp(data->name, section) == 0)
	{
	    CRM_DEBUG2("Added section (%s) to cib request", data->name);
	    xmlNodePtr cib = xmlNewChild(fragment, NULL, XML_TAG_CIB, NULL);
	    xmlAddChild(cib, data);
	}
	else
	{
	    cl_log(LOG_INFO, "Mismatch between section (%s) and data supplied (%s)... ignoring.", section, data->name);
	}
    }
    else
	cl_log(LOG_INFO, "No data to add to cib message");

    if(failed != NULL && failed->children != NULL)
    {
	xmlAddChild(fragment, failed);
    }
    FNRET(fragment);
}

