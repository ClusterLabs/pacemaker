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
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/cl_log.h>

#include <libxml/tree.h>
#include <time.h>

#include <crm/common/crmutils.h>
#include <crm/common/xmlutils.h>
#include <cibio.h>
#include <crm/common/xmltags.h>
#include <clplumbing/cl_log.h>
#include <cibprimatives.h>

const char *generateReference(void);
xmlNodePtr createEmptyMsg(const char *reference);
xmlNodePtr createLrmdRequest(gboolean isLocal, const char *operation, const char *section,
			    const char *verbose, xmlNodePtr data);
xmlNodePtr processLrmdRequest(xmlNodePtr command);
xmlNodePtr createLrmdAnswer(const char *reference, const char *operation, const char *section,
			   const char *status, const char *verbose,
			   xmlNodePtr data, xmlNodePtr failed);
void addLrmdPingAnswer(xmlNodePtr answer, const char *status);
void addLrmdSimpleAnswer(xmlNodePtr answer, const char *status);
void addLrmdFragmentAnswer(xmlNodePtr answer, const char *section,
			  xmlNodePtr data, xmlNodePtr failed);
void addLrmdFragment(xmlNodePtr top, const char *section, xmlNodePtr data);
void updateList(xmlNodePtr update_command, xmlNodePtr failed, int operation, const char *section);
gboolean conditional_add_failure(xmlNodePtr failed, xmlNodePtr target, int operation, int return_code);


const char *
generateReference(void)
{
    return getNow();
}

xmlNodePtr
createEmptyMsg(const char *reference)
{
    xmlDocPtr doc;
    
    doc = xmlNewDoc("1.0");
    doc->children = xmlNewDocNode(doc, NULL, XML_MSG_TAG, NULL);

    xmlSetProp(doc->children, XML_ATTR_VERSION, CRM_VERSION);
    xmlSetProp(doc->children, XML_MSG_ATTR_SUBSYS, "none");
    if(reference == NULL)
    {
	xmlSetProp(doc->children, XML_MSG_ATTR_MSGTYPE, XML_MSG_TAG_REQUEST);
	xmlSetProp(doc->children, XML_MSG_ATTR_REFERENCE, generateReference());
    }
    else
    {
	xmlSetProp(doc->children, XML_MSG_ATTR_MSGTYPE, XML_MSG_TAG_RESPONSE);
	xmlSetProp(doc->children, XML_MSG_ATTR_REFERENCE, reference);
    }
    
    xmlSetProp(doc->children, XML_ATTR_TSTAMP, getNow());

    return xmlDocGetRootElement(doc);
}

xmlNodePtr
createLrmdRequest(gboolean isLocal, const char *operation, 
		  const char *type_filter, const char *id_filter
		  xmlNodePtr data)
{
    xmlNodePtr root = NULL, cmd = NULL;

    const char *reference;
    if(isLocal)
    {
	xmlDocPtr doc = xmlNewDoc("1.0");
	doc->children = xmlNewDocNode(doc, NULL, XML_REQ_TAG_CIB, NULL);
	cmd = doc->children;
	root = cmd;
	reference = generateReference();
    }
    else
    {
	xmlNodePtr request;
	root = createEmptyMsg(NULL);
	xmlSetProp(root, XML_MSG_ATTR_SUBSYS, "cib");
	request   = xmlNewChild(root, NULL, XML_MSG_TAG_REQUEST, NULL);
	cmd       = xmlNewChild(request, NULL, XML_REQ_TAG_LRM, NULL);
	reference = xmlGetProp(root, XML_MSG_ATTR_REFERENCE);
    }
    xmlSetProp(cmd, XML_MSG_ATTR_REFERENCE, reference);
    xmlSetProp(cmd, XML_LRM_ATTR_OP       , operation);
    xmlSetProp(cmd, XML_LRM_ATTR_IDFILTE  , id_filter);
    xmlSetProp(cmd, XML_LRM_ATTR_TYPEFILTE, type_filter);
    
    return root;
}

#define LRM_OP_NONE    0
#define LRM_OP_START   1
#define LRM_OP_STOP    2
#define LRM_OP_RESTART 3

xmlNodePtr
processLrmdRequest(xmlNodePtr command)
{
    // sanity check
    if(command == NULL)
    {
	cl_log(LOG_INFO, "The (%s) received an empty message", "cib");
	return NULL;
    }
    else if(strcmp(XML_REQ_TAG_LRM, command->name) != 0)
    {
	cl_log(LOG_INFO, "The (%s) received an invalid message of type (%s)", "cib", command->name);
	return NULL;
    }

    const char *status      = "failed";
    xmlNodePtr data         = NULL;
    xmlNodePtr failed       = xmlNewNode(NULL, XML_TAG_FAILED);
    const char *op          = xmlGetProp(command, XML_LRM_ATTR_OP);
    const char *id_filter   = xmlSetProp(command, XML_LRM_ATTR_IDFILTE);
    const char *type_filter = xmlSetProp(command, XML_LRM_ATTR_TYPEFILTE);
    const char *reference   = xmlGetProp(command, XML_MSG_ATTR_REFERENCE);
    
    gboolean start_resource = FALSE;
    gboolean stop_resource = FALSE;
    int resource_operation = LRM_OP_NONE;

/*
<!ATTLIST lrm_request
          lrm_operation    (noop|ping|query|start|stop|restart|shutdown|respawn|disconnect|reconnect)	'noop'
          type_filter?     #CDATA
	  id_filter?	   #CDATA
	  reference	   #CDATA
          timeout          #CDATA       '0'>
*/

    if(strcmp("noop", op) == 0) ;
    else if(strcmp("ping", op) == 0)
    {
	status = "ok";
    }
    else if(strcmp("query", op) == 0)
    {
	if(data != NULL) status = "ok";
// let createLrmdAnswer() fill in the LRM's local view of things
    }
    else if(strcmp("stop", op) == 0 || strcmp("restart", op))
    {
	stop_resource = TRUE;
	if(strcmp("restart", op) == 0)
	    start_resource = TRUE;
    }
    else if(strcmp("start", op) == 0)
    {
      start_resource = TRUE;
    }
    else
	status = "not supported (yet)";

    if(stop_resource == TRUE || start_resource == TRUE)
    {
	xmlNodePtr resourceList = retrieveResourceList(id_filter, type_filter);
	if(stop_resource == TRUE)
	{
	    actionRequest(resourceList, op, failed);
	}
	
	if(start_resource == TRUE)
	{
	    startResources(resourceList, failed);
	}
    }

    xmlNodePtr lrm_answer = createLrmdAnswer(reference,
					     op,
					     status,
					     failed);
    
    return lrm_answer;
}

xmlNodePtr
retrieveResourceList(const char *id_filter, const char *type_filter)
{
}

void
actionRequest(xmlNodePtr update_command, const char *operation, xmlNodePtr failed)
{
  xmlNodePtr xml_section = findNode(update_command, XML_TAG_CIB);
  xml_section = findNode(update_command, XML_CIB_TAG_RESOURCES);
  xmlNodePtr child = xml_section->children;
  
  while(child != NULL)
    {
      cl_log(LOG_DEBUG, "Performing action %s on (%s=%s).", operation, child->name, ID(child));

      int result = 0; // change to -1 post-prototype
      const char *old_state = NULL;  // get this from internal lists
      const char *new_state = old_state;

      // set timers etc.
      if(strcmp("stop", op) == 0)
      {
	  // result = try to stop the resource
	  if(result == 0)
	  {
	      new_state = CIB_VAL_RESSTATUS_STOPED;
	      // update internal lists
	  }
	  // may want to put into a particular state depending on result code
      }
      else if(strcmp("start", op) == 0)
      {
	  // result = try to stop the resource
	  if(result == 0)
	  {
	      new_state = CIB_VAL_RESSTATUS_STARTED;
	      // update internal lists
	  }
	  // may want to put into a particular state depending on result code
      }
      /* failures here will be like:
       *  - resource script not found
       *  - already started/stopped
       *  - operation not supported
       *
       * other failures will be reported by timer callbacks or something
       */
      conditional_add_failure(failed, child, operation, new_state, result);
      child = child->next;
    }

}

gboolean
conditional_add_failure(xmlNodePtr failed, xmlNodePtr target, const char *operation, const char *status, int return_code)
{
  gboolean was_error = FALSE;

  if(return_code < 0)
    {
      was_error = TRUE;

      // do some fabulous logging
      
      xmlNodePtr xml_node = xmlNewNode(NULL, XML_FAIL_TAG_RESOURCE);
      xmlSetProp(xml_node, XML_FAILCIB_ATTR_RESID, ID(target));
      xmlSetProp(xml_node, XML_LRM_ATTR_OP, operation);
      xmlSetProp(xml_node, XML_LRM_ATTR_RESSTATUS, status);

      char buffer[20]; // will handle 64 bit integers

      /* for now just put in the return code
       * later, convert it to text based on the operation
       */
      sprintf(buffer, "%d", return_code);
      xmlSetProp(xml_node, XML_FAILRES_ATTR_REASON, buffer);
      
      xmlAddChild(failed, xml_node);
    }

  return was_error;
}


xmlNodePtr
createLrmdAnswer(const char *reference, const char *operation,
		 const char *status, xmlNodePtr failed)
{
    xmlNodePtr root, response, answer;

/*
<!ELEMENT lrm_response (cib_fragment, res_failed?)|ping_item>
<!ATTLIST lrm_response
	  reference	   #CDATA>
 */
    
    root = createEmptyMsg(reference);
    xmlSetProp(root, XML_MSG_ATTR_SRCSUBSYS, "lrm");
    response = xmlNewChild(root, NULL, XML_MSG_TAG_RESPONSE, NULL);
    answer = xmlNewChild(response, NULL, XML_RESP_TAG_LRM, NULL);

    if(operation == NULL) return root;
    
    if(strcmp("ping", operation) == 0)
    {
	addLrmdPingAnswer(answer, status);
    }
    else
    {
	xmlNodePtr fragment = xmlNewChild(answer, NULL, XML_CIB_TAG_FRAGMENT, NULL);
	xmlSetProp(fragment, XML_CIB_ATTR_SECTION, "status");
	addLrmdFragment(fragment);
	
	if(failed != NULL && failed->children != NULL)
	{
	    xmlAddChild(answer, failed);
	}
    }
    return root;
}

void
addLrmdPingAnswer(xmlNodePtr answer, const char *status)
{
    xmlNodePtr ping = xmlNewChild(answer, NULL, XML_CRM_TAG_PING, NULL);
    xmlSetProp(ping, XML_PING_ATTR_STATUS, status);
}

void
addLrmdFragment(xmlNodePtr fragment_root)
{    
    // dump the local status into fragment_root
}


