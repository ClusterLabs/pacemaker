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
#include <crm.h>

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>

#include <clplumbing/cl_log.h>

#include <time.h> 

#include <msgutils.h>
#include <crmutils.h>
#include <xmlutils.h>
#include <xmltags.h>

xmlNodePtr
createPingAnswerFragment(const char *from, const char *to, const char *status)
{
    xmlNodePtr ping = xmlNewNode(NULL, XML_CRM_TAG_PING);
    xmlSetProp(ping, XML_PING_ATTR_STATUS, status);
    xmlSetProp(ping, XML_PING_ATTR_SUBSYS, from);

    return ping;
}

xmlNodePtr
createPingRequest(const char *reference, const char *from, const char *to)
{
    xmlNodePtr root_xml_node = NULL, ping = createIpcMessage(reference, from, to, NULL, TRUE);
	
    int msg_type_len = strlen(to) + 10 + 1; // + "_operation" + '\0'
    char *msg_type_target = (char*)ha_malloc(sizeof(char)*(msg_type_len));
    sprintf(msg_type_target, "%s_operation", to);
    xmlSetProp(ping, msg_type_target, "ping");
//    ha_free(msg_type_target);

/*      if(is_local) */
/* 	 xmlNodePtr root_xml_node = createCrmMsg(reference, from, to, ping, TRUE); */
/*      else */
	 root_xml_node = ping;
     
    return root_xml_node;
}


xmlNodePtr
createCrmMsg(const char *reference,
	     const char *src_subsystem,
	     const char *dest_subsystem,
	     xmlNodePtr data,
	     gboolean is_request)
{
    xmlDocPtr doc;
    const char *message_type = XML_MSG_TAG_RESPONSE;
    
    cl_log(LOG_DEBUG, "Building crm message - 1");
    
    if(reference == NULL) reference = generateReference();
    if(is_request) message_type = XML_MSG_TAG_REQUEST;
    
    doc = xmlNewDoc("1.0");
    doc->children = xmlNewDocNode(doc, NULL, XML_MSG_TAG, NULL);

    cl_log(LOG_DEBUG, "Building crm message - 2");

    // the root_xml_node node
    xmlSetProp(doc->children, XML_ATTR_VERSION, CRM_VERSION);
    xmlSetProp(doc->children, XML_MSG_ATTR_MSGTYPE, message_type);
    xmlSetProp(doc->children, XML_MSG_ATTR_REFERENCE, reference);
    xmlSetProp(doc->children, XML_ATTR_TSTAMP, getNow());

    cl_log(LOG_DEBUG, "Building crm message - 3");
    
    if(dest_subsystem == NULL)
	xmlSetProp(doc->children, XML_MSG_ATTR_SUBSYS, "none");
    else
	xmlSetProp(doc->children, XML_MSG_ATTR_SUBSYS, dest_subsystem);
    if(src_subsystem == NULL)
	xmlSetProp(doc->children, XML_MSG_ATTR_SUBSYS, "none");
    else
	xmlSetProp(doc->children, XML_MSG_ATTR_SRCSUBSYS, src_subsystem);
	
    cl_log(LOG_DEBUG, "Building crm message - 4");
    // create a place holder for the eventual data

    xmlNodePtr xml_node   = xmlNewChild(doc->children, NULL, message_type, NULL);


    cl_log(LOG_DEBUG, "Building crm message - 5");
    if(data != NULL)
    {
	xmlAddChild(xml_node, data);
	xmlSetProp(data, XML_MSG_ATTR_REFERENCE, reference);
    }
    cl_log(LOG_DEBUG, "Building crm message - 6");
    cl_log(LOG_DEBUG, "Building crm message - 8");
    
    return xmlDocGetRootElement(doc);
}

xmlNodePtr
createIpcMessage(const char *reference, const char *from, const char *to, xmlNodePtr data, gboolean is_request)
{
    const char *tmp = from;
    if(is_request) tmp = to;

    cl_log(LOG_DEBUG, "Building ipc message - 5.1 (%s)", tmp);

    const char *message_type = XML_MSG_TAG_RESPONSE;
    
    cl_log(LOG_DEBUG, "Building ipc message - 5.2 (%s)", message_type);
    
    if(reference == NULL) reference = generateReference();
    if(is_request) message_type = XML_MSG_TAG_REQUEST;
    
    if(tmp == NULL) return NULL;
    
    int sub_type_len = strlen(tmp) + strlen(message_type) + 2; // 2 = "_" + '\0'
    cl_log(LOG_DEBUG, "Building ipc message - 5.3");
    char *sub_type_target = (char*)ha_malloc(sizeof(char)*(sub_type_len));
    cl_log(LOG_DEBUG, "Building ipc message - 5.4");
    sprintf(sub_type_target, "%s_%s", tmp, message_type);
    cl_log(LOG_DEBUG, "Building ipc message - 5.5 (%s)", sub_type_target);
    xmlNodePtr xml_node   = xmlNewNode(NULL, sub_type_target);
//	ha_free(sub_type_target);
    xmlSetProp(xml_node, XML_MSG_ATTR_REFERENCE, reference);
    
    cl_log(LOG_DEBUG, "Building ipc message - 5.6");
    if(data != NULL)
    {
	xmlAddChild(xml_node, data);
//	xmlSetProp(data, XML_MSG_ATTR_REFERENCE, reference);
    }
    
    cl_log(LOG_DEBUG, "Building ipc message - 5.7");
    return xml_node;
}


const char *
generateReference(void)
{
    return getNow();
}

gboolean
conditional_add_failure(xmlNodePtr failed, xmlNodePtr target, int operation, int return_code)
{
  gboolean was_error = FALSE;

  if(return_code < 0)
    {
      was_error = TRUE;

      // do some fabulous logging
      
      xmlNodePtr xml_node = xmlNewNode(NULL, XML_FAIL_TAG_CIB);
      xmlSetProp(xml_node, XML_FAILCIB_ATTR_ID, ID(target));
      xmlSetProp(xml_node, XML_FAILCIB_ATTR_OBJTYPE, TYPE(target));

      char buffer[20]; // will handle 64 bit integers

      /* for now just put in the operation code
       * later, convert it to text based
       */
      sprintf(buffer, "%d", operation);
      xmlSetProp(xml_node, XML_FAILCIB_ATTR_OP, buffer);

      /* for now just put in the return code
       * later, convert it to text based on the operation
       */
      sprintf(buffer, "%d", return_code);
      xmlSetProp(xml_node, XML_FAILCIB_ATTR_REASON, buffer);
      
      xmlAddChild(failed, xml_node);
    }

  return was_error;
}


xmlNodePtr
validate_crm_message(xmlNodePtr root_xml_node, const char *sys, const char *msg_type)
{
    if(root_xml_node == NULL) return NULL;

    const char *from = xmlGetProp(root_xml_node, XML_MSG_ATTR_SRCSUBSYS);
    const char *to = xmlGetProp(root_xml_node, XML_MSG_ATTR_SUBSYS);
    const char *type = xmlGetProp(root_xml_node, XML_MSG_ATTR_MSGTYPE);
    const char *reference = xmlGetProp(root_xml_node, XML_MSG_ATTR_REFERENCE);

    cl_log(LOG_DEBUG, "Recieved XML message with (version=%s)"       , xmlGetProp(root_xml_node, XML_ATTR_VERSION));
    cl_log(LOG_DEBUG, "Recieved XML message with (from=%s)"          , from);
    cl_log(LOG_DEBUG, "Recieved XML message with (to=%s)"            , to);
    cl_log(LOG_DEBUG, "Recieved XML message with (type=%s)"          , type);
    cl_log(LOG_DEBUG, "Recieved XML message with (ref=%s)"           , reference);

    if(to == NULL)
    {
	cl_log(LOG_INFO, "No sub-system defined.");
	return NULL;
    }
    else if(sys != NULL && strcmp(to, sys) != 0)
    {
	cl_log(LOG_DEBUG, "The message is not for this sub-system (%s != %s).", to, sys);
	return NULL;
    }
    
    if(type == NULL)
    {
	cl_log(LOG_INFO, "No message type defined.");
	return NULL;
    }
    else if(msg_type != NULL && strcmp(msg_type, type) != 0)
    {
	cl_log(LOG_INFO, "Expecting a (%s) message but receieved a (%s).", msg_type, type);
	return NULL;
    }

    if(reference == NULL)
    {
	cl_log(LOG_INFO, "No message reference defined.");
	return NULL;
    }
    
    xmlNodePtr action = findNode(root_xml_node, type);
    if(action == NULL)
    {
	cl_log(LOG_INFO, "Malformed XML.  Message type (%s) not found.", type);
	return NULL;
    }

    /* when the msg is a request, the message will contain <dest_sys>_request node.
     *   Otherwise it will contain a <src_sys>_response node.
     */
    const char *action_sys = from;
    if(strcmp("request", type) == 0)
    {
	action_sys = to;
    }

    int action_len = strlen(action_sys) + strlen(type) + 2;
    char *action_target = (char*)ha_malloc(sizeof(char)*(action_len));
    sprintf(action_target, "%s_%s", action_sys, type);
    action_target[action_len-1] = '\0';
    
    action = findNode(action, action_target);
    if(action == NULL)
    {
	cl_log(LOG_ERR, "Malformed XML.  Message action (%s) not found... discarding message.", action_target);
	return NULL;
    }

    
    cl_log(LOG_DEBUG, "XML is valid and node with message type (%s) found.", type);
    return action;
}

// callers responsibility to free name and value
gboolean decodeNVpair(const char *srcstring, char separator, char **name, char **value)
{
    int lpc = 0;
    const char *temp = NULL;

    CRM_DEBUG2("Attempting to decode: [%s]", srcstring);
    if(srcstring != NULL)
    {
	int len = strlen(srcstring);
	while(lpc < len)
	{
	    if(srcstring[lpc++] == separator)
	    {
		*name = (char*)ha_malloc(sizeof(char)*lpc);
		CRM_DEBUG2("Malloc ok %d", lpc);
		strncpy(*name, srcstring, lpc-1);
		CRM_DEBUG2("Strcpy ok %d", lpc-1);
		(*name)[lpc-1] = '\0';
		CRM_DEBUG2("Found token [%s]", *name);

                // this sucks but as the strtok *is* a bug
		len = len-lpc+1;
		*value = (char*)ha_malloc(sizeof(char)*len);
		CRM_DEBUG2("Malloc ok %d", len);
		temp = srcstring+lpc;
		CRM_DEBUG("Doing str copy");
		strncpy(*value, temp, len-1);
		(*value)[len-1] = '\0';
		CRM_DEBUG2("Found token [%s]", *value);

		return TRUE;
	    }
	}
    }

    *name = NULL;
    *value = NULL;
    
    return FALSE;
}

