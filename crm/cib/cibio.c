/* $Id: cibio.c,v 1.10 2004/02/17 22:11:56 lars Exp $ */
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
#include <sys/stat.h>

#include <string.h>
#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>

#include <libxml/tree.h>
#include <cibio.h>
#include <crm/common/msgutils.h> // for getNow()
#include <crm/common/xmltags.h>
#include <crm/common/xmlutils.h>

#include <crm/dmalloc_wrapper.h>

const char * local_resource_path[] =
{
	XML_CIB_TAG_STATUS,
};

const char * resource_path[] =
{
	XML_CIB_TAG_RESOURCES,
};

const char * node_path[] =
{
	XML_CIB_TAG_NODES,
};

const char * constraint_path[] =
{
	XML_CIB_TAG_CONSTRAINTS,
};

gboolean initialized = FALSE;
xmlNodePtr the_cib = NULL;
xmlNodePtr node_search = NULL;
xmlNodePtr resource_search = NULL;
xmlNodePtr constraint_search = NULL;
xmlNodePtr status_search = NULL;

/*
 * It is the callers responsibility to free both the new CIB (output)
 *     and the new CIB (input)
 */
xmlNodePtr
createEmptyCib(void)
{
	xmlNodePtr cib_root = NULL, config = NULL, status = NULL;
	
	cib_root = create_xml_node(NULL, XML_TAG_CIB);

	config = create_xml_node(cib_root, XML_CIB_TAG_CONFIGURATION);
	status = create_xml_node(cib_root, XML_CIB_TAG_STATUS);

	set_node_tstamp(cib_root);
	set_node_tstamp(config);
	set_node_tstamp(status);
	
	set_xml_property_copy(cib_root, "version", "1");
	set_xml_property_copy(cib_root, "generated", "true");

	create_xml_node(config, XML_CIB_TAG_NODES);
	create_xml_node(config, XML_CIB_TAG_RESOURCES);
	create_xml_node(config, XML_CIB_TAG_CONSTRAINTS);
	
	if (verifyCibXml(cib_root)) {
		FNRET(cib_root);
	}
	cl_log(LOG_CRIT,
	       "The generated CIB did not pass integrity testing!!"
	       "  All hope is lost.");
	FNRET(NULL);
}

gboolean
verifyCibXml(xmlNodePtr cib)
{
	gboolean is_valid = TRUE;
	xmlNodePtr tmp_node = NULL;
	FNIN();

	if (cib == NULL) {
		cl_log(LOG_INFO, "XML Buffer was empty.");
		FNRET(FALSE);
	}
	
	tmp_node = get_object_root(XML_CIB_TAG_NODES, cib);
	if (tmp_node == NULL) is_valid = FALSE;

	tmp_node = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	if (tmp_node == NULL) is_valid = FALSE;

	tmp_node = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	if (tmp_node == NULL) is_valid = FALSE;

	tmp_node = get_object_root(XML_CIB_TAG_STATUS, cib);
 	if (tmp_node == NULL) is_valid = FALSE;

	// more integrity tests

	FNRET(TRUE);
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
		       "Section cib[%s[%s]] not present",
		       node_stack[0],
		       node_stack[1]);
	}
	FNRET(tmp_node);
}


/*
 * It is the callers responsibility to free the output of this function
 */
xmlNodePtr
readCibXml(char *buffer)
{
	xmlDocPtr doc = xmlParseMemory(buffer, strlen(buffer));
	if (doc == NULL) {
		cl_log(LOG_INFO,
		       "XML Buffer was not valid...\n Buffer: %s",
		       buffer);
	}
	xmlNodePtr root = xmlDocGetRootElement(doc);
	if (verifyCibXml(root) == FALSE) {
		free_xml(root);
		FNRET(createEmptyCib());
	}
	FNRET(root);
}

/*
 * It is the callers responsibility to free the output of this function
 */
xmlNodePtr
readCibXmlFile(const char *filename)
{
	struct stat buf;
	int s_res = stat(CIB_FILENAME, &buf);
	FNIN();
	
	cl_log(LOG_DEBUG, "Stat of (%s) was (%d).", CIB_FILENAME, s_res);
    
	xmlDocPtr doc = NULL;
	if (s_res == 0) {
		doc = xmlParseFile(filename);
		set_xml_property_copy(xmlDocGetRootElement(doc),
				      "generated",
				      "false");
	}
	xmlNodePtr root = xmlDocGetRootElement(doc);
	if (verifyCibXml(root) == FALSE) {
		free_xml(root);
		FNRET(createEmptyCib());
	}

	FNRET(root);
}

/*
 * The caller should never free the return value
 */
xmlNodePtr
get_the_CIB(void)
{
	FNIN();
	FNRET(the_cib);
}

/*
 * The caller needs to free the return value, it is a copy of the
 *   true data
 */
xmlNodePtr
getCibSection(const char *section)
{
	xmlNodePtr res = NULL;
	FNIN();

	CRM_DEBUG2("Looking for section (%s) of the CIB", section);

	res = get_object_root(section, the_cib);

	// make sure the siblings dont turn up as well
	if (res != NULL)
		res = copy_xml_node_recursive(res, 1);
	else if (the_cib == NULL) {
		cl_log(LOG_CRIT, "The CIB has not been initialized!");
	} else
		cl_log(LOG_ERR, "Section (%s) not found.", section);
    
	FNRET(res);
}

gboolean
uninitializeCib(void)
{
	xmlNodePtr tmp_cib = the_cib;
	FNIN();
	
	if(tmp_cib == NULL) {
		cl_log(LOG_ERR, "The CIB has already been deallocated.");
		FNRET(FALSE);
	}
	
	initialized = FALSE;
	the_cib = NULL;
	node_search = NULL;
	resource_search = NULL;
	constraint_search = NULL;
	status_search = NULL;

	cl_log(LOG_WARNING, "Deallocating the CIB.");
	
	free_xml(tmp_cib);

	cl_log(LOG_WARNING, "The CIB has been deallocated.");
	
	FNRET(TRUE);
}




/*
 * This method will not free the old CIB pointer or the new one.
 * We rely on the caller to have saved a pointer to the old CIB
 *   and to free the old/bad one depending on what is appropriate.
 */
gboolean
initializeCib(xmlNodePtr new_cib)
{
	if (verifyCibXml(new_cib)) {

		initialized = FALSE;
		the_cib = new_cib;

		// update search paths
		/* not used yet...
		node_search =
			get_object_root(XML_CIB_TAG_NODES, new_cib);
		resource_search =
			get_object_root(XML_CIB_TAG_RESOURCES, new_cib);
		constraint_search =
			get_object_root(XML_CIB_TAG_CONSTRAINTS, new_cib);
		status_search =
			get_object_root(XML_CIB_TAG_STATUS, new_cib);
		*/
		initialized = TRUE;

		CRM_DEBUG("CIB initialized");
		FNRET(TRUE);
	}
	else
		CRM_DEBUG("CIB Verification failed");
	FNRET(FALSE);
    
}

int
moveFile(const char *oldname,
	 const char *newname,
	 gboolean backup,
	 char *ext)
{
	/* move 'oldname' to 'newname' by creating a hard link to it
	 *  and then removing the original hard link
	 */
	int res = 0;
	struct stat tmp;
	int s_res = stat(newname, &tmp);
	FNIN();
	
	cl_log(LOG_INFO, "Stat of %s (code: %d).", newname, s_res);
	if (s_res >= 0)
	{
		if (backup == TRUE) {
			char backname[1024];
			static const char *back_ext = "bak";
			if (ext != NULL) back_ext = (char*)ext;
	    
			snprintf(backname, sizeof(backname)-1,
				 "%s.%s", newname, back_ext);
			moveFile(newname, backname, FALSE, NULL);
		} else {
			res = unlink(newname);
			if (res < 0) {
				perror("Could not remove the current backup of Cib");
				FNRET(-1);
			}
		}
	}
    
	s_res = stat(oldname, &tmp);
	cl_log(LOG_INFO, "Stat of %s (code: %d).", oldname, s_res);

	if (s_res >= 0) {
		res = link(oldname, newname);
		if (res < 0) {
			perror("Could not create backup of current Cib");
			FNRET(-2);
		}
		res = unlink(oldname);
		if (res < 0) {
			perror("Could not unlink the current Cib");
			FNRET(-3);
		}
	}
    
	FNRET(0);
    
}


int
activateCibBuffer(char *buffer)
{
	int result = -1;
	xmlNodePtr local_cib = NULL;
	FNIN();
	
	local_cib = readCibXml(buffer);
	result = activateCibXml(local_cib);
	
	FNRET(result);
}

/*
 * This method will free the old CIB pointer on success and the new one
 * on failure.
 */
int
activateCibXml(xmlNodePtr new_cib)
{
	int error_code = 0;
	xmlNodePtr saved_cib = get_the_CIB();

	FNIN();
	
	if (initializeCib(new_cib) == TRUE) {
		int res = moveFile(CIB_FILENAME, CIB_BACKUP, FALSE, NULL);
	
		if (res  < 0) {
			cl_log(LOG_INFO,
			       "Could not make backup of the current Cib "
			       "(code: %d)... aborting update.", res);
			error_code = -1;
		} else {
			// modify the timestamp
			set_node_tstamp(new_cib);
	    
			cl_log(LOG_INFO,
			       "Writing CIB out to %s",
			       CIB_FILENAME);
	    
			if (new_cib->doc == NULL) {
				cl_log(LOG_INFO,
				       "Writing of a node tree with a NULL "
				       "document will fail, creating a new "
				       "back link.");
				xmlDocPtr foo = xmlNewDoc("1.0");
				xmlDocSetRootElement(foo, new_cib);
				xmlSetTreeDoc(new_cib,foo);
			}
	    
	    
			/* save it.
			 * set arg 3 to 0 to disable line breaks,1 to enable
			 * res == num bytes saved
			 */
			res = xmlSaveFormatFile(CIB_FILENAME,
						new_cib->doc,
						0);
			
			/* for some reason, reading back after saving with
			 * line-breaks doesnt go real well 
			 */
			cl_log(LOG_INFO,
			       "Saved %d bytes to the Cib as XML",
			       res);
	    
			if (res < 0) {
				// assume 0 is good
				if (moveFile(CIB_BACKUP,
					     CIB_FILENAME,
					     FALSE,
					     NULL) < -1) {
					cl_log(LOG_CRIT,
					       "Could not restore the "
					       "backup of the current Cib "
					       "(code: %d)... panic!",
					       res);
					error_code = -2;
					// should probably exit here 
				}
				else if (initializeCib(saved_cib) == FALSE){
					// oh we are so dead 
					cl_log(LOG_CRIT,
					       "Could not re-initialize "
					       "with the old CIB.  "
					       "Everything is about to go "
					       "pear shaped");
					error_code = -3;
				} else {
					cl_log(LOG_CRIT,
					       "Update of Cib failed "
					       "(code: %d)... reverted to "
					       "last known valid version",
					       res);
					
					error_code = -4;
				}
			}
		}
	}
	else
	{
		cl_log(LOG_INFO, "Ignoring invalid or NULL Cib");
		error_code = -5;
	}

	CRM_DEBUG2("New CIB %p", new_cib);
	CRM_DEBUG2("Saved CIB %p", saved_cib);

// Make sure memory is cleaned up appropriately
	if (error_code < 0) {
		CRM_DEBUG2("Freeing new CIB %p", new_cib);
		free_xml(new_cib);
	} else {
		CRM_DEBUG2("Freeing saved CIB %p", saved_cib);
		free_xml(saved_cib);
	}
	
	FNRET(error_code);
    
}
