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

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <libxml/tree.h>
#include <cibio.h>
#include <crm/common/msgutils.h> // for getNow()
#include <crm/common/xmltags.h>
#include <crm/common/xmlutils.h>

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
    (void)_ha_msg_h_Id; // until the lmb cleanup
    // real code...
    xmlDocPtr cib = xmlNewDoc("1.0");
//    xmlNodePtr tree, subtree;

    cib->children = xmlNewDocNode(cib, NULL, "cib", NULL);
    set_xml_property_copy(cib->children, "version", "1");
    set_xml_property_copy(cib->children, "generated", "true");
    set_xml_property_copy(cib->children, XML_ATTR_TSTAMP, getNow());        

    xmlAddChild(cib->children, xmlNewNode(NULL, XML_CIB_TAG_NODES));
    xmlAddChild(cib->children, xmlNewNode(NULL, XML_CIB_TAG_RESOURCES));
    xmlAddChild(cib->children, xmlNewNode(NULL, XML_CIB_TAG_CONSTRAINTS));
    xmlAddChild(cib->children, xmlNewNode(NULL, XML_CIB_TAG_STATUS));

    xmlNodePtr root = xmlDocGetRootElement(cib);
    if(verifyCibXml(root))
    {
	FNRET(root);
    }
    cl_log(LOG_CRIT, "The generated CIB did not pass integrity testing!!  All hope is lost.");
    FNRET(NULL);
}

gboolean
verifyCibXml(xmlNodePtr cib)
{
    if(cib == NULL)
    {
	cl_log(LOG_INFO, "XML Buffer was empty.");
	FNRET(FALSE);
    }

    xmlNodePtr tmp1 = find_xmlnode(cib, XML_CIB_TAG_NODES);
    xmlNodePtr tmp2 = find_xmlnode(cib, XML_CIB_TAG_RESOURCES);
    xmlNodePtr tmp3 = find_xmlnode(cib, XML_CIB_TAG_CONSTRAINTS);
    xmlNodePtr tmp4 = find_xmlnode(cib, XML_CIB_TAG_STATUS);
    
    if(tmp1 == NULL || tmp2 == NULL || tmp3 == NULL || tmp4 == NULL)
    {
	xmlChar *mem = NULL;
	int size = 0;

	// check for memory leak
	xmlDocDumpMemory(cib->doc, &mem, &size);
	cl_log(LOG_CRIT, "Not all required sections were present. Sections [%s, %s, %s, %s]\nCib was: %s", tmp1 == NULL? "ok":"null", tmp2 == NULL? "ok":"null", tmp3 == NULL? "ok":"null", tmp4 == NULL? "ok":"null", (char*)mem);
	FNRET(FALSE);
    }

    // more integrity tests

    FNRET(TRUE);
}


/*
 * It is the callers responsibility to free the output of this function
 */
xmlNodePtr
readCibXml(char *buffer)
{
   xmlDocPtr doc = xmlParseMemory(buffer, strlen(buffer));
   if(doc == NULL)
   {
       cl_log(LOG_INFO, "XML Buffer was not valid...\n Buffer: %s", buffer);
   }
   xmlNodePtr root = xmlDocGetRootElement(doc);
   if(verifyCibXml(root) == FALSE)
   {
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
    
    cl_log(LOG_DEBUG, "Stat of (%s) was (%d).", CIB_FILENAME, s_res);
    
    xmlDocPtr doc = NULL;
    if(s_res == 0)
    {
	doc = xmlParseFile(filename);
	set_xml_property_copy(xmlDocGetRootElement(doc), "generated", "false");
    }
   xmlNodePtr root = xmlDocGetRootElement(doc);
   if(verifyCibXml(root) == FALSE)
   {
       free_xml(root);
       FNRET(createEmptyCib());
   }
   FNRET(root);
}

/*
 * The caller should never free the return value
 */
xmlNodePtr
theCib(void)
{
    FNRET(the_cib);
}

/*
 * The caller should never free the return value
 */
xmlNodePtr
getCibSection(const char *section)
{
    CRM_DEBUG2("Looking for section (%s) of the CIB", section);

    if(section == NULL || strcmp("all", section) == 0)
    {
	FNRET(the_cib);
    }

    xmlNodePtr res = find_xmlnode(the_cib, section);

    // make sure the siblings dont turn up as well
    if(res != NULL) res = xmlLinkedCopyNoSiblings(res, 1);
    else if(the_cib == NULL)
    {
	cl_log(LOG_CRIT, "The CIB has not been initialized!");
	
    }
    else cl_log(LOG_ERR, "Section (%s) not found.", section);
    
    FNRET(res);
}


/*
 * This method will not free the old CIB pointer or the new one.
 * We rely on the caller to have saved a pointer to the old CIB
 *   and to free the old/bad one depending on what is appropriate.
 */
gboolean
initializeCib(xmlNodePtr new_cib)
{
    if(verifyCibXml(new_cib))
    {

	initialized = FALSE;
	the_cib = new_cib;

	// update search paths
	node_search = updatedSearchPath(new_cib, XML_CIB_TAG_NODES);
	resource_search = updatedSearchPath(new_cib, XML_CIB_TAG_RESOURCES);
	constraint_search = updatedSearchPath(new_cib, XML_CIB_TAG_CONSTRAINTS);
	status_search = updatedSearchPath(new_cib, XML_CIB_TAG_STATUS);
	initialized = TRUE;

	FNRET(TRUE);
    }
    FNRET(FALSE);
    
}


/*
 * The caller should never free the return value
 */
xmlNodePtr
updatedSearchPath(xmlNodePtr cib, const char *path)
{
//    const char *last_path = path[DIMOF(path)-1];
    cl_log(LOG_INFO, "Updating (%s) search path.", path);
    xmlNodePtr parent = find_xmlnode(cib, path);
    if(parent == NULL)
	cl_log(LOG_CRIT, "Updating %s search path failed.", path);
    cl_log(LOG_INFO, "Updating (%s) search path to (%s).", path, xmlGetNodePath(parent) );
    FNRET(parent);
}


int
moveFile(const char *oldname, const char *newname, gboolean backup, char *ext)
{
    /* move 'oldname' to 'newname' by creating a hard link to it
     *  and then removing the original hard link
     */
    int res = 0;
    struct stat tmp;
    int s_res = stat(newname, &tmp);

    cl_log(LOG_INFO, "Stat of %s (code: %d).", newname, s_res);
    if(s_res >= 0)
    {
	if(backup == TRUE)
	{
	    char backname[1024];
	    static const char *back_ext = "bak";
	    if(ext != NULL) back_ext = (char*)ext;
	    
	    snprintf(backname, sizeof(backname)-1, "%s.%s", newname, back_ext);
	    moveFile(newname, backname, FALSE, NULL);
	}
	else
	{
	    res = unlink(newname);
	    if(res < 0)
	    {
		perror("Could not remove the current backup of Cib");
		FNRET(-1);
	    }
	}
    }
    
    s_res = stat(oldname, &tmp);
    cl_log(LOG_INFO, "Stat of %s (code: %d).", oldname, s_res);

    if(s_res >= 0)
    {
	res = link(oldname, newname);
	if(res < 0)
	{
	    perror("Could not create backup of current Cib");
	    FNRET(-2);
	}
	res = unlink(oldname);
	if(res < 0)
	{
	    perror("Could not unlink the current Cib");
	    FNRET(-3);
	}
    }
    
    FNRET(0);
    
}


int
activateCibBuffer(char *buffer)
{
    xmlNodePtr local_cib = readCibXml(buffer);
    FNRET(activateCibXml(local_cib));
    free_xml(local_cib);
}

/*
 * This method will free the old CIB pointer on success and the new one on failure.
 */
int
activateCibXml(xmlNodePtr new_cib)
{
    int error_code = 0;
    xmlNodePtr saved_cib = theCib();

    if(initializeCib(new_cib) == FALSE)
    {
	int res = moveFile(CIB_FILENAME, CIB_BACKUP, FALSE, NULL);
	
	if(res  < 0)
	{
	    cl_log(LOG_INFO, "Could not make backup of the current Cib (code: %d)... aborting update.", res);
	    error_code = -1;
	}
	else
	{
	    // modify the timestamp
	    set_xml_property_copy(new_cib, XML_ATTR_TSTAMP, getNow());        
	    
	    cl_log(LOG_INFO, "Writing CIB out to %s", CIB_FILENAME);
	    
	    if(new_cib->doc == NULL)
	    {
		cl_log(LOG_INFO, "Writing of a node tree with a NULL document will fail, creating a new back link.");
		xmlDocPtr foo = xmlNewDoc("1.0");
		xmlSetTreeDoc(new_cib,foo);
	    }
	    
	    
	    /* save it.  set arg 3 to 0 to disable line breaks, 1 to enable
	     * res == num bytes saved
	     */
	    res = xmlSaveFormatFile(CIB_FILENAME, new_cib->doc, 0);
	    // for some reason, reading back after saving with line-breaks doesnt go real well 
	    
	    cl_log(LOG_INFO, "Saved %d bytes to the Cib as XML", res);
	    
	    if(res < 0) // assume 0 is good
	    {
		if(moveFile(CIB_BACKUP, CIB_FILENAME, FALSE, NULL) < -1)
		{
		    cl_log(LOG_CRIT, "Could not restore the backup of the current Cib (code: %d)... panic!", res);
		    error_code = -2;
		    // should probably exit here 
		}
		else
		{
		    cl_log(LOG_CRIT,
			   "Update of Cib failed (code: %d)... reverted to last known valid version",
			   res);

		    if(initializeCib(saved_cib) == FALSE)
		    {
			// oh we are so dead
			cl_log(LOG_CRIT,
			       "Could not re-initialize with the old CIB.  Everything is about to go pear shaped");
			error_code = -3;
		    }
		    else
		    {
			cl_log(LOG_INFO,
			       "Re-initializing with the old CIB succeeded.  Recovery complete.");
			error_code = -4;
		    }
		}
	    }
	}
    }
    else
    {
	cl_log(LOG_INFO, "Ignoring invalid or NULL Cib");
	error_code = -5;
    }

    // Make sure memory is cleaned up appropriately
    if(error_code < 0)
	free_xml(new_cib);
    else
	free_xml(saved_cib);
    
    FNRET(error_code);
    
}
