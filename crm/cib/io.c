/* $Id: io.c,v 1.6 2005/02/01 22:45:12 andrew Exp $ */
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

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

#include <string.h>
#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>

#include <cibio.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>

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
crm_data_t *the_cib = NULL;
crm_data_t *node_search = NULL;
crm_data_t *resource_search = NULL;
crm_data_t *constraint_search = NULL;
crm_data_t *status_search = NULL;


/*
 * It is the callers responsibility to free the output of this function
 */
crm_data_t*
readCibXml(char *buffer)
{
	crm_data_t *root = string2xml(buffer);
	if (verifyCibXml(root) == FALSE) {
		free_xml(root);
		return createEmptyCib();
	}
	return root;
}

/*
 * It is the callers responsibility to free the output of this function
 */
crm_data_t*
readCibXmlFile(const char *filename)
{
	int s_res = -1;
	struct stat buf;
	crm_data_t *root = NULL;
	

	if(filename != NULL) {
		s_res = stat(filename, &buf);
	}
	
	if (s_res == 0) {
		FILE *cib_file = fopen(filename, "r");
		root = file2xml(cib_file);
		set_xml_property_copy(root, "generated", XML_BOOLEAN_FALSE);
		fclose(cib_file);
		
	} else {
		crm_warn("Stat of (%s) failed, file does not exist.",
			 CIB_FILENAME);
	}
	
	if (verifyCibXml(root) == FALSE) {
		free_xml(root);
/*		return createEmptyCib(); */
		root = NULL;
	}

	return root;
}

/*
 * The caller should never free the return value
 */
crm_data_t*
get_the_CIB(void)
{
	return the_cib;
}

gboolean
uninitializeCib(void)
{
	crm_data_t *tmp_cib = the_cib;
	
	
	if(tmp_cib == NULL) {
		crm_err("The CIB has already been deallocated.");
		return FALSE;
	}
	
	initialized = FALSE;
	the_cib = NULL;
	node_search = NULL;
	resource_search = NULL;
	constraint_search = NULL;
	status_search = NULL;

	crm_err("Deallocating the CIB.");
	
	free_xml(tmp_cib);

	crm_err("The CIB has been deallocated.");
	
	return TRUE;
}




/*
 * This method will not free the old CIB pointer or the new one.
 * We rely on the caller to have saved a pointer to the old CIB
 *   and to free the old/bad one depending on what is appropriate.
 */
gboolean
initializeCib(crm_data_t *new_cib)
{
	if (verifyCibXml(new_cib)) {

		initialized = FALSE;
		the_cib = new_cib;

		/* update search paths */
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

		crm_trace("CIB initialized");
		return TRUE;
	}
	else {
		crm_warn("CIB Verification failed");
	}
	
	return FALSE;
    
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
				return -1;
			}
		}
	}
    
	s_res = stat(oldname, &tmp);

	if (s_res >= 0) {
		res = link(oldname, newname);
		if (res < 0) {
			perror("Could not create backup of current Cib");
			return -2;
		}
		res = unlink(oldname);
		if (res < 0) {
			perror("Could not unlink the current Cib");
			return -3;
		}
	}
    
	return 0;
    
}


int
activateCibBuffer(char *buffer, const char *filename)
{
	int result = -1;
	crm_data_t *local_cib = NULL;
	
	
	local_cib = readCibXml(buffer);
	result = activateCibXml(local_cib, filename);
	
	return result;
}

/*
 * This method will free the old CIB pointer on success and the new one
 * on failure.
 */
int
activateCibXml(crm_data_t *new_cib, const char *filename)
{
	int error_code = 0;
	crm_data_t *saved_cib = get_the_CIB();
	const char *filename_bak = CIB_BACKUP; /* calculate */

	if (initializeCib(new_cib) == TRUE) {
		int res = moveFile(filename, filename_bak, FALSE, NULL);
	
		if (res  < 0) {
			crm_warn("Could not make backup of the current Cib "
				 "(code: %d)... aborting update.", res);
			error_code = -1;
		} else {
			crm_debug("Writing CIB out to %s", CIB_FILENAME);
			res = write_xml_file(new_cib, CIB_FILENAME);
#ifdef DEVEL_CIB_COPY
			write_xml_file(new_cib, DEVEL_DIR"/cib.xml");
#endif
			if (res < 0) {
				/* assume 0 is good */
				if (moveFile(filename_bak,
					     filename,
					     FALSE,
					     NULL) < -1) {
					crm_crit("Could not restore the "
						 "backup of the current Cib "
						 "(code: %d)... panic!",
						 res);
					error_code = -2;
					/* should probably exit here  */
				} else if (initializeCib(saved_cib) == FALSE) {
					/* oh we are so dead  */
					crm_crit("Could not re-initialize "
						 "with the old CIB.  "
						 "Everything is about to go "
						 "pear shaped");
					error_code = -3;
				} else {
					crm_crit("Update of Cib failed "
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
		crm_warn("Ignoring invalid or NULL Cib");
		error_code = -5;
	}

	/* Make sure memory is cleaned up appropriately */
	if (error_code != 0) {
		crm_trace("Freeing new CIB %p", new_cib);
		free_xml(new_cib);
	} else {
		crm_trace("Freeing saved CIB %p", saved_cib);
		free_xml(saved_cib);
	}

	return error_code;
    
}
