/* $Id: io.c,v 1.47 2006/02/15 13:19:14 andrew Exp $ */
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
#include <sys/stat.h>

#include <string.h>
#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>

#include <heartbeat.h>
#include <crm/crm.h>

#include <cibio.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <clplumbing/cl_misc.h>
#include <clplumbing/lsb_exitcodes.h>

#include <cibprimatives.h>

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

extern gboolean cib_writes_enabled;
extern char *ccm_transition_id;
extern gboolean cib_have_quorum;
extern GHashTable *peer_hash;
extern GHashTable *ccm_membership;
extern GTRIGSource *cib_writer;

int set_connected_peers(crm_data_t *xml_obj);
void GHFunc_count_peers(gpointer key, gpointer value, gpointer user_data);
int write_cib_contents(gpointer p);

/*
 * It is the callers responsibility to free the output of this function
 */
crm_data_t*
readCibXml(char *buffer)
{
	crm_data_t *root = NULL;
	if(buffer != NULL) {
		root = string2xml(buffer);
	}

	do_id_check(root, NULL);
	
	if (verifyCibXml(root) == FALSE) {
		free_xml(root);
		root = createEmptyCib();
		crm_xml_add(root, XML_ATTR_GENERATION_ADMIN, "0");
		crm_xml_add(root, XML_ATTR_GENERATION, "0");
		crm_xml_add(root, XML_ATTR_NUMUPDATES, "0");
	}
	return root;
}

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

/*
 * It is the callers responsibility to free the output of this function
 */
crm_data_t*
readCibXmlFile(const char *filename)
{
	int s_res = -1;
	struct stat buf;

	const char *name = NULL;
	const char *value = NULL;

	crm_data_t *root = NULL;
	crm_data_t *status = NULL;
	
	if(filename != NULL) {
		s_res = stat(filename, &buf);
	}
	
	if (s_res == 0) {
		FILE *cib_file = NULL;
		struct passwd *cib_user = getpwnam(HA_CCMUSER);
		gboolean user_readwritable = (
			cib_user != NULL
			&& buf.st_uid == cib_user->pw_uid
			&& (buf.st_mode & (S_IRUSR|S_IWUSR)));

		if( S_ISREG(buf.st_mode) == FALSE ) {
			crm_err("%s must be a regular file", filename);
			exit(100);
			
		} else if( user_readwritable == FALSE ) {
			struct group *cib_grp = getgrnam(HA_APIGROUP);
			gboolean group_readwritable = (
				cib_grp != NULL
				&& buf.st_gid == cib_grp->gr_gid
				&& (buf.st_mode & (S_IRGRP|S_IWGRP)));

			if( group_readwritable == FALSE ) {
				crm_err("%s must be owned and read/writeable by user %s,"
					" or owned and read/writable by group %s",
					filename, HA_CCMUSER, HA_APIGROUP);
				exit(100);
			}
			crm_warn("%s should be owned and read/writeable by user %s",
				 filename, HA_CCMUSER);
		}

		cib_file = fopen(filename, "r");
		crm_info("Reading cluster configuration from: %s", filename);
		root = file2xml(cib_file);
		crm_xml_add(root, "generated", XML_BOOLEAN_FALSE);
		fclose(cib_file);
	}

	if(root == NULL && s_res == 0) {
		crm_crit("Parse ERROR reading %s.", filename);
		crm_crit("Inhibiting respawn by Heartbeat to avoid loss"
			 " of configuration data.");
		sleep(3); /* give the messages a little time to be logged */
		exit(100);

	} else if(root == NULL) {
		crm_warn("Cluster configuration not found: %s."
			 "  Creating an empty one.", filename);
		return NULL;
	}

	crm_log_xml_info(root, "[on-disk]");
	
	/* strip out the status section if there is one */
	status = find_xml_node(root, XML_CIB_TAG_STATUS, TRUE);
	if(status != NULL) {
		free_xml_from_parent(root, status);
	}
	create_xml_node(root, XML_CIB_TAG_STATUS);

	/* fill in some defaults */
	name = XML_ATTR_GENERATION_ADMIN;
	value = crm_element_value(root, name);
	if(value == NULL) {
		crm_xml_add(root, name, "0");
	}
	
	name = XML_ATTR_GENERATION;
	value = crm_element_value(root, name);
	if(value == NULL) {
		crm_xml_add(root, name, "0");
	}
	
	name = XML_ATTR_NUMUPDATES;
	value = crm_element_value(root, name);
	if(value == NULL) {
		crm_xml_add(root, name, "0");
	}
	
	do_id_check(root, NULL);

	if (verifyCibXml(root) == FALSE) {
		free_xml(root);
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
	gboolean is_valid = TRUE;
	crm_data_t *tmp_node = NULL;

	if(new_cib == NULL) {
		return FALSE;
	}
	
	xml_validate(new_cib);

	tmp_node = get_object_root(XML_CIB_TAG_NODES, new_cib);
	if (tmp_node == NULL) { is_valid = FALSE; }

	tmp_node = get_object_root(XML_CIB_TAG_RESOURCES, new_cib);
	if (tmp_node == NULL) { is_valid = FALSE; }

	tmp_node = get_object_root(XML_CIB_TAG_CONSTRAINTS, new_cib);
	if (tmp_node == NULL) { is_valid = FALSE; }

	tmp_node = get_object_root(XML_CIB_TAG_CRMCONFIG, new_cib);
	if (tmp_node == NULL) { is_valid = FALSE; }

	tmp_node = get_object_root(XML_CIB_TAG_STATUS, new_cib);
	if (is_valid && tmp_node == NULL) {
		create_xml_node(new_cib, XML_CIB_TAG_STATUS);
	}

	if(is_valid == FALSE) {
		crm_warn("CIB Verification failed");
		return FALSE;
	}

	update_counters(__FILE__, __FUNCTION__, new_cib);
	
	the_cib = new_cib;
	initialized = TRUE;
	return TRUE;
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
			if (ext != NULL) { back_ext = (char*)ext; }
	    
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

/*
 * This method will free the old CIB pointer on success and the new one
 * on failure.
 */
int
activateCibXml(crm_data_t *new_cib, const char *filename)
{
	int error_code = cib_ok;
	crm_data_t *saved_cib = get_the_CIB();
	const char *filename_bak = CIB_BACKUP; /* calculate */

	crm_log_xml_debug_4(new_cib, "Attempting to activate CIB");

	CRM_ASSERT(new_cib != saved_cib);
	if(saved_cib != NULL) {
		crm_validate_data(saved_cib);
	}
	
	if (initializeCib(new_cib) == FALSE) {
		crm_warn("Ignoring invalid or NULL CIB");
		error_code = -1;

	} else if(cib_writes_enabled) {
		int local_rc = moveFile(filename, filename_bak, FALSE, NULL);
		if(local_rc != 0) {
			crm_err("Could not make backup of the current CIB..."
				 " disabling writes.");
			cib_writes_enabled = FALSE;
		}
		
		if(cib_writes_enabled) {
			crm_debug_2("Triggering CIB write");
			G_main_set_trigger(cib_writer);
		}
	}

	if(error_code != cib_ok && saved_cib != NULL) {
		int local_rc = 0;
		crm_crit("Reverting to last known CIB (%d)...", error_code);
		CRM_DEV_ASSERT(initializeCib(saved_cib));
		if (crm_assert_failed) {
			/* oh we are so dead  */
			crm_crit("Could not re-initialize with the old CIB.");
			local_rc = -3;
		}

		if(local_rc == 0 && cib_writes_enabled) {
			local_rc = moveFile(filename_bak, filename,FALSE,NULL);
			CRM_DEV_ASSERT(local_rc >= 0);
			if (crm_assert_failed){
				/* At least if we stay up the config isnt lost
				 */
				crm_crit("Could not restore the backup of the "
					 " current Cib... disabling writes");
				cib_writes_enabled = FALSE;
			}
		}
		
	} else if(error_code != cib_ok) {
		crm_crit("Could not write out new CIB and no saved"
			 " version to revert to");
	}
	
	if(the_cib != saved_cib && the_cib != new_cib) {
		CRM_DEV_ASSERT(error_code != cib_ok);
		CRM_DEV_ASSERT(the_cib == NULL);
	}

	if(the_cib != new_cib) {
		free_xml(new_cib);
		CRM_DEV_ASSERT(error_code != cib_ok);
	}

	if(the_cib != saved_cib) {
		free_xml(saved_cib);
	}
	
	return error_code;
    
}

int write_cib_contents(gpointer p) 
{
	int rc = 0;
	crm_data_t *cib_status_root = NULL;

	/* we can scribble on "the_cib" here and not affect the parent */
	const char *epoch = crm_element_value(the_cib, XML_ATTR_GENERATION);
	const char *updates = crm_element_value(the_cib, XML_ATTR_NUMUPDATES);
	const char *admin_epoch = crm_element_value(
		the_cib, XML_ATTR_GENERATION_ADMIN);
	
	crm_info("Writing version %s.%s.%s of the CIB to disk",
		 admin_epoch?admin_epoch:"0",
		 epoch?epoch:"0", updates?updates:"0");
	
	/* Given that we discard the status section on startup
	 *   there is no point writing it out in the first place
	 *   since users just get confused by it
	 *
	 * Although, it does help me once in a while
	 *
	 * So delete the status section before we write it out
	 */
	cib_status_root = find_xml_node(the_cib, XML_CIB_TAG_STATUS, TRUE);
	CRM_DEV_ASSERT(cib_status_root != NULL);
	
	if(cib_status_root != NULL) {
		free_xml_from_parent(the_cib, cib_status_root);
	}
	
	rc = write_xml_file(the_cib, CIB_FILENAME);

	CRM_DEV_ASSERT(rc != -1 && rc != 0);
	if(crm_assert_failed) {
		crm_err("Changes activated but couldn't be written to disk");
		exit(LSB_EXIT_GENERIC);
	}
	exit(LSB_EXIT_OK);
	return HA_OK;
}

gboolean
set_transition(crm_data_t *xml_obj)
{
	const char *current = crm_element_value(
		xml_obj, XML_ATTR_CCM_TRANSITION);
	if(safe_str_neq(current, ccm_transition_id)) {
		crm_debug("CCM transition: old=%s, new=%s",
			  current, ccm_transition_id);
		crm_xml_add(xml_obj, XML_ATTR_CCM_TRANSITION,ccm_transition_id);
		return TRUE;
	}
	return FALSE;
}

gboolean
set_connected_peers(crm_data_t *xml_obj)
{
	int active = 0;
	int current = 0;
	char *peers_s = NULL;
	const char *current_s = crm_element_value(xml_obj, XML_ATTR_NUMPEERS);

	g_hash_table_foreach(peer_hash, GHFunc_count_peers, &active);
	current = crm_parse_int(current_s, "0");
	if(current != active) {
		peers_s = crm_itoa(active);
		crm_xml_add(xml_obj, XML_ATTR_NUMPEERS, peers_s);
		crm_debug("We now have %s active peers", peers_s);
		crm_free(peers_s);
		return TRUE;
	}
	return FALSE;
}

gboolean
update_quorum(crm_data_t *xml_obj) 
{
	const char *quorum_value = XML_BOOLEAN_FALSE;
	const char *current = crm_element_value(xml_obj, XML_ATTR_HAVE_QUORUM);
	if(cib_have_quorum) {
		quorum_value = XML_BOOLEAN_TRUE;
	}
	if(safe_str_neq(current, quorum_value)) {
		crm_debug("CCM quorum: old=%s, new=%s",
			  current, quorum_value);
		crm_xml_add(xml_obj, XML_ATTR_HAVE_QUORUM, quorum_value);
		return TRUE;
	}
	return FALSE;
}


gboolean
update_counters(const char *file, const char *fn, crm_data_t *xml_obj) 
{
	gboolean did_update = FALSE;

	did_update = did_update || update_quorum(xml_obj);
	did_update = did_update || set_transition(xml_obj);
	did_update = did_update || set_connected_peers(xml_obj);
	
	if(did_update) {
		do_crm_log(LOG_DEBUG, file, fn, "Counters updated");
	}
	return did_update;
}



void GHFunc_count_peers(gpointer key, gpointer value, gpointer user_data)
{
	int *active = user_data;
	if(safe_str_eq(value, ONLINESTATUS)) {
		(*active)++;
		
	} else if(safe_str_eq(value, JOINSTATUS)) {
		(*active)++;
	}
}

