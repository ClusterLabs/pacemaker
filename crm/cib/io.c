/* $Id: io.c,v 1.51 2006/03/10 10:08:35 andrew Exp $ */
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

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include <clplumbing/md5.h>

/* "c048eae664dba840e1d2060f00299e9d" */
static char *
calculate_cib_digest(crm_data_t *local_cib)
{
	int i = 0;
	int digest_len = 16;
	char *digest = NULL;
	unsigned char *raw_digest = NULL;
	char *buffer = dump_xml_formatted(local_cib);

	CRM_DEV_ASSERT(buffer != NULL && strlen(buffer) > 0);

	crm_malloc0(digest, sizeof(char) * (2 * digest_len + 1));
	crm_malloc0(raw_digest, sizeof(char) * (digest_len + 1));
	MD5((unsigned char *)buffer, strlen(buffer), raw_digest);
         for(i = 0; i < digest_len; i++) {
 		sprintf(digest+(2*i), "%02x", raw_digest[i]);
 	}
        crm_debug_2("Digest is: %s\n", digest);
	crm_free(buffer);
	crm_free(raw_digest);
	return digest;
}

static gboolean
validate_cib_digest(crm_data_t *local_cib)
{
	int s_res = -1;
	struct stat buf;
	char *digest = NULL;
	char *expected = NULL;
	gboolean passed = FALSE;
	FILE *expected_strm = NULL;
	int start = 0, length = 0, read_len = 0;

	if(local_cib != NULL) {
		digest = calculate_cib_digest(local_cib);
	}
	
	s_res = stat(CIB_FILENAME ".sig", &buf);
	
	if (s_res != 0) {
		crm_warn("No on-disk digest present");
		return TRUE;
	}

	expected_strm = fopen(CIB_FILENAME ".sig", "r");
	start  = ftell(expected_strm);
	fseek(expected_strm, 0L, SEEK_END);
	length = ftell(expected_strm);
	fseek(expected_strm, 0L, start);
	
	CRM_ASSERT(start == ftell(expected_strm));

	crm_debug_3("Reading %d bytes from file", length);
	crm_malloc0(expected, sizeof(char) * (length+1));
	read_len = fread(expected, sizeof(char), length, expected_strm);
	CRM_ASSERT(read_len == length);

	if(expected == NULL) {
		crm_err("On-disk digest is empty");
		
	} else if(safe_str_eq(expected, digest)) {
		crm_debug("Digest comparision passed: %s", digest);
		passed = TRUE;

	} else {
		crm_err("Digest comparision failed: %s vs. %s",
			expected, digest);
	}

 	crm_free(digest);
 	crm_free(expected);
	return passed;
}

static int
write_cib_digest(crm_data_t *local_cib, char *digest)
{
	int rc = 0;
	FILE *digest_strm = fopen(CIB_FILENAME ".sig", "w");
	char *local_digest = NULL;
	CRM_ASSERT(digest_strm != NULL);

	if(digest == NULL) {
		digest = calculate_cib_digest(local_cib);
		CRM_ASSERT(digest != NULL);
		local_digest = digest;
	}
	
	rc = fprintf(digest_strm, "%s", digest);
	if(rc < 0) {
		cl_perror("Cannot write output to %s.sig", CIB_FILENAME);
	}

	fflush(digest_strm);
	fclose(digest_strm);
	crm_free(local_digest);
	return rc;
}

static gboolean
validate_on_disk_cib(const char *filename, crm_data_t **on_disk_cib)
{
	int s_res = -1;
	struct stat buf;
	FILE *cib_file = NULL;
	gboolean passed = TRUE;
	crm_data_t *root = NULL;
	
	if(filename != NULL) {
		s_res = stat(filename, &buf);
	}
	
	if (s_res == 0) {
		cib_file = fopen(filename, "r");
		crm_debug_2("Reading cluster configuration from: %s", filename);
		root = file2xml(cib_file);
		fclose(cib_file);
		
		if(validate_cib_digest(root) == FALSE) {
			passed = FALSE;
		}
	}
	
	if(on_disk_cib != NULL) {
		*on_disk_cib = root;
	} else {
		free_xml(root);
	}
	return passed;
}

/*
 * It is the callers responsibility to free the output of this function
 */
crm_data_t*
readCibXmlFile(const char *filename)
{
	int s_res = -1;
	struct stat buf;
	gboolean valid = FALSE;

	const char *name = NULL;
	const char *value = NULL;
	
	crm_data_t *root = NULL;
	crm_data_t *status = NULL;

	struct passwd *cib_user = NULL;
	gboolean user_readwritable = FALSE;
	
	if(filename != NULL) {
		s_res = stat(filename, &buf);
	}
	
	if (s_res != 0) {
		return NULL;
	}
	
	cib_user = getpwnam(HA_CCMUSER);
	user_readwritable = (cib_user != NULL
			     && buf.st_uid == cib_user->pw_uid
			     && (buf.st_mode & (S_IRUSR|S_IWUSR)));
	
	if( S_ISREG(buf.st_mode) == FALSE ) {
		crm_err("%s must be a regular file", filename);
		cl_flush_logs();
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
			cl_flush_logs();
			exit(100);
		}
		crm_warn("%s should be owned and read/writeable by user %s",
			 filename, HA_CCMUSER);
	}
	
	crm_info("Reading cluster configuration from: %s", filename);
	valid = validate_on_disk_cib(filename, &root);
	crm_log_xml_info(root, "[on-disk]");

	if(root == NULL) {
		crm_crit("Parse ERROR reading %s.", filename);
		crm_crit("Inhibiting respawn by Heartbeat to avoid loss"
			 " of configuration data.");
		cl_flush_logs();
		exit(100);

	} else if(valid == FALSE) {
		crm_err("%s has been manually changed"
			" - please update the md5 digest in %s.sig",
			filename, filename);
		cl_flush_logs();
		exit(100);
	}

	crm_xml_add(root, "generated", XML_BOOLEAN_FALSE);
	
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
		crm_crit("%s does not contain a vaild configuration.",
			 filename);
		crm_crit("Inhibiting respawn by Heartbeat to avoid loss"
			 " of configuration data.");
		cl_flush_logs();
		exit(100);
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

static int
archive_file(const char *oldname, const char *newname, const char *ext)
{
	/* move 'oldname' to 'newname' by creating a hard link to it
	 *  and then removing the original hard link
	 */
	int rc = 0;
	int res = 0;
	struct stat tmp;
	int s_res = 0;
	char *backup_file = NULL;
	static const char *back_ext = "bak";

	/* calculate the backup name if required */
	if(newname != NULL) {
		backup_file = crm_strdup(newname);

	} else {
		crm_malloc0(backup_file, 1024);
		if (ext == NULL) {
			ext = back_ext;
		}
		snprintf(backup_file, strlen(backup_file)-1,
			 "%s.%s", oldname, ext);
	}

	if(backup_file == NULL || strlen(backup_file) == 0) {
		crm_err("%s backup filename was %s",
			newname == NULL?"calculated":"supplied",
			backup_file == NULL?"null":"empty");
		rc = -4;		
	}
	
	s_res = stat(backup_file, &tmp);
	
	/* unlink the old backup */
	if (rc == 0 && s_res >= 0) {
		res = unlink(backup_file);
		if (res < 0) {
			cl_perror("Could not unlink %s", backup_file);
			rc = -1;
		}
	}
    
	s_res = stat(oldname, &tmp);

	/* copy */
	if (rc == 0 && s_res >= 0) {
		res = link(oldname, backup_file);
		if (res < 0) {
			cl_perror("Could not create backup %s from %s",
				  backup_file, oldname);
			rc = -2;
		}
	}

	/* unlink the original */
	if (rc == 0 && s_res >= 0) {
		res = unlink(oldname);
		if (res < 0) {
			cl_perror("Could not unlink %s", oldname);
			rc = -3;
		}
	}

	crm_free(backup_file);
	return rc;
    
}

/*
 * This method will free the old CIB pointer on success and the new one
 * on failure.
 */
int
activateCibXml(crm_data_t *new_cib, const char *ignored)
{
	int error_code = cib_ok;
	crm_data_t *saved_cib = get_the_CIB();

	crm_log_xml_debug_4(new_cib, "Attempting to activate CIB");

	CRM_ASSERT(new_cib != saved_cib);
	if(saved_cib != NULL) {
		crm_validate_data(saved_cib);
	}
	
	if (initializeCib(new_cib) == FALSE) {
		crm_err("Ignoring invalid or NULL CIB");
		error_code = -1;
		if(saved_cib != NULL) {
			crm_warn("Reverting to last known CIB");
			if (initializeCib(saved_cib)) {
				/* oh we are so dead  */
				crm_crit("Couldn't re-initialize the old CIB!");
				cl_flush_logs();
				exit(1);
			}
			
		} else if(error_code != cib_ok) {
			crm_crit("Could not write out new CIB and no saved"
				 " version to revert to");
		}

	} else if(cib_writes_enabled) {
		crm_debug_2("Triggering CIB write");
		G_main_set_trigger(cib_writer);
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

int
write_cib_contents(gpointer p) 
{
	int rc = 0;
	char *digest = NULL;
	crm_data_t *cib_status_root = NULL;
	const char *digest_filename = CIB_FILENAME ".sig";

	/* we can scribble on "the_cib" here and not affect the parent */
	const char *epoch = crm_element_value(the_cib, XML_ATTR_GENERATION);
	const char *updates = crm_element_value(the_cib, XML_ATTR_NUMUPDATES);
	const char *admin_epoch = crm_element_value(
		the_cib, XML_ATTR_GENERATION_ADMIN);

	/* check the admin didnt modify it underneath us */
	if(validate_on_disk_cib(CIB_FILENAME, NULL) == FALSE) {
		crm_err("%s was manually modified while Heartbeat was active!",
			CIB_FILENAME);
		exit(LSB_EXIT_GENERIC);
	}

	rc = archive_file(CIB_FILENAME, NULL, "last");
	if(rc != 0) {
		crm_err("Could not make backup of the existing CIB: %d", rc);
		exit(LSB_EXIT_GENERIC);
	}

	rc = archive_file(digest_filename, NULL, "last");
	if(rc != 0) {
		crm_warn("Could not make backup of the existing CIB digest: %d",
			rc);
	}

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
	if(rc <= 0) {
		crm_err("Changes couldn't be written to disk");
		exit(LSB_EXIT_GENERIC);
	}

	digest = calculate_cib_digest(the_cib);
	crm_info("Wrote version %s.%s.%s of the CIB to disk (digest: %s)",
		 admin_epoch?admin_epoch:"0",
		 epoch?epoch:"0", updates?updates:"0", digest);	
	
	rc = write_cib_digest(the_cib, digest);
	if(rc <= 0) {
		crm_err("Digest couldn't be written to disk");
		exit(LSB_EXIT_GENERIC);
	}

#if 0
	if(validate_on_disk_cib(CIB_FILENAME, NULL) == FALSE) {
		crm_err("wrote incorrect digest");
		exit(LSB_EXIT_GENERIC);
	}
#endif
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

