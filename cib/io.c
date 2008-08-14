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

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <string.h>
#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>

#include <heartbeat.h>
#include <crm/crm.h>

#include <cibio.h>
#include <crm/cib.h>
#include <crm/common/util.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/common/cluster.h>
#include <clplumbing/cl_misc.h>
#include <clplumbing/lsb_exitcodes.h>

#include <cibprimatives.h>

#define CIB_WRITE_PARANOIA	0

int archive_file(const char *oldname, const char *newname, const char *ext, gboolean preserve);

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
xmlNode *node_search = NULL;
xmlNode *resource_search = NULL;
xmlNode *constraint_search = NULL;
xmlNode *status_search = NULL;

extern gboolean cib_writes_enabled;
extern GTRIGSource *cib_writer;
extern enum cib_errors cib_status;

int set_connected_peers(xmlNode *xml_obj);
void GHFunc_count_peers(gpointer key, gpointer value, gpointer user_data);
int write_cib_contents(gpointer p);
extern void cib_cleanup(void);


static gboolean
validate_cib_digest(xmlNode *local_cib, const char *sigfile)
{
	int s_res = -1;
	struct stat buf;
	char *digest = NULL;
	char *expected = NULL;
	gboolean passed = FALSE;
	FILE *expected_strm = NULL;
	int start = 0, length = 0, read_len = 0;
	
	CRM_ASSERT(sigfile != NULL);
	s_res = stat(sigfile, &buf);
	
	if (s_res != 0) {
		crm_warn("No on-disk digest present");
		return TRUE;
	}

	if(local_cib != NULL) {
	    digest = calculate_xml_digest(local_cib, FALSE, FALSE);
	}
	
	expected_strm = fopen(sigfile, "r");
	if(expected_strm == NULL) {
		cl_perror("Could not open signature file %s for reading", sigfile);
		goto bail;
	}

	start  = ftell(expected_strm);
	fseek(expected_strm, 0L, SEEK_END);
	length = ftell(expected_strm);
	fseek(expected_strm, 0L, start);
	
	CRM_ASSERT(start == ftell(expected_strm));

	crm_debug_3("Reading %d bytes from file", length);
	crm_malloc0(expected, (length+1));
	read_len = fread(expected, 1, length, expected_strm);
	CRM_ASSERT(read_len == length);
	fclose(expected_strm);

  bail:
	if(expected == NULL) {
		crm_err("On-disk digest is empty");
		
	} else if(safe_str_eq(expected, digest)) {
		crm_debug_2("Digest comparision passed: %s", digest);
		passed = TRUE;

	} else {
		crm_err("Digest comparision failed: expected %s (%s), calculated %s",
			expected, sigfile, digest);
	}

 	crm_free(digest);
 	crm_free(expected);
	return passed;
}

static int
write_cib_digest(xmlNode *local_cib, char *digest)
{
	int rc = 0;
	char *local_digest = NULL;
	FILE *digest_strm = fopen(CIB_FILENAME ".sig", "w");
	if(digest_strm == NULL) {
		cl_perror("Cannot open signature file "CIB_FILENAME ".sig for writing");
		return -1;
	}

	if(digest == NULL) {
		local_digest = calculate_xml_digest(local_cib, FALSE, FALSE);
		CRM_ASSERT(digest != NULL);
		digest = local_digest;
	}
	
	rc = fprintf(digest_strm, "%s", digest);
	if(rc < 0) {
		cl_perror("Cannot write to signature file "CIB_FILENAME ".sig");
	}

	CRM_ASSERT(digest_strm != NULL);
	if(fflush(digest_strm) != 0) {
	    cl_perror("fflush for %s failed:", digest);
	    rc = -1;
	}
	
	if(fsync(fileno(digest_strm)) < 0) {
	    cl_perror("fsync for %s failed:", digest);
	    rc = -1;
	}
	
	fclose(digest_strm);
	crm_free(local_digest);
	return rc;
}

static gboolean
validate_on_disk_cib(const char *filename, xmlNode **on_disk_cib)
{
	int s_res = -1;
	struct stat buf;
	gboolean passed = TRUE;
	xmlNode *root = NULL;

	CRM_ASSERT(filename != NULL);
	
	s_res = stat(filename, &buf);
	if (s_res == 0) {
		char *sigfile = NULL;
		size_t		fnsize;
		crm_debug_2("Reading cluster configuration from: %s", filename);
		root = filename2xml(filename);
		
		fnsize =  strlen(filename) + 5;
		crm_malloc0(sigfile, fnsize);
		snprintf(sigfile, fnsize, "%s.sig", filename);
		if(validate_cib_digest(root, sigfile) == FALSE) {
			passed = FALSE;
		}
		crm_free(sigfile);
	}
	
	if(on_disk_cib != NULL) {
		*on_disk_cib = root;
	} else {
		free_xml(root);
	}
	
	return passed;
}

static int
cib_unlink(const char *file)
{
    int rc = unlink(file);
    if (rc < 0) {
	cl_perror("Could not unlink %s - Disabling disk writes and continuing", file);
	cib_writes_enabled = FALSE;
    }
    return rc;
}

/*
 * It is the callers responsibility to free the output of this function
 */

static xmlNode*
retrieveCib(const char *filename, const char *sigfile, gboolean archive_invalid)
{
    struct stat buf;
    xmlNode *root = NULL;
    crm_info("Reading cluster configuration from: %s (digest: %s)",
	     filename, sigfile);

    if(stat(filename, &buf) != 0) {
	crm_warn("Cluster configuration not found: %s", filename);
	return NULL;
    }

    root = filename2xml(filename);
    
    if(root == NULL) {
	crm_err("%s exists but does NOT contain valid XML. ", filename);
	crm_warn("Continuing but %s will NOT used.", filename);
	
    } else if(validate_cib_digest(root, sigfile) == FALSE) {
	crm_err("Checksum of %s failed!  Configuration contents ignored!", filename);
	crm_err("Usually this is caused by manual changes, "
		"please refer to http://linux-ha.org/v2/faq/cib_changes_detected");
	crm_warn("Continuing but %s will NOT used.", filename);
	free_xml(root);
	root = NULL;

	if(archive_invalid) {
	    int rc = 0;
	    char *suffix = crm_itoa(getpid());
	    
	    /* Archive the original files so the contents are not lost */
	    crm_err("Archiving corrupt or unusable configuration to %s.%s", filename, suffix);
	    rc = archive_file(filename, NULL, suffix, TRUE);
	    if(rc < 0) {
		crm_err("Archival of %s failed - Disabling disk writes and continuing", filename);
		cib_writes_enabled = FALSE;
	    }

	    rc = archive_file(sigfile, NULL, suffix, TRUE);
	    if(rc < 0) {
		crm_err("Archival of %s failed - Disabling disk writes and continuing", sigfile);
		cib_writes_enabled = FALSE;
	    }
	    
	    /* Unlink the original files so they dont get in the way later */
	    cib_unlink(filename);
	    cib_unlink(sigfile);
	    crm_free(suffix);
	}
    }
    return root;
}

xmlNode*
readCibXmlFile(const char *dir, const char *file, gboolean discard_status)
{
	char *filename = NULL, *sigfile = NULL;
	const char *name = NULL;
	const char *value = NULL;
	const char *validation = NULL;
	const char *use_valgrind = getenv("HA_VALGRIND_ENABLED");
	
	xmlNode *root = NULL;
	xmlNode *status = NULL;

	if(!crm_is_writable(dir, file, HA_CCMUSER, NULL, FALSE)) {
		cib_status = cib_bad_permissions;
		return NULL;
	}
	
	filename = crm_concat(dir, file, '/');
	sigfile  = crm_concat(filename, "sig", '.');

	cib_status = cib_ok;
	root = retrieveCib(filename, sigfile, TRUE);
	if(root == NULL) {
	    char *tmp = NULL;
	    
	    /* Try the backups */
	    tmp = filename;
	    filename = crm_concat(tmp, "last", '.');
	    crm_free(tmp);
	    
	    tmp = sigfile;
	    sigfile = crm_concat(tmp, "last", '.');
	    crm_free(tmp);
	    
	    crm_warn("Primary configuration corrupt or unusable, trying backup...");
	    root = retrieveCib(filename, sigfile, FALSE);
	}

	if(root == NULL) {
	    root = createEmptyCib();
	    crm_xml_add(root, XML_ATTR_GENERATION, "0");
	    crm_xml_add(root, XML_ATTR_NUMUPDATES, "0");
	    crm_xml_add(root, XML_ATTR_GENERATION_ADMIN, "0");
	    crm_xml_add(root, XML_ATTR_VALIDATION, LATEST_SCHEMA_VERSION);
	    crm_warn("Continuing with an empty configuration.");
	}	

	if(cib_writes_enabled && use_valgrind) {
	    if(crm_is_true(use_valgrind) || strstr(use_valgrind, "cib")) {
		cib_writes_enabled = FALSE;
		crm_err("HA_VALGRIND_ENABLED: %s",
			getenv("HA_VALGRIND_ENABLED"));
		crm_err("*********************************************************");
		crm_err("*** Disabling disk writes to avoid confusing Valgrind ***");
		crm_err("*********************************************************");
	    }
	}
	
	status = find_xml_node(root, XML_CIB_TAG_STATUS, FALSE);
	if(discard_status && status != NULL) {
		/* strip out the status section if there is one */
		free_xml_from_parent(root, status);
		status = NULL;
	}
	if(status == NULL) {
		create_xml_node(root, XML_CIB_TAG_STATUS);		
	}
	
	/* Do this before DTD validation happens */

	/* fill in some defaults */
	name = XML_ATTR_GENERATION_ADMIN;
	value = crm_element_value(root, name);
	if(value == NULL) {
		crm_warn("No value for %s was specified in the configuration.",
			 name);
		crm_warn("The reccomended course of action is to shutdown,"
			 " run crm_verify and fix any errors it reports.");
		crm_warn("We will default to zero and continue but may get"
			 " confused about which configuration to use if"
			 " multiple nodes are powered up at the same time.");
		crm_xml_add_int(root, name, 0);
	}
	
	name = XML_ATTR_GENERATION;
	value = crm_element_value(root, name);
	if(value == NULL) {
		crm_xml_add_int(root, name, 0);
	}
	
	name = XML_ATTR_NUMUPDATES;
	value = crm_element_value(root, name);
	if(value == NULL) {
		crm_xml_add_int(root, name, 0);
	}
	
	/* unset these and require the DC/CCM to update as needed */
	xml_remove_prop(root, XML_ATTR_DC_UUID);

	if(discard_status) {
		crm_log_xml_debug(root, "[on-disk]");
	}

	validation = crm_element_value(root, XML_ATTR_VALIDATION);
	if(validate_xml(root, NULL, TRUE) == FALSE) {
	    crm_err("CIB does not validate with %s", crm_str(validation));
	    cib_status = cib_dtd_validation;
		
	} else if(validation == NULL) {
	    int version = 0;
	    update_validation(&root, &version, FALSE, FALSE);
	    if(version > 0) {
		crm_notice("Enabling %s validation on"
			   " the existing (sane) configuration",
			   get_schema_name(version));
	    } else {
		crm_err("CIB does not validate with any known DTD or schema");
		cib_status = cib_dtd_validation;
	    }
	}

	crm_free(filename);
	crm_free(sigfile);
	return root;
}

/*
 * The caller should never free the return value
 */
xmlNode*
get_the_CIB(void)
{
	return the_cib;
}

gboolean
uninitializeCib(void)
{
	xmlNode *tmp_cib = the_cib;
	
	
	if(tmp_cib == NULL) {
		crm_debug("The CIB has already been deallocated.");
		return FALSE;
	}
	
	initialized = FALSE;
	the_cib = NULL;
	node_search = NULL;
	resource_search = NULL;
	constraint_search = NULL;
	status_search = NULL;

	crm_debug("Deallocating the CIB.");
	
	free_xml(tmp_cib);

	crm_debug("The CIB has been deallocated.");
	
	return TRUE;
}




/*
 * This method will not free the old CIB pointer or the new one.
 * We rely on the caller to have saved a pointer to the old CIB
 *   and to free the old/bad one depending on what is appropriate.
 */
gboolean
initializeCib(xmlNode *new_cib)
{
	if(new_cib == NULL) {
		return FALSE;
	}
	
	the_cib = new_cib;
	initialized = TRUE;
	return TRUE;
}

static void
sync_file(const char *file) 
{
    FILE *syncme = fopen(file, "a");
    if(syncme == NULL) {
	cl_perror("Cannot open file %s for syncing", file);
	return;
    }
    
    if(fsync(fileno(syncme)) < 0) {
	cl_perror("fsync for %s failed:", file);
    }
    fclose(syncme);
}

int
archive_file(const char *oldname, const char *newname, const char *ext, gboolean preserve)
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
		int max_name_len = 1024;
		crm_malloc0(backup_file, max_name_len);
		if (ext == NULL) {
			ext = back_ext;
		}
		snprintf(backup_file, max_name_len - 1, "%s.%s", oldname, ext);
	}

	if(backup_file == NULL || strlen(backup_file) == 0) {
		crm_err("%s backup filename was %s",
			newname == NULL?"calculated":"supplied",
			backup_file == NULL?"null":"empty");
		rc = -4;		
	}
	
	s_res = stat(backup_file, &tmp);
	
	/* move the old backup */
	if (rc == 0 && s_res >= 0) {
		if(preserve == FALSE) {
			res = unlink(backup_file);
			if (res < 0) {
				cl_perror("Could not unlink %s", backup_file);
				rc = -1;
			}
		} else {
			crm_info("Archive file %s exists... backing it up first", backup_file);
			res = archive_file(backup_file, NULL, NULL, preserve);
			if (res < 0) {
				return res;
			}
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

		} else if(preserve) {
			crm_info("%s archived as %s", oldname, backup_file);

		} else {
			crm_debug("%s archived as %s", oldname, backup_file);
		}
		sync_file(backup_file);
	}
	crm_free(backup_file);
	return rc;
    
}

/*
 * This method will free the old CIB pointer on success and the new one
 * on failure.
 */
int
activateCibXml(xmlNode *new_cib, gboolean to_disk, const char *op)
{
	xmlNode *saved_cib = the_cib;

	CRM_ASSERT(new_cib != saved_cib);
	if(initializeCib(new_cib) == FALSE) {
		free_xml(new_cib);
		crm_err("Ignoring invalid or NULL CIB");

		if(saved_cib != NULL) {
			crm_warn("Reverting to last known CIB");
			if (initializeCib(saved_cib) == FALSE) {
				/* oh we are so dead  */
				crm_crit("Couldn't re-initialize the old CIB!");
				cl_flush_logs();
				exit(1);
			}
			
		} else {
			crm_crit("Could not write out new CIB and no saved"
				 " version to revert to");
		}
		return cib_ACTIVATION;		
	} 

	free_xml(saved_cib);
	if(cib_writes_enabled && cib_status == cib_ok && to_disk) {
	    crm_debug("Triggering CIB write for %s op", op);
	    G_main_set_trigger(cib_writer);
	}
	
	return cib_ok;
    
}

int
write_cib_contents(gpointer p) 
{
	int rc = 0;
	gboolean need_archive = FALSE;
	struct stat buf;
	char *digest = NULL;
	int exit_rc = LSB_EXIT_OK;
	xmlNode *cib_status_root = NULL;
	
	/* we can scribble on "the_cib" here and not affect the parent */
	const char *epoch = crm_element_value(the_cib, XML_ATTR_GENERATION);
	const char *updates = crm_element_value(the_cib, XML_ATTR_NUMUPDATES);
	const char *admin_epoch = crm_element_value(
		the_cib, XML_ATTR_GENERATION_ADMIN);

	if(crm_log_level > LOG_INFO) {
	    crm_log_level--;
	}
	
	need_archive = (stat(CIB_FILENAME, &buf) == 0);
	if (need_archive) {
	    crm_debug("Archiving current version");	    

	    /* check the admin didnt modify it underneath us */
	    if(validate_on_disk_cib(CIB_FILENAME, NULL) == FALSE) {
		crm_err("%s was manually modified while Heartbeat was active!",
			CIB_FILENAME);
		exit_rc = LSB_EXIT_GENERIC;
		goto cleanup;
	    }

#if CIB_WRITE_PARANOIA
	    /* These calls leak, but we're in a separate process that will exit
	     * when the function does... so it's of no consequence
	     */
	    CRM_ASSERT(retrieveCib(CIB_FILENAME, CIB_FILENAME".sig", FALSE) != NULL);
#endif	    
	    rc = archive_file(CIB_FILENAME, NULL, "last", FALSE);
	    if(rc != 0) {
		crm_err("Could not make backup of the existing CIB: %d", rc);
		exit_rc = LSB_EXIT_GENERIC;
		goto cleanup;
	    }
	
	    rc = archive_file(CIB_FILENAME".sig", NULL, "last", FALSE);
	    if(rc != 0) {
		crm_warn("Could not make backup of the existing CIB digest: %d",
			 rc);
	    }

#if CIB_WRITE_PARANOIA
	    CRM_ASSERT(retrieveCib(CIB_FILENAME, CIB_FILENAME".sig", FALSE) != NULL);
	    CRM_ASSERT(retrieveCib(CIB_FILENAME".last", CIB_FILENAME".sig.last", FALSE) != NULL);
	    crm_debug("Verified CIB archive");	    
#endif    
	}
	
	/* Given that we discard the status section on startup
	 *   there is no point writing it out in the first place
	 *   since users just get confused by it
	 *
	 * Although, it does help me once in a while
	 *
	 * So delete the status section before we write it out
	 */
	crm_debug("Writing CIB to disk");	    
	if(p == NULL) {
	    cib_status_root = find_xml_node(the_cib, XML_CIB_TAG_STATUS, TRUE);
	    CRM_DEV_ASSERT(cib_status_root != NULL);
	    
	    if(cib_status_root != NULL) {
		free_xml_from_parent(the_cib, cib_status_root);
	    }
	}
	
	rc = write_xml_file(the_cib, CIB_FILENAME, FALSE);
	crm_debug("Wrote CIB to disk");
	if(rc <= 0) {
		crm_err("Changes couldn't be written to disk");
		exit_rc = LSB_EXIT_GENERIC;
		goto cleanup;
	}

	digest = calculate_xml_digest(the_cib, FALSE, FALSE);
	crm_info("Wrote version %s.%s.%s of the CIB to disk (digest: %s)",
		 admin_epoch?admin_epoch:"0",
		 epoch?epoch:"0", updates?updates:"0", digest);	
	
	rc = write_cib_digest(the_cib, digest);
	crm_debug("Wrote digest to disk");

	if(rc <= 0) {
		crm_err("Digest couldn't be written to disk");
		exit_rc = LSB_EXIT_GENERIC;
		goto cleanup;
	}

	CRM_ASSERT(retrieveCib(CIB_FILENAME, CIB_FILENAME".sig", FALSE) != NULL);
#if CIB_WRITE_PARANOIA
	if(need_archive) {
	    CRM_ASSERT(retrieveCib(CIB_FILENAME".last", CIB_FILENAME".sig.last", FALSE) != NULL);
	}
#endif
	crm_debug("Wrote and verified CIB");

  cleanup:
	crm_free(digest);

	if(p == NULL) {
		/* fork-and-write mode */
		exit(exit_rc);
	}

	/* stand-alone mode */
	return exit_rc;
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

