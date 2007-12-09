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

#include <hb_config.h>
#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>

#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h> 

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <clplumbing/md5.h>
#if HAVE_BZLIB_H
#  include <bzlib.h>
#endif

#define XML_BUFFER_SIZE	4096

static const char *filter[] = {
    XML_ATTR_ORIGIN,
    XML_DIFF_MARKER,
    XML_CIB_ATTR_WRITTEN,		
};

int is_comment_start(const char *input, size_t offset, size_t max);
int is_comment_end(const char *input, size_t offset, size_t max);
gboolean drop_comments(const char *input, size_t *offset, size_t max);

void dump_array(
	int log_level, const char *message, const char **array, int depth);

int print_spaces(char *buffer, int spaces);

int log_data_element(const char *function, const char *prefix, int log_level,
		     int depth, const crm_data_t *data, gboolean formatted);

int dump_data_element(
	int depth, char **buffer, const crm_data_t *data, gboolean formatted);

crm_data_t *parse_xml(const char *input, size_t *offset);
int get_tag_name(const char *input, size_t offset, size_t max);
int get_attr_name(const char *input, size_t offset, size_t max);
int get_attr_value(const char *input, size_t offset, size_t max);
gboolean can_prune_leaf(crm_data_t *xml_node);

void diff_filter_context(int context, int upper_bound, int lower_bound,
		    crm_data_t *xml_node, crm_data_t *parent);
int in_upper_context(int depth, int context, crm_data_t *xml_node);

crm_data_t *
find_xml_node(crm_data_t *root, const char * search_path, gboolean must_find)
{
	if(must_find || root != NULL) {
		crm_validate_data(root);
	}
	
	if(search_path == NULL) {
		crm_warn("Will never find <NULL>");
		return NULL;
	}
	
	xml_child_iter_filter(
		root, a_child, search_path,
/* 		crm_debug_5("returning node (%s).", crm_element_name(a_child)); */
		crm_log_xml(LOG_DEBUG_5, "found:", a_child);
		crm_log_xml(LOG_DEBUG_6, "in:",    root);
		crm_validate_data(a_child);
		return a_child;
		);

	if(must_find) {
		crm_warn("Could not find %s in %s.", search_path, crm_element_name(root));
	} else if(root != NULL) {
		crm_debug_3("Could not find %s in %s.", search_path, crm_element_name(root));
	} else {
		crm_debug_3("Could not find %s in <NULL>.", search_path);
	}
	
	
	return NULL;
}

crm_data_t*
find_xml_node_nested(crm_data_t *root, const char **search_path, int len)
{
	int	j;
	gboolean is_found = TRUE;
	crm_data_t *match =  NULL;
	crm_data_t *lastMatch = root;

	crm_validate_data(root);
	
	if(search_path == NULL || search_path[0] == 0) {
		crm_warn("Will never find NULL");
		return NULL;
	}
	
	dump_array(LOG_DEBUG_5, "Looking for.", search_path, len);

	for (j=0; j < len; ++j) {
		if (search_path[j] == NULL) {
/* a NULL also means stop searching */
			break;
		}

		match = find_xml_node(lastMatch, search_path[j], FALSE);
		if(match == NULL) {
			is_found = FALSE;
			break;
		} else {
			lastMatch = match;
		}
	}

	if (is_found) {
		crm_debug_5("returning node (%s).",
			   crm_element_name(lastMatch));

		crm_log_xml_debug_5(lastMatch, "found\t%s");
		crm_log_xml_debug_5(root, "in \t%s");
		
		crm_validate_data(lastMatch);
		return lastMatch;
	}

	dump_array(LOG_DEBUG_2,
		   "Could not find the full path to the node you specified.",
		   search_path, len);

	crm_debug_2("Closest point was node (%s) starting from %s.",
		    crm_element_name(lastMatch), crm_element_name(root));

	return NULL;
    
}



const char *
get_xml_attr_nested(crm_data_t *parent,
		    const char **node_path, int length,
		    const char *attr_name, gboolean error)
{
	const char *attr_value = NULL;
	crm_data_t *attr_parent = NULL;

	if(error || parent != NULL) {
		crm_validate_data(parent);
	}
	
	if(parent == NULL) {
		crm_debug_3("Can not find attribute %s in NULL parent",attr_name);
		return NULL;
	} 

	if(attr_name == NULL || attr_name[0] == 0) {
		crm_err("Can not find attribute with no name in %s",
		       crm_element_name(parent));
		return NULL;
	}
	
	if(length == 0) {
		attr_parent = parent;
		
	} else {
		attr_parent = find_xml_node_nested(parent, node_path, length);
		if(attr_parent == NULL && error) {
			crm_err("No node at the path you specified.");
			return NULL;
		}
	}
	
	attr_value = crm_element_value(attr_parent, attr_name);
	if((attr_value == NULL || attr_value[0] == 0) && error) {
		crm_err("No value present for %s at %s",
			attr_name, crm_element_name(attr_parent));
		return NULL;
	}
	
	return attr_value;
}


crm_data_t*
find_entity(crm_data_t *parent, const char *node_name, const char *id)
{
	crm_validate_data(parent);
	xml_child_iter_filter(
		parent, a_child, node_name,
		if(id == NULL || crm_str_eq(id, ID(a_child), TRUE)) {
			crm_debug_4("returning node (%s).", 
				    crm_element_name(a_child));
			return a_child;
		}
		);
	crm_debug_3("node <%s id=%s> not found in %s.",
		    node_name, id, crm_element_name(parent));
	return NULL;
}

void
copy_in_properties(crm_data_t* target, const crm_data_t *src)
{
	int value_len = 0;
	char *incr_value = NULL;
	char *new_value = NULL;
	
	crm_validate_data(src);
	crm_validate_data(target);

	if(src == NULL) {
		crm_warn("No node to copy properties from");

	} else if (target == NULL) {
		crm_err("No node to copy properties into");

	} else {
		xml_prop_iter(
			src, local_prop_name, local_prop_value,

			/* if the value is name followed by "++" we need
			 *   to increment the existing value
			 */
			new_value = NULL;
			incr_value = NULL;

			if(strstr(local_prop_value, "++") > local_prop_value) {
				int old_int = 0;
				const char *old_value = NULL;
				value_len = strlen(local_prop_value);
				crm_malloc0(incr_value, value_len+2);
				sprintf(incr_value, "%s++", local_prop_name);

				if(safe_str_eq(local_prop_value, incr_value)) {
					old_value = crm_element_value(
						target, local_prop_name);
					old_int = crm_parse_int(old_value, "0");
					new_value = crm_itoa(old_int + 1);
					local_prop_value = new_value;
				}
			}

			crm_xml_add(target, local_prop_name, local_prop_value);
			crm_free(incr_value);
			crm_free(new_value);
			);
		crm_validate_data(target);
	}
	
	return;
}

crm_data_t*
add_node_copy(crm_data_t *parent, const crm_data_t *src_node) 
{
	const char *name = NULL;
	crm_data_t *child = NULL;
	CRM_CHECK(src_node != NULL, return NULL);

	crm_validate_data(src_node);

	name = crm_element_name(src_node);
	CRM_CHECK(name != NULL, return NULL);
	
	child = create_xml_node(parent, name);
	copy_in_properties(child, src_node);

	xml_child_iter(src_node, src_child,
		       add_node_copy(child, src_child);
		);
	
	return child;
}


int
add_node_nocopy(crm_data_t *parent, const char *name, crm_data_t *child)
{

	int next = 0;
	crm_validate_data(parent);
	crm_validate_data(child);	

	if(name == NULL) {
		name = crm_element_name(child);
	}
	if(name == NULL || name[0] == 0) {
	    crm_err("Cannot add object with no name");
	    return HA_FAIL;
	}
	
	if (parent->nfields >= parent->nalloc
		&& ha_msg_expand(parent) != HA_OK ){
		crm_err("Parent expansion failed");
		return HA_FAIL;
	}

	next = parent->nfields;
	parent->names[next] = crm_strdup(name);
	parent->nlens[next] = strlen(name);
	parent->values[next] = child;
	parent->vlens[next] = sizeof(struct ha_msg);
	parent->types[next] = FT_UNCOMPRESS;
	parent->nfields++;	
	
	return HA_OK;
}

const char *
crm_xml_add(crm_data_t* node, const char *name, const char *value)
{
	const char *parent_name = NULL;

	if(node != NULL) {
		parent_name = crm_element_name(node);
	}
	
	crm_debug_5("[%s] Setting %s to %s", crm_str(parent_name), name, value);

	if (name == NULL || name[0] == 0) {
		
	} else if(node == NULL) {
		
	} else if(parent_name == NULL && strcasecmp(name, F_XML_TAGNAME) != 0) {
		
	} else if (value == NULL || value[0] == 0) {
		xml_remove_prop(node, name);
		return NULL;
		
	} else {
		const char *new_value = NULL;
		crm_validate_data(node);
		ha_msg_mod(node, name, value);
		new_value = crm_element_value(node, name);
		return new_value;
	}
	
	return NULL;
}

const char *
crm_xml_add_int(crm_data_t* node, const char *name, int value)
{
	const char *parent_name = NULL;

	if(node != NULL) {
		parent_name = crm_element_name(node);
	}

	crm_debug_5("[%s] Setting %s to %d", crm_str(parent_name), name, value);

	if (name == NULL || name[0] == 0) {
		
	} else if(node == NULL) {
		
	} else if(parent_name == NULL && strcasecmp(name, F_XML_TAGNAME) != 0) {
		
	} else {
		crm_validate_data(node);
		ha_msg_mod_int(node, name, value);
		return crm_element_value(node, name);
	}

	return NULL;
}

crm_data_t*
create_xml_node(crm_data_t *parent, const char *name)
{
	const char *local_name = NULL;
	const char *parent_name = NULL;
	crm_data_t *ret_value = NULL;
	

	if (name == NULL || name[0] == 0) {
		ret_value = NULL;
	} else {
		local_name = name;
		ret_value = ha_msg_new(3);
		CRM_CHECK(ret_value != NULL, return NULL);
		
		crm_xml_add(ret_value, F_XML_TAGNAME, name);
		crm_validate_data(ret_value);
		if(parent) {
			crm_validate_data(parent);
			parent_name = crm_element_name(parent);
			crm_debug_5("Attaching %s to parent %s",
				   local_name, parent_name);
			CRM_CHECK(HA_OK == ha_msg_addstruct(
					  parent, name, ret_value), return NULL);
			crm_msg_del(ret_value);

			crm_validate_data(parent);
			ret_value = parent->values[parent->nfields-1];
		}
	}

	crm_debug_5("Created node [%s [%s]]",
		  crm_str(parent_name), crm_str(local_name));
	return ret_value;
}

void
free_xml_from_parent(crm_data_t *parent, crm_data_t *a_node)
{
	CRM_CHECK(parent != NULL, return);
	CRM_CHECK(a_node != NULL, return);

	crm_validate_data(parent);
	cl_msg_remove_value(parent, a_node);	
	crm_validate_data(parent);
}

void
add_xml_tstamp(crm_data_t *a_node)
{
	char *since_epoch = NULL;
	time_t a_time = time(NULL);
	
	crm_validate_data(a_node);

	if(a_time == (time_t)-1) {
		cl_perror("set_node_tstamp(): Invalid time returned");
		return;
	}
	
	crm_malloc0(since_epoch, 128);
	if(since_epoch != NULL) {
		sprintf(since_epoch, "%ld", (unsigned long)a_time);
		ha_msg_mod(a_node, XML_ATTR_TSTAMP, since_epoch);
		crm_validate_data(a_node);
		crm_free(since_epoch);
	}
}

crm_data_t*
copy_xml(const crm_data_t *src_node)
{
	return add_node_copy(NULL, src_node);
}

crm_data_t*
string2xml(const char *input)
{
	crm_data_t *output = parse_xml(input, NULL);
	if(output != NULL) {
		crm_validate_data(output);
	}
	return output;
}

crm_data_t *
stdin2xml(void) 
{
 	size_t data_length = 0;
 	size_t read_chars = 0;
  
  	char *xml_buffer = NULL;
  	crm_data_t *xml_obj = NULL;
  
 	do {
 		crm_realloc(xml_buffer, XML_BUFFER_SIZE + data_length + 1);
 		read_chars = fread(xml_buffer + data_length, 1, XML_BUFFER_SIZE, stdin);
 		data_length += read_chars;
 	} while (read_chars > 0);
  	
 	xml_buffer[data_length] = '\0';

	xml_obj = string2xml(xml_buffer);
	crm_free(xml_buffer);

	crm_log_xml_debug_3(xml_obj, "Created fragment");
	return xml_obj;
}


crm_data_t*
file2xml(FILE *input, gboolean compressed)
{
	char *buffer = NULL;
	gboolean work_done = FALSE;
	crm_data_t *new_obj = NULL;
	size_t length = 0, read_len = 0;

	if(input == NULL) {
		/* Use perror here as we likely just called fopen() which return NULL */
		cl_perror("File open failed, cannot read contents");
		return NULL;
	}

	if(compressed) {
#if HAVE_BZLIB_H
		int rc = 0;
		BZFILE *bz_file = BZ2_bzReadOpen(&rc, input, 0, 0, NULL, 0);
		if ( rc != BZ_OK ) {
			BZ2_bzReadClose ( &rc, bz_file);
			return NULL;
		}
		
		rc = BZ_OK;
		while ( rc == BZ_OK ) {
			crm_realloc(buffer, XML_BUFFER_SIZE + length + 1);
			read_len = BZ2_bzRead (
				&rc, bz_file, buffer + length, XML_BUFFER_SIZE);

			crm_debug_5("Read %ld bytes from file: %d",
				    (long)read_len, rc);

			if ( rc == BZ_OK || rc == BZ_STREAM_END) {
				length += read_len;
			}
		}

		buffer[length] = '\0';
		read_len = length;

		if ( rc != BZ_STREAM_END ) {
			crm_err("Couldnt read compressed xml from file");
			crm_free(buffer);
			buffer = NULL;
		}

		BZ2_bzReadClose (&rc, bz_file);
		if(buffer == NULL) {
			return NULL;
		}

		work_done = TRUE;
#else
		crm_err("Cannot read compressed files:"
			" bzlib was not available at compile time");
#endif
	}	
	
	if(work_done == FALSE) {
		int start = 0;
		start  = ftell(input);
		fseek(input, 0L, SEEK_END);
		length = ftell(input);
		fseek(input, 0L, start);
		
		CRM_ASSERT(start == ftell(input));
		
		crm_debug_3("Reading %ld bytes from file", (long)length);
		crm_malloc0(buffer, (length+1));
		read_len = fread(buffer, 1, length, input);
	}

	/* see how big the file is */
	if(read_len != length) {
		crm_err("Calculated and read bytes differ: %ld vs. %ld",
			(long)length, (long)read_len);
	} else if(length > 0) {
		new_obj = string2xml(buffer);
	} else {
		crm_warn("File contained no XML");
	}
	
	crm_free(buffer);
	return new_obj;
}

void
dump_array(int log_level, const char *message, const char **array, int depth)
{
	int j;
	
	if(message != NULL) {
		do_crm_log(log_level, "%s", message);
	}

	do_crm_log(log_level,  "Contents of the array:");
	if(array == NULL || array[0] == NULL || depth == 0) {
		do_crm_log(log_level, "\t<empty>");
		return;
	}
	
	for (j=0; j < depth && array[j] != NULL; j++) {
		if (array[j] == NULL) { break; }
		do_crm_log(log_level, "\t--> (%s).", array[j]);
	}
}

int
write_xml_file(crm_data_t *xml_node, const char *filename, gboolean compress) 
{
	int res = 0;
	time_t now;
	char *buffer = NULL;
	char *now_str = NULL;
	unsigned int out = 0;
	FILE *file_output_strm = NULL;
	static mode_t cib_mode = S_IRUSR|S_IWUSR;
	
	CRM_CHECK(filename != NULL, return -1);

	crm_debug_3("Writing XML out to %s", filename);
	crm_validate_data(xml_node);
	if (xml_node == NULL) {
		crm_err("Cannot write NULL to %s", filename);
		return -1;
	}

	file_output_strm = fopen(filename, "w");
	if(file_output_strm == NULL) {
		cl_perror("Cannot open %s for writing", filename);
		return -1;
	} 

	/* establish the correct permissions */
	fchmod(fileno(file_output_strm), cib_mode);
	
	crm_validate_data(xml_node);
	crm_log_xml_debug_4(xml_node, "Writing out");
	crm_validate_data(xml_node);
	
	now = time(NULL);
	now_str = ctime(&now);
	now_str[24] = EOS; /* replace the newline */
	crm_xml_add(xml_node, XML_CIB_ATTR_WRITTEN, now_str);
	crm_validate_data(xml_node);
	
	buffer = dump_xml_formatted(xml_node);
	CRM_CHECK(buffer != NULL && strlen(buffer) > 0, goto bail);	

	if(compress) {
#if HAVE_BZLIB_H
	    int rc = BZ_OK;
	    unsigned int in = 0;
	    BZFILE *bz_file = NULL;
	    bz_file = BZ2_bzWriteOpen(&rc, file_output_strm, 5,0,0);
	    if(rc != BZ_OK) {
		crm_err("bzWriteOpen failed: %d", rc);
	    } else {
		BZ2_bzWrite(&rc,bz_file,buffer,strlen(buffer));
		if(rc != BZ_OK) {
		    crm_err("bzWrite() failed: %d", rc);
		}
	    }
	    
	    if(rc == BZ_OK) {
		BZ2_bzWriteClose(&rc, bz_file, 0, &in, &out);
		if(rc != BZ_OK) {
		    crm_err("bzWriteClose() failed: %d",rc);
		    out = -1;
		} else {
		    crm_debug_2("%s: In: %d, out: %d", filename, in, out);
		}
	    }
#else
	    crm_err("Cannot write compressed files:"
		    " bzlib was not available at compile time");		
#endif
	}
	
	if(out <= 0) {
	    res = fprintf(file_output_strm, "%s", buffer);
	    if(res < 0) {
		cl_perror("Cannot write output to %s", filename);
		goto bail;
	    }		
	}
	
  bail:
	
	if(fflush(file_output_strm) != 0) {
	    cl_perror("fflush for %s failed:", filename);
	    res = -1;
	}
	
	if(fsync(fileno(file_output_strm)) < 0) {
	    cl_perror("fsync for %s failed:", filename);
	    res = -1;
	}
	    
	fclose(file_output_strm);
	
	crm_debug_3("Saved %d bytes to the Cib as XML", res);
	crm_free(buffer);

	return res;
}

void
print_xml_formatted(int log_level, const char *function,
		    const crm_data_t *msg, const char *text)
{
	if(msg == NULL) {
		do_crm_log(log_level, "%s: %s: NULL", function, crm_str(text));
		return;
	}

	crm_validate_data(msg);
	log_data_element(function, text, log_level, 0, msg, TRUE);
	return;
}

crm_data_t *
get_message_xml(HA_Message *msg, const char *field) 
{
	int type = 0;
	crm_data_t *xml_node = NULL;
	
	type = cl_get_type(msg, field);
	if(type < 0) {
	    /* not found */
	    return NULL;
	    
	} else if(type == FT_STRING) {
	    /* Future proof */
	    const char *xml_text = cl_get_string(msg, field);
	    xml_node = string2xml(xml_text);

	} else if(type > FT_BINARY) {
	    HA_Message *tmp_node = NULL;
	    crm_validate_data(msg);
	    tmp_node = cl_get_struct(msg, field);
	    if(tmp_node != NULL) {
		const char *name = cl_get_string(tmp_node, F_XML_TAGNAME);
		if(name == NULL || safe_str_neq(field, name)) {
		    /* Deprecated */
		    xml_node = copy_xml(tmp_node);
		    
		} else {
		    /* Valid XML */
		    xml_child_iter(tmp_node, child, return copy_xml(child));
		}
	    }

	} else if(type == FT_BINARY) {
	    /* Future proof */
	    int rc = BZ_OK;
	    size_t orig_len = 0;
	    unsigned int used = 0;
	    char *uncompressed = NULL;
	    const char *const_value = cl_get_binary(msg, field, &orig_len);
	    char *compressed = NULL;
	    int size = orig_len * 10;

	    if(orig_len < 1) {
		crm_err("Invalid binary field: %s", field);
		return NULL;
	    }
	    crm_malloc0(compressed, orig_len);
	    memcpy(compressed, const_value, orig_len);
	    
	    crm_debug_2("Trying to decompress %d bytes", (int)orig_len);
	  retry:
	    crm_realloc(uncompressed, size);
	    memset(uncompressed, 0, size);
	    used = size;
	    
	    rc = BZ2_bzBuffToBuffDecompress(
		uncompressed, &used, compressed, orig_len, 1, 0);
	    
	    if(rc == BZ_OUTBUFF_FULL) {
		size = size * 2;
		/* dont try to allocate more memory than we have */
		if(size > 0) {
		    goto retry;
		}
	    }
	    
	    if(rc != BZ_OK) {
		crm_err("Decompression of %d bytes into %d failed: %d", (int)orig_len, size, rc);
		
	    } else {
		xml_node = string2xml(uncompressed);
	    }
	    
	    crm_free(compressed);		
	    crm_free(uncompressed);
	}
	
	return xml_node;
}

gboolean
add_message_xml(HA_Message *msg, const char *field, const crm_data_t *xml) 
{
	crm_validate_data(xml);
	crm_validate_data(msg);
	CRM_CHECK(field != NULL, return FALSE);
	ha_msg_addstruct_compress(msg, field, xml);
	return TRUE;
}


char *
dump_xml_formatted(const crm_data_t *an_xml_node)
{
	char *buffer     = NULL;
	char *mutable_ptr = NULL;
	if(an_xml_node == NULL) {
		return NULL;
	}
  	crm_malloc0(buffer, 3*get_stringlen(an_xml_node));
	mutable_ptr = buffer;
	
	crm_validate_data(an_xml_node);
	CRM_CHECK(dump_data_element(
			  0, &mutable_ptr, an_xml_node, TRUE) >= 0,
		  crm_crit("Could not dump the whole message"));
	crm_debug_4("Dumped: %s", buffer);
	return buffer;
}
	
char *
dump_xml_unformatted(const crm_data_t *an_xml_node)
{
	char *buffer     = NULL;
	char *mutable_ptr = NULL;
  	crm_malloc0(buffer, 2*get_stringlen(an_xml_node));
	mutable_ptr = buffer;
	
	crm_validate_data(an_xml_node);
	CRM_CHECK(dump_data_element(
			  0, &mutable_ptr, an_xml_node, FALSE) >= 0,
		  crm_crit("Could not dump the whole message"));

	crm_debug_4("Dumped: %s", buffer);
	return buffer;
}

#define update_buffer_head(buffer, len) if(len < 0) {	\
		(*buffer) = EOS; return -1;		\
	} else {					\
		buffer += len;				\
	}


int
print_spaces(char *buffer, int depth) 
{
	int lpc = 0;
	int spaces = 2*depth;
	/* <= so that we always print 1 space - prevents problems with syslog */
	for(lpc = 0; lpc <= spaces; lpc++) {
		if(sprintf(buffer, "%c", ' ') < 1) {
			return -1;
		}
		buffer += 1;
	}
	return lpc;
}

int
log_data_element(
	const char *function, const char *prefix, int log_level, int depth,
	const crm_data_t *data, gboolean formatted) 
{
	int printed = 0;
	int child_result = 0;
	int has_children = 0;
	char print_buffer[1000];
	char *buffer = print_buffer;
	const char *name = crm_element_name(data);
	const char *hidden = NULL;	

	crm_debug_5("Dumping %s...", name);
	crm_validate_data(data);
	if(data == NULL) {
		crm_warn("No data to dump as XML");
		return 0;

	} else if(name == NULL && depth == 0) {
		xml_child_iter(
			data, a_child, 
			child_result = log_data_element(
				function, prefix, log_level, depth, a_child, formatted);
			if(child_result < 0) {
				return child_result;
			}
			);
		return 0;

	} else if(name == NULL) {
		crm_err("Cannot dump NULL element at depth %d", depth);
		return -1;
	}
	
	if(formatted) {
		printed = print_spaces(buffer, depth);
		update_buffer_head(buffer, printed);
	}
	
	printed = sprintf(buffer, "<%s", name);
	update_buffer_head(buffer, printed);

	hidden = crm_element_value(data, "hidden");
	xml_prop_iter(
		data, prop_name, prop_value,

		if(prop_name == NULL
		   || safe_str_eq(F_XML_TAGNAME, prop_name)) {
			continue;

		} else if(hidden != NULL
			  && prop_name[0] != 0
			  && strstr(hidden, prop_name) != NULL) {
			prop_value = "*****";
		}
		
		crm_debug_5("Dumping <%s %s=\"%s\"...",
			    name, prop_name, prop_value);
		printed = sprintf(buffer, " %s=\"%s\"", prop_name, prop_value);
		update_buffer_head(buffer, printed);
		);

	xml_child_iter(
		data, child, 
		if(child != NULL) {
			has_children++;
			break;
		}
		);

	printed = sprintf(buffer, "%s>", has_children==0?"/":"");
	update_buffer_head(buffer, printed);
	do_crm_log(log_level, "%s: %s%s",
		   function, prefix?prefix:"", print_buffer);
	buffer = print_buffer;
	
	if(has_children == 0) {
		return 0;
	}
	
	xml_child_iter(
		data, a_child, 
		child_result = log_data_element(
			function, prefix, log_level, depth+1, a_child, formatted);

		if(child_result < 0) { return -1; }
		);

	if(formatted) {
		printed = print_spaces(buffer, depth);
		update_buffer_head(buffer, printed);
	}
	do_crm_log(log_level, "%s: %s%s</%s>",
		   function, prefix?prefix:"", print_buffer, name);
	crm_debug_5("Dumped %s...", name);

	return has_children;
}


int
dump_data_element(
	int depth, char **buffer,  const crm_data_t *data, gboolean formatted) 
{
	int printed = 0;
	int child_result = 0;
	int has_children = 0;
	const char *name = NULL;

	if(data == NULL) {
	    return 0;
	}
	
	CRM_ASSERT(buffer != NULL && *buffer != NULL);

	name = crm_element_name(data);
	if(name == NULL && depth == 0) {
		name = "__fake__";

	} else if(name == NULL) {
	    return 0;
	}
	
	crm_debug_5("Dumping %s...", name);

	if(formatted) {
		printed = print_spaces(*buffer, depth);
		update_buffer_head(*buffer, printed);
	}
	
	printed = sprintf(*buffer, "<%s", name);
	update_buffer_head(*buffer, printed);
	has_children = xml_has_children(data);

	xml_prop_iter(data, prop_name, prop_value,
		      crm_debug_5("Dumping <%s %s=\"%s\"...",
				  name, prop_name, prop_value);
		      printed = sprintf(*buffer, " %s=\"%s\"", prop_name, prop_value);
		      update_buffer_head(*buffer, printed);
		);

	printed = sprintf(*buffer, "%s>%s",
			  has_children==0?"/":"", formatted?"\n":"");
	update_buffer_head(*buffer, printed);

	if(has_children == 0) {
		return 0;
	}
	
	xml_child_iter(
		data, child, 
		child_result = dump_data_element(
			depth+1, buffer, child, formatted);

		if(child_result < 0) { return -1; }
		);

	if(formatted) {
		printed = print_spaces(*buffer, depth);
		update_buffer_head(*buffer, printed);
	}
	printed = sprintf(*buffer, "</%s>%s", name, formatted?"\n":"");
	update_buffer_head(*buffer, printed);
	crm_debug_5("Dumped %s...", name);

	return has_children;
}

gboolean
xml_has_children(const crm_data_t *xml_root)
{
	if(xml_root != NULL) {
		xml_child_iter(
			xml_root, a_child, 
			return TRUE;
			);
	}
	return FALSE;
}

void
xml_validate(const crm_data_t *xml_root)
{
	int lpc = 0;
	CRM_ASSERT(xml_root != NULL);
	CRM_ASSERT(cl_is_allocated(xml_root) == 1);
	CRM_ASSERT(xml_root->nfields < 500);
	
	for (lpc = 0; lpc < xml_root->nfields; lpc++) {
		void *child = xml_root->values[lpc];
		CRM_ASSERT(cl_is_allocated(xml_root->names[lpc]) == 1);

		if(child == NULL) {
			
		} else if(xml_root->types[lpc] == FT_STRUCT
			  || xml_root->types[lpc] == FT_UNCOMPRESS) {
			crm_validate_data(child);
			
		} else if(xml_root->types[lpc] == FT_STRING) {
			CRM_ASSERT(cl_is_allocated(child) == 1);
/* 		} else { */
/* 			CRM_CHECK(FALSE); */
		}
	}
}

const char *
crm_element_value(const crm_data_t *data, const char *name)
{
	const char *value = NULL;
	crm_validate_data(data);
	value = cl_get_string(data, name);
#if XML_PARANOIA_CHECKS
	CRM_CHECK(value == NULL || cl_is_allocated(value) == 1, return NULL);
#endif
	return value;
}

char *
crm_element_value_copy(const crm_data_t *data, const char *name)
{
	char *value_copy = NULL;
	const char *value = crm_element_value(data, name);
	if(value != NULL) {
		value_copy = crm_strdup(value);
	}
	return value_copy;
}

const char *
crm_element_name(const crm_data_t *data)
{
#if CRM_DEV_BUILD
	crm_validate_data(data);
#endif
	return cl_get_string(data, F_XML_TAGNAME);
}

void
xml_remove_prop(crm_data_t *obj, const char *name)
{
	if(crm_element_value(obj, name) != NULL) {
		cl_msg_remove(obj, name);
	}
}

int
get_tag_name(const char *input, size_t offset, size_t max) 
{
	char ch = 0;
	size_t lpc = offset;

	const char *error = NULL;
	gboolean do_special = FALSE;
	
	for(; error == NULL && lpc < max; lpc++) {
		ch = input[lpc];
		crm_debug_5("Processing char %c [%d]", ch, (int)lpc);

		switch(ch) {
			case 0:
				error = "unexpected EOS";
				break;
			case '?':
				if(lpc == 0) {
					/* weird xml tag that we dont care about */
					do_special = TRUE;
				} else {
					goto out;
				}
				break;
			case '/':
			case '>':
			case '\t':
			case '\n':
			case ' ':
				if(!do_special) {
					goto out;
				}
				break;
			default:
				if(do_special) {

				} else if('a' <= ch && ch <= 'z') {
				} else if('A' <= ch && ch <= 'Z') {
				} else if(ch == '_') {
				} else if(ch == '-') {
				} else {
					error = "bad character, not in [a-zA-Z_-]";
				}
 				break;
		}
	}
	crm_err("Error parsing token near %.15s: %s", input, crm_str(error));
	return -1;
  out:
	CRM_ASSERT(lpc > offset);
	return lpc - offset;
}

int
get_attr_name(const char *input, size_t offset, size_t max) 
{
	char ch = 0;
	size_t lpc = offset;
	const char *error = NULL;
	
	for(; error == NULL && lpc < max; lpc++) {
		ch = input[lpc];
		crm_debug_5("Processing char %c[%d]", ch, (int)lpc);

		switch(ch) {
			case 0:
				error = "unexpected EOS";
 				break;
			case '\t':
			case '\n':
			case ' ':
				error = "unexpected whitespace";
 				break;
			case '=':
				return lpc - offset;
			default:
				if('a' <= ch && ch <= 'z') {
				} else if('A' <= ch && ch <= 'Z') {
				} else if('0' <= ch && ch <= '9') {
				} else if(ch == '_') {
				} else if(ch == '-') {
				} else {
					error = "bad character, not in [a-zA-Z0-9_-]";
				}
 				break;
		}
	}
	crm_err("Error parsing token near %.15s: %s", input, crm_str(error));
	return -1;
}

int
get_attr_value(const char *input, size_t offset, size_t max) 
{
	char ch = 0;
	size_t lpc = offset;
	const char *error = NULL;
	
	for(; error == NULL && lpc < max; lpc++) {
		ch = input[lpc];
		crm_debug_5("Processing char %c [%d]", ch, (int)lpc);
		
		switch(ch) {
			case 0:
				error = "unexpected EOS";
 				break;
			case '\\':
				if(input[lpc+1] == '"') {
					/* skip over the next char */ 
					lpc++;
					break;
				}
				/*fall through*/
			case '"':
				return lpc - offset;
			default:
 				break;
		}
	}
	crm_err("Error parsing token near %.15s: %s", input, crm_str(error));
	return -1;
}

int
is_comment_start(const char *input, size_t offset, size_t max)
{
	size_t remaining = max - offset;
	CRM_CHECK(input != NULL, return 0);
	CRM_CHECK(offset < max, return 0);
	input += offset;
	
	if(remaining > 4
	   && input[0] == '<'
	   && input[1] == '!'
	   && input[2] == '-'
	   && input[3] == '-') {
		crm_debug_6("Found comment start: <!--");
		return 4;
		
	} else if(remaining > 2
	   && input[0] == '<'
	   && input[1] == '!') {
		crm_debug_6("Found comment start: <!");
		return 2;

	} else if(remaining > 2
	   && input[0] == '<'
	   && input[1] == '?') {
		crm_debug_6("Found comment start: <?");
		return 2;
	}
	if(remaining > 3) {
		crm_debug_6("Not comment start: %c%c%c%c", input[0], input[1], input[2], input[3]);
	} else {
		crm_debug_6("Not comment start");
	}
	
	return 0;
}


int
is_comment_end(const char *input, size_t offset, size_t max)
{
	size_t remaining = max - offset;
	CRM_CHECK(input != NULL, return 0);
	input += offset;
	
	if(remaining > 2
	   && input[0] == '-'
	   && input[1] == '-'
	   && input[2] == '>') {
		crm_debug_6("Found comment end: -->");
		return 3;
		
	} else if(remaining > 1
	   && input[0] == '?'
	   && input[1] == '>') {
		crm_debug_6("Found comment end: ?>");
		return 2;
	}
	if(remaining > 2) {
		crm_debug_6("Not comment end: %c%c%c", input[0], input[1], input[2]);
	} else {
		crm_debug_6("Not comment end");
	}
	return 0;
}

static gboolean
drop_whitespace(const char *input, size_t *offset, size_t max)
{
	char ch = 0;
	size_t lpc = *offset;
	gboolean more = TRUE;
	const char *our_input = input;

	if(input == NULL) {
		return FALSE;
	}
	while(lpc < max && more) {
		ch = our_input[lpc];
		crm_debug_6("Processing char %c[%d]", ch, (int)lpc);
		if(isspace(ch)) {
			lpc++;

		} else {
			more = FALSE;
		}
	}

	crm_debug_4("Finished processing whitespace");
	if(lpc > *offset) {
		crm_debug_5("Skipped %d whitespace chars", (int)(lpc - *offset));
	}
	(*offset) = lpc;	
	return FALSE;
}

gboolean
drop_comments(const char *input, size_t *offset, size_t max)
{
	gboolean more = TRUE;
	gboolean in_directive = FALSE;
	int in_comment = FALSE;
	size_t lpc = 0;
	int tag_len = 0;
	char ch = 0;
	if(input == NULL) {
		return FALSE;
	}

	CRM_ASSERT(offset != NULL);
	lpc = *offset;
	while(lpc < max && more) {
		ch = input[lpc];
		crm_debug_6("Processing char [%d]: %c ", (int)lpc, ch);
		switch(ch) {
			case 0:
				if(in_comment == FALSE) {
					more = FALSE;
				} else {
					crm_err("unexpected EOS");
					crm_warn("Parsing error at or before: %s", input+lpc);
				}
				break;
			case '<':
				tag_len = is_comment_start(input, lpc, max);
				if(tag_len > 0) {
					if(in_comment) {
						crm_err("Nested XML comments are not supported!");
						crm_warn("Parsing error at or before: %s", input+lpc);
					}
					in_comment = TRUE;
					lpc+=tag_len;
					if(tag_len == 2 && input[lpc-1] == '!') {
						in_directive = TRUE;
					}
				} else if(in_comment == FALSE){
					more = FALSE;
					
				} else {
					lpc++;
				}
				break;
			case '>':
				lpc++;
				if(in_directive) {
					in_directive = FALSE;
					in_comment = FALSE;
				}
				break;
			case '-':
			case '?':
				tag_len = is_comment_end(input, lpc, max);
				if(tag_len > 0) {
					lpc+=tag_len;
					in_comment = FALSE;

				} else {
					lpc++;
				}
				break;
			case ' ':
			case '\t':
			case '\n':
			case '\r':
				lpc++;
				break;
			default:
				lpc++;
				break;
		}
	}
	crm_debug_4("Finished processing comments");
	crm_debug_5("Skipped %d comment chars", (int)(lpc - *offset));
	*offset = lpc;
	return FALSE;
}

crm_data_t*
parse_xml(const char *input, size_t *offset)
{
	char ch = 0;
	int len = 0;
	size_t lpc = 0, max = 0;
	char *tag_name = NULL;
	char *attr_name = NULL;
	char *attr_value = NULL;
	gboolean more = TRUE;
	gboolean were_comments = TRUE;
	const char *error = NULL;
	const char *our_input = input;
	crm_data_t *new_obj = NULL;

	if(input == NULL) {
		return NULL;
	}
	if(offset != NULL) {
		our_input = input + (*offset);
	}

	max = strlen(our_input);
	were_comments = drop_comments(our_input, &lpc, max);
	CRM_CHECK(our_input[lpc] == '<', return NULL);
	lpc++;

	len = get_tag_name(our_input, lpc, max);
	crm_debug_5("Tag length: %d", (int)len);
	CRM_CHECK(len > 0, return NULL);

	crm_malloc0(tag_name, len+1);
	strncpy(tag_name, our_input + lpc, len+1);
	tag_name[len] = EOS;
	crm_debug_4("Processing tag %s", tag_name);
	
	new_obj = ha_msg_new(1);
	
	ha_msg_add(new_obj, F_XML_TAGNAME, tag_name);
	lpc += len;

	for(; more && error == NULL && lpc < max; lpc++) {
		ch = our_input[lpc];
		crm_debug_5("Processing char %c[%d]", ch, (int)lpc);
		switch(ch) {
			case 0:
				error = "unexpected EOS";
				break;
			case '/':
				if(our_input[lpc+1] == '>') {
					more = FALSE;
				}
				break;
			case '<':
				if(our_input[lpc+1] == '!') {
					lpc--; /* allow the '<' to be processed */
					drop_comments(our_input, &lpc, max);
					lpc--; /* allow the '<' to be processed */
					
				} else if(our_input[lpc+1] != '/') {
					crm_data_t *child = NULL;
					crm_debug_4("Start parsing child at %d...", (int)lpc);
					
					lpc--;
					child = parse_xml(our_input, &lpc);
					if(child == NULL) {
						error = "error parsing child";
						break;
					} 
					add_node_nocopy(new_obj, NULL, child);
/* 					ha_msg_addstruct_compress( */
/* 						new_obj, crm_element_name(child), child); */
					
					crm_debug_4("Finished parsing child: %s",
						    crm_element_name(child));
					if(our_input[lpc] == '<') {
						lpc--; /* allow the '<' to be processed */
					}
					
				} else {
					lpc += 2; /* </ */
					len = get_tag_name(our_input, lpc, max);
					if(len < 0) {
						error = "couldnt find tag";
						
					} else if(strlen(tag_name) == len
						  && strncmp(our_input+lpc, tag_name, len) == 0) {
						more = FALSE;
						lpc += len;
						if(our_input[lpc] != '>') {
							error = "clase tag cannot contain attrs";
						}
						crm_debug_4("Finished parsing ourselves: %s",
							    crm_element_name(new_obj));
						
					} else {
						error = "Mismatching close tag";
						crm_err("Expected: %s", tag_name);
					}
				}
				break;
			case '=':
				lpc++; /* = */
				/*fall through*/
			case '"':
				lpc++; /* " */
				len = get_attr_value(our_input, lpc, max);
				if(len < 0) {
					error = "couldnt find attr_value";
				} else {
					crm_malloc0(attr_value, len+1);
					strncpy(attr_value, our_input+lpc, len+1);
					attr_value[len] = EOS;
					lpc += len;
					
					crm_debug_4("creating nvpair: <%s %s=\"%s\"...",
						    tag_name, attr_name, attr_value);
					
					ha_msg_add(new_obj, attr_name, attr_value);
					crm_free(attr_name);
					crm_free(attr_value);
				}
				break;
			case '>':
				while(lpc < max && our_input[lpc+1] != '<') {
					lpc++;
				}
				break;
			case ' ':
			case '\t':
			case '\n':
			case '\r':
				break;
			default:
				len = get_attr_name(our_input, lpc, max);
				if(len < 0) {
					error = "couldnt find attr_name";
				} else {
					crm_malloc0(attr_name, len+1);
					strncpy(attr_name, our_input+lpc, len+1);
					attr_name[len] = EOS;
					lpc += len;
					crm_debug_4("found attr name: %s", attr_name);
					lpc--; /* make sure the '=' is seen next time around */
				}
				break;
		}
	}
	
	if(error) {
		crm_err("Error parsing token: %s", error);
		crm_err("Error at or before: %.20s", our_input+lpc-3);
		return NULL;
	}
	
	if(offset == NULL) {
		drop_comments(our_input, &lpc, max);
		drop_whitespace(our_input, &lpc, max);
		if(lpc < max) {
		    if(crm_log_level < LOG_ERR) {
			fprintf(stderr, "%s: Ignoring trailing characters in XML input.  Supply -V for more details.\n", __PRETTY_FUNCTION__);
		    } else {
			cl_log(LOG_ERR, "%s: Ignoring trailing characters in XML input.", __PRETTY_FUNCTION__);
		    }
		    cl_log(LOG_ERR, "%s: Parsed %d characters of a possible %d.  Trailing text was: \'%.20s\'...",
			   __PRETTY_FUNCTION__, (int)lpc, (int)max, our_input+lpc);
		}
	}
	
	crm_debug_4("Finished processing %s tag", tag_name);
	crm_free(tag_name);
	if(offset != NULL) {
		(*offset) += lpc;
	}

	return new_obj;
}

void
log_xml_diff(unsigned int log_level, crm_data_t *diff, const char *function)
{
	crm_data_t *added = find_xml_node(diff, "diff-added", FALSE);
	crm_data_t *removed = find_xml_node(diff, "diff-removed", FALSE);
	gboolean is_first = TRUE;

	if(crm_log_level < log_level) {
		/* nothing will ever be printed */
		return;
	}
	
	xml_child_iter(
		removed, child, 
		log_data_element(function, "-", log_level, 0, child, TRUE);
		if(is_first) {
			is_first = FALSE;
		} else {
			do_crm_log(log_level, " --- ");
		}
		
		);
	is_first = TRUE;
	xml_child_iter(
		added, child, 
		log_data_element(function, "+", log_level, 0, child, TRUE);
		if(is_first) {
			is_first = FALSE;
		} else {
			do_crm_log(log_level, " --- ");
		}
		);
}

void
purge_diff_markers(crm_data_t *a_node)
{
	CRM_CHECK(a_node != NULL, return);

	xml_remove_prop(a_node, XML_DIFF_MARKER);
	xml_child_iter(a_node, child,
		       purge_diff_markers(child);
		);
}

gboolean
apply_xml_diff(crm_data_t *old, crm_data_t *diff, crm_data_t **new)
{
	gboolean result = TRUE;
	const char *digest = crm_element_value(diff, XML_ATTR_DIGEST);
	crm_data_t *added = find_xml_node(diff, "diff-added", FALSE);
	crm_data_t *removed = find_xml_node(diff, "diff-removed", FALSE);

	int root_nodes_seen = 0;

	CRM_CHECK(new != NULL, return FALSE);

	crm_debug_2("Substraction Phase");
	xml_child_iter(removed, child_diff, 
		       CRM_CHECK(root_nodes_seen == 0, result = FALSE);
		       if(root_nodes_seen == 0) {
			       *new = subtract_xml_object(old, child_diff, NULL);
		       }
		       root_nodes_seen++;
		);
	if(root_nodes_seen == 0) {
		*new = copy_xml(old);
		
	} else if(root_nodes_seen > 1) {
		crm_err("(-) Diffs cannot contain more than one change set..."
			" saw %d", root_nodes_seen);
		result = FALSE;
	}

	root_nodes_seen = 0;
	crm_debug_2("Addition Phase");
	if(result) {
		xml_child_iter(added, child_diff, 
			       CRM_CHECK(root_nodes_seen == 0, result = FALSE);
			       if(root_nodes_seen == 0) {
				       add_xml_object(NULL, *new, child_diff);
			       }
			       root_nodes_seen++;
			);
	}

	if(root_nodes_seen > 1) {
		crm_err("(+) Diffs cannot contain more than one change set..."
			" saw %d", root_nodes_seen);
		result = FALSE;

	} else if(result && digest) {
	    char *new_digest = calculate_xml_digest(*new, FALSE, TRUE);
	    if(safe_str_neq(new_digest, digest)) {
		crm_info("Digest mis-match: expected %s, calculated %s",
			 digest, new_digest);
 		result = FALSE;
	    } else {
		crm_debug_2("Digest matched: expected %s, calculated %s",
			    digest, new_digest);
	    }
	    
	} else if(result) {
		int lpc = 0;
		crm_data_t *intermediate = NULL;
		crm_data_t *diff_of_diff = NULL;
		crm_data_t *calc_added = NULL;
		crm_data_t *calc_removed = NULL;

		const char *value = NULL;
		const char *name = NULL;
		const char *version_attrs[] = {
			XML_ATTR_NUMUPDATES,
			XML_ATTR_GENERATION,
			XML_ATTR_GENERATION_ADMIN
		};

		crm_debug_2("Verification Phase");
		intermediate = diff_xml_object(old, *new, FALSE);
		calc_added = find_xml_node(intermediate, "diff-added", FALSE);
		calc_removed = find_xml_node(intermediate, "diff-removed", FALSE);

		/* add any version details to the diff so they match */
		for(lpc = 0; lpc < DIMOF(version_attrs); lpc++) {
			name = version_attrs[lpc];

			value = crm_element_value(added, name);
			crm_xml_add(calc_added, name, value);
			
			value = crm_element_value(removed, name);
			crm_xml_add(calc_removed, name, value);	
		}

		diff_of_diff = diff_xml_object(intermediate, diff, TRUE);
		if(diff_of_diff != NULL) {
			crm_info("Diff application failed!");
			crm_log_xml_debug(old, "diff:original");
			crm_log_xml_debug(diff, "diff:input");
			result = FALSE;
		}
		
		free_xml(diff_of_diff);
		free_xml(intermediate);
		diff_of_diff = NULL;
		intermediate = NULL;
	}
	
	if(result) {
		purge_diff_markers(*new);
	}

	return result;
}


crm_data_t *
diff_xml_object(crm_data_t *old, crm_data_t *new, gboolean suppress)
{
	crm_data_t *diff = NULL;
	crm_data_t *tmp1 = NULL;
	crm_data_t *added = NULL;
	crm_data_t *removed = NULL;

	tmp1 = subtract_xml_object(old, new, "removed:top");
	if(tmp1 != NULL) {
		if(suppress && can_prune_leaf(tmp1)) {
			ha_msg_del(tmp1);

		} else {
			diff = create_xml_node(NULL, "diff");
			removed = create_xml_node(diff, "diff-removed");
			added = create_xml_node(diff, "diff-added");
			add_node_nocopy(removed, NULL, tmp1);
		}
	}
	
	tmp1 = subtract_xml_object(new, old, "added:top");
	if(tmp1 != NULL) {
		if(suppress && can_prune_leaf(tmp1)) {
			ha_msg_del(tmp1);
			return diff;
			
		}

		if(diff == NULL) {
			diff = create_xml_node(NULL, "diff");
		}
		if(removed == NULL) {
			removed = create_xml_node(diff, "diff-removed");
		}
		if(added == NULL) {
			added = create_xml_node(diff, "diff-added");
		}
		add_node_nocopy(added, NULL, tmp1);
	}

	return diff;
}

gboolean
can_prune_leaf(crm_data_t *xml_node)
{
	gboolean can_prune = TRUE;
/* 	return FALSE; */
	
	xml_prop_iter(xml_node, prop_name, prop_value,
		      if(safe_str_eq(prop_name, XML_ATTR_ID)) {
			      continue;
		      }		      
		      can_prune = FALSE;
		);
	xml_child_iter(xml_node, child, 
		       if(can_prune_leaf(child)) {
			       cl_msg_remove_value(xml_node, child);
			       __counter--;
		       } else {
			       can_prune = FALSE;
		       }
		);
	return can_prune;
}


void
diff_filter_context(int context, int upper_bound, int lower_bound,
		    crm_data_t *xml_node, crm_data_t *parent) 
{
	crm_data_t *us = NULL;
	crm_data_t *new_parent = parent;
	const char *name = crm_element_name(xml_node);

	CRM_CHECK(xml_node != NULL && name != NULL, return);
	
	us = create_xml_node(parent, name);
	xml_prop_iter(xml_node, prop_name, prop_value,
		      lower_bound = context;
		      crm_xml_add(us, prop_name, prop_value);
		);
	if(lower_bound >= 0 || upper_bound >= 0) {
		crm_xml_add(us, XML_ATTR_ID, ID(xml_node));
		new_parent = us;

	} else {
		upper_bound = in_upper_context(0, context, xml_node);
		if(upper_bound >= 0) {
			crm_xml_add(us, XML_ATTR_ID, ID(xml_node));
			new_parent = us;
		} else {
			free_xml(us);
			us = NULL;
		}
	}

	xml_child_iter(us, child, 
		       diff_filter_context(
			       context, upper_bound-1, lower_bound-1,
			       child, new_parent);
		);
}

int
in_upper_context(int depth, int context, crm_data_t *xml_node)
{
	gboolean has_attributes = FALSE;
	if(context == 0) {
		return 0;
	}
	
	xml_prop_iter(xml_node, prop_name, prop_value,
		      has_attributes = TRUE;
		      break;
		);
	
	if(has_attributes) {
		return depth;

	} else if(depth < context) {
		xml_child_iter(xml_node, child, 
			       if(in_upper_context(depth+1, context, child)) {
				       return depth;
			       }
			);
	}
	return 0;       
}


crm_data_t *
subtract_xml_object(crm_data_t *left, crm_data_t *right, const char *marker)
{
	gboolean skip = FALSE;
	gboolean differences = FALSE;
	crm_data_t *diff = NULL;
	crm_data_t *child_diff = NULL;
	crm_data_t *right_child = NULL;

	const char *id = NULL;
	const char *name = NULL;
	const char *value = NULL;
	const char *right_val = NULL;

	int lpc = 0;
	static int filter_len = DIMOF(filter);
	
	crm_log_xml(LOG_DEBUG_5, "left:",  left);
	crm_log_xml(LOG_DEBUG_5, "right:", right);
	
	if(left == NULL) {
		return NULL;

	}
	id = ID(left);
	if(right == NULL) {
		crm_data_t *deleted = NULL;

		crm_debug_5("Processing <%s id=%s> (complete copy)",
			    crm_element_name(left), id);
		deleted = copy_xml(left);
		crm_xml_add(deleted, XML_DIFF_MARKER, marker);

		return deleted;
	}

	name = crm_element_name(left);

	/* sanity checks */
	CRM_CHECK(name != NULL, return NULL);

/* 	these checks are costly haven't caught anything for a while	*/
/* 	CRM_CHECK(safe_str_eq(crm_element_name(left),			*/
/* 			      crm_element_name(right)), return NULL);	*/
/* 	CRM_CHECK(safe_str_eq(id, ID(right)), return NULL);		*/
	
	diff = create_xml_node(NULL, name);

	/* changes to name/value pairs */
	crm_debug_5("Processing <%s id=%s>", crm_str(name), id);

	xml_prop_iter(left, prop_name, left_value,
		      if(crm_str_eq(prop_name, XML_ATTR_ID, TRUE)) {
			      continue;
		      }

		      skip = FALSE;
		      for(lpc = 0; skip == FALSE && lpc < filter_len; lpc++){
			      if(crm_str_eq(prop_name, filter[lpc], TRUE)) {
				      skip = TRUE;
			      }
		      }
		      
		      if(skip) { continue; }
		      
		      right_val = crm_element_value(right, prop_name);
		      if(right_val == NULL) {
			      differences = TRUE;
			      crm_xml_add(diff, prop_name, left_value);
			      crm_debug_6("\t%s: %s", crm_str(prop_name),
					  crm_str(left_value));
				      
		      } else if(safe_str_eq(left_value, right_val)) {
			      crm_debug_5("\t%s: %s (removed)",
					  crm_str(prop_name),
					  crm_str(left_value));
		      } else {
			      differences = TRUE;
			      crm_xml_add(diff, prop_name, left_value);
			      crm_debug_5("\t%s: %s->%s",
					  crm_str(prop_name),
					  crm_str(left_value),
					  right_val);
		      }
		);

	/* changes to child objects */
	crm_debug_3("Processing children of <%s id=%s>",crm_str(name),id);
	xml_child_iter(
		left, left_child,  
		right_child = find_entity(
			right, crm_element_name(left_child), ID(left_child));
		child_diff = subtract_xml_object(
			left_child, right_child, marker);
		if(child_diff != NULL) {
			differences = TRUE;
			add_node_nocopy(diff, NULL, child_diff);
		}
		
		);

	if(differences == FALSE) {
		/* check for XML_DIFF_MARKER in a child */ 
		xml_child_iter(
			right, right_child,  
			value = crm_element_value(right_child, XML_DIFF_MARKER);
			if(value != NULL && safe_str_eq(value, "removed:top")) {
				crm_debug_3("Found the root of the deletion: %s", name);
				crm_log_xml_debug_3(right_child, "deletion");
				differences = TRUE;
				break;
			}
			);
	}
	
	if(differences == FALSE) {
		free_xml(diff);
		crm_debug_5("\tNo changes to <%s id=%s>", crm_str(name), id);
		return NULL;
	}
	crm_xml_add(diff, XML_ATTR_ID, id);
	return diff;
}

int
add_xml_object(crm_data_t *parent, crm_data_t *target, const crm_data_t *update)
{
	const char *object_id = NULL;
	const char *object_name = NULL;

	crm_log_xml(LOG_DEBUG_5, "update:", update);
	crm_log_xml(LOG_DEBUG_5, "target:", target);

	CRM_CHECK(update != NULL, return 0);

	object_name = crm_element_name(update);
	object_id = ID(update);

	CRM_CHECK(object_name != NULL, return 0);
	
	if(target == NULL && object_id == NULL) {
		/*  placeholder object */
		target = find_xml_node(parent, object_name, FALSE);

	} else if(target == NULL) {
		target = find_entity(parent, object_name, object_id);
	}

	if(target == NULL) {
		target = create_xml_node(parent, object_name);
		CRM_CHECK(target != NULL, return 0);
		crm_debug_2("Added  <%s%s%s/>", crm_str(object_name),
			    object_id?" id=":"", object_id?object_id:"");

	} else {
		crm_debug_3("Found node <%s%s%s/> to update",
			    crm_str(object_name),
			    object_id?" id=":"", object_id?object_id:"");
	}

	copy_in_properties(target, update);

	xml_child_iter(
		update, a_child,  
		crm_debug_4("Updating child <%s id=%s>",
			    crm_element_name(a_child), ID(a_child));
		add_xml_object(target, NULL, a_child);
		);

	crm_debug_3("Finished with <%s id=%s>",
		    crm_str(object_name), crm_str(object_id));
	return 0;
}

gboolean
update_xml_child(crm_data_t *child, crm_data_t *to_update)
{
	gboolean can_update = TRUE;
	
	CRM_CHECK(child != NULL, return FALSE);
	CRM_CHECK(to_update != NULL, return FALSE);
	
	if(safe_str_neq(crm_element_name(to_update), crm_element_name(child))) {
		can_update = FALSE;

	} else if(safe_str_neq(ID(to_update), ID(child))) {
		can_update = FALSE;

	} else if(can_update) {
		crm_log_xml_debug_2(child, "Update match found...");
		add_xml_object(NULL, child, to_update);
	}
	
	xml_child_iter(
		child, child_of_child, 
		/* only update the first one */
		if(can_update) {
			break;
		}
		can_update = update_xml_child(child_of_child, to_update);
		);
	
	return can_update;
}


int
find_xml_children(crm_data_t **children, crm_data_t *root,
		  const char *tag, const char *field, const char *value,
		  gboolean search_matches)
{
	int match_found = 0;
	
	CRM_CHECK(root != NULL, return FALSE);
	CRM_CHECK(children != NULL, return FALSE);
	
	if(tag != NULL && safe_str_neq(tag, crm_element_name(root))) {

	} else if(value != NULL
		  && safe_str_neq(value, crm_element_value(root, field))) {

	} else {
		if(*children == NULL) {
			*children = create_xml_node(NULL, __FUNCTION__);
		}
		add_node_copy(*children, root);
		match_found = 1;
	}

	if(search_matches || match_found == 0) {
		xml_child_iter(
			root, child, 
			match_found += find_xml_children(
				children, child, tag, field, value,
				search_matches);
			);
	}
	
	return match_found;
}

gboolean
replace_xml_child(crm_data_t *parent, crm_data_t *child, crm_data_t *update, gboolean delete_only)
{
	gboolean can_delete = FALSE;

	const char *up_id = NULL;
	const char *child_id = NULL;
	const char *right_val = NULL;
	
	CRM_CHECK(child != NULL, return FALSE);
	CRM_CHECK(update != NULL, return FALSE);

	up_id = ID(update);
	child_id = ID(child);
	
	if(up_id == NULL || safe_str_eq(child_id, up_id)) {
		can_delete = TRUE;
	} 
	if(safe_str_neq(crm_element_name(update), crm_element_name(child))) {
		can_delete = FALSE;
	}
	if(can_delete && delete_only) {
		xml_prop_iter(update, prop_name, left_value,
			      right_val = crm_element_value(child, prop_name);
			      if(safe_str_neq(left_value, right_val)) {
				      can_delete = FALSE;
			      }
			);
	}
	
	if(can_delete && parent != NULL) {
		crm_log_xml_debug_4(child, "Delete match found...");
		if(delete_only) {
			cl_msg_remove_value(parent, child);
		} else {
			/* preserve the order */
			cl_msg_replace_value(parent, child, update,
					     sizeof(struct ha_msg), FT_STRUCT);
		}
		child = NULL;
		return TRUE;
		
	} else if(can_delete) {
		crm_log_xml_debug(child, "Cannot delete the search root");
		can_delete = FALSE;
	}
	
	
	xml_child_iter(
		child, child_of_child, 
		/* only delete the first one */
		if(can_delete) {
			break;
		}
		can_delete = replace_xml_child(child, child_of_child, update, delete_only);
		);
	
	return can_delete;
}

void
hash2nvpair(gpointer key, gpointer value, gpointer user_data) 
{
	const char *name    = key;
	const char *s_value = value;

	crm_data_t *xml_node  = user_data;
	crm_data_t *xml_child = create_xml_node(xml_node, XML_CIB_TAG_NVPAIR);

	crm_xml_add(xml_child, XML_ATTR_ID, name);
	crm_xml_add(xml_child, XML_NVPAIR_ATTR_NAME, name);
	crm_xml_add(xml_child, XML_NVPAIR_ATTR_VALUE, s_value);

	crm_debug_3("dumped: name=%s value=%s", name, s_value);
}

void
hash2field(gpointer key, gpointer value, gpointer user_data) 
{
	const char *name    = key;
	const char *s_value = value;

	crm_data_t *xml_node  = user_data;

	if(crm_element_value(xml_node, name) == NULL) {
		crm_xml_add(xml_node, name, s_value);
		crm_debug_3("dumped: %s=%s", name, s_value);
	} else {
		crm_debug_2("duplicate: %s=%s", name, s_value);
	}
}

void
hash2metafield(gpointer key, gpointer value, gpointer user_data) 
{
	char *crm_name = NULL;

	if(key == NULL || value == NULL) {
		return;
	}
	
	crm_name = crm_concat(CRM_META, key, '_');
	hash2field(crm_name, value, user_data);
	crm_free(crm_name);
}


#if CRM_DEPRECATED_SINCE_2_0_3
GHashTable *
xml2list_202(crm_data_t *parent)
{
	crm_data_t *nvpair_list = NULL;
	GHashTable *nvpair_hash = g_hash_table_new_full(
		g_str_hash, g_str_equal,
		g_hash_destroy_str, g_hash_destroy_str);

	CRM_CHECK(parent != NULL, return nvpair_hash);

	nvpair_list = find_xml_node(parent, XML_TAG_ATTRS, FALSE);
	if(nvpair_list == NULL) {
		crm_debug("No attributes in %s",
			  crm_element_name(parent));
		crm_log_xml_debug_2(
			parent,"No attributes for resource op");
	}
	
	xml_child_iter_filter(
		nvpair_list, node_iter, XML_CIB_TAG_NVPAIR,
		
		const char *key   = crm_element_value(
			node_iter, XML_NVPAIR_ATTR_NAME);
		const char *value = crm_element_value(
			node_iter, XML_NVPAIR_ATTR_VALUE);
		
		crm_debug_2("Added %s=%s", key, value);
		
		g_hash_table_insert(
			nvpair_hash, crm_strdup(key), crm_strdup(value));
		);
	
	return nvpair_hash;
}
#endif

GHashTable *
xml2list(crm_data_t *parent)
{
	crm_data_t *nvpair_list = NULL;
	GHashTable *nvpair_hash = g_hash_table_new_full(
		g_str_hash, g_str_equal,
		g_hash_destroy_str, g_hash_destroy_str);
	
	CRM_CHECK(parent != NULL, return nvpair_hash);

	nvpair_list = find_xml_node(parent, XML_TAG_ATTRS, FALSE);
	if(nvpair_list == NULL) {
		crm_debug_2("No attributes in %s",
			    crm_element_name(parent));
		crm_log_xml_debug_2(
			parent,"No attributes for resource op");
	}
	
	crm_log_xml_debug_3(nvpair_list, "Unpacking");

	xml_prop_iter(
		nvpair_list, key, value, 
		
		crm_debug_4("Added %s=%s", key, value);
		
		g_hash_table_insert(
			nvpair_hash, crm_strdup(key), crm_strdup(value));
		);
	
	return nvpair_hash;
}


static void
assign_uuid(crm_data_t *xml_obj) 
{
	cl_uuid_t new_uuid;
	char *new_uuid_s = NULL;
	const char *tag_name = crm_element_name(xml_obj);
	const char *tag_id = ID(xml_obj);
	
	crm_malloc0(new_uuid_s, 38);
	cl_uuid_generate(&new_uuid);
	cl_uuid_unparse(&new_uuid, new_uuid_s);
	
	crm_warn("Updating object from <%s id=%s/> to <%s id=%s/>",
		 tag_name, tag_id?tag_id:"__empty__", tag_name, new_uuid_s);
	
	crm_xml_add(xml_obj, XML_ATTR_ID, new_uuid_s);
	crm_log_xml_debug(xml_obj, "Updated object");	
	crm_free(new_uuid_s);
}

static gboolean
tag_needs_id(const char *tag_name) 
{
	int lpc = 0;
	const char *allowed_list[] = {
		XML_TAG_CIB,
		XML_TAG_FRAGMENT,
		XML_CIB_TAG_NODES,
		XML_CIB_TAG_RESOURCES,
		XML_CIB_TAG_CONSTRAINTS,
		XML_CIB_TAG_STATUS,
		XML_LRM_TAG_RESOURCES,
		"configuration",
		"crm_config",
		"attributes",
		"operations",
		"diff",
		"diff-added",
		"diff-removed",
	};
	
	for(lpc = 0; lpc < DIMOF(allowed_list); lpc++) {
		if(crm_str_eq(tag_name, allowed_list[lpc], TRUE)) {
			/* this tag is never meant to have an ID */
			return FALSE;
		}
	}
	return TRUE;
}

static gboolean
non_unique_allowed(const char *tag_name) 
{
	int lpc = 0;
	const char *non_unique[] = {
		XML_LRM_TAG_RESOURCE,
		XML_LRM_TAG_RSC_OP,
	};

	for(lpc = 0; lpc < DIMOF(non_unique); lpc++) {
		if(safe_str_eq(tag_name, non_unique[lpc])) {
			/* this tag can have a non-unique ID */
			return TRUE;
		}
	}
	return FALSE;
}

gboolean
do_id_check(crm_data_t *xml_obj, GHashTable *id_hash,
	    gboolean silent_add, gboolean silent_rename) 
{
	char *lookup_id = NULL;
	gboolean modified = FALSE;

	char *old_id = NULL;
	const char *tag_id = NULL;
	const char *tag_name = NULL;
	const char *lookup_value = NULL;

	gboolean created_hash = FALSE;

	if(xml_obj == NULL) {
		return FALSE;

	} else if(id_hash == NULL) {
		created_hash = TRUE;
		id_hash = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
	}

	xml_child_iter(
		xml_obj, xml_child, 
		if(do_id_check(xml_child, id_hash, silent_add, silent_rename)) {
			modified = TRUE;
		}
		);

	tag_id = ID(xml_obj);
	tag_name = TYPE(xml_obj);
	
	if(tag_needs_id(tag_name) == FALSE) {
		crm_debug_5("%s does not need an ID", tag_name);
		goto finish_id_check;

	} else if(tag_id != NULL && non_unique_allowed(tag_name)){
		crm_debug_5("%s does not need top be unique", tag_name);
		goto finish_id_check;
	}
	
	lookup_id = NULL;
	if(tag_id != NULL) {
		lookup_id = crm_concat(tag_name, tag_id, '-');
		lookup_value = g_hash_table_lookup(id_hash, lookup_id);
		if(lookup_value == NULL) {
			g_hash_table_insert(id_hash, lookup_id, crm_strdup(tag_id));
			goto finish_id_check;
		}
		modified |= (!silent_rename);
		
	} else {
		modified |= (!silent_add);
	}

	if(tag_id != NULL) {
		old_id = crm_strdup(tag_id);
	}
	
	crm_free(lookup_id);
	assign_uuid(xml_obj);
	tag_id = ID(xml_obj);
	
	if(modified == FALSE) {
		/* nothing to report */
		
	} else if(old_id != NULL && safe_str_neq(tag_id, old_id)) {
		crm_err("\"id\" collision detected... Multiple '%s' entries"
			" with id=\"%s\", assigned id=\"%s\"",
			tag_name, old_id, tag_id);

	} else if(old_id == NULL && tag_id != NULL) {
		crm_err("Detected <%s.../> object without an ID. Assigned: %s",
			tag_name, tag_id);
	}
	crm_free(old_id);

  finish_id_check:
	if(created_hash) {
		g_hash_table_destroy(id_hash);
	}

	return modified;
}

typedef struct name_value_s 
{
	const char *name;
	const void *value;
} name_value_t;

static gint
sort_pairs(gconstpointer a, gconstpointer b)
{
	const name_value_t *pair_a = a;
	const name_value_t *pair_b = b;
	
	if(a == NULL && b == NULL) {
		return 0;
	} else if(a == NULL) {
		return 1;
	} else if(b == NULL) {
		return -1;
	}

	if(pair_a->name == NULL && pair_b->name == NULL) {
		return 0;
	} else if(pair_a->name == NULL) {
		return 1;
	} else if(pair_b->name == NULL) {
		return -1;
	}
	return strcmp(pair_a->name, pair_b->name);
}

static void
dump_pair(gpointer data, gpointer user_data)
{
	name_value_t *pair = data;
	crm_data_t *parent = user_data;
	crm_xml_add(parent, pair->name, pair->value);
}

static void
free_pair(gpointer data, gpointer user_data)
{
	name_value_t *pair = data;
	crm_free(pair);
}

static crm_data_t *
sorted_xml(const crm_data_t *input, crm_data_t *parent, gboolean recursive)
{
	GListPtr sorted = NULL;
	GListPtr unsorted = NULL;
	name_value_t *pair = NULL;
	crm_data_t *result = NULL;
	const char *name = crm_element_name(input);

	CRM_CHECK(input != NULL, return NULL);
	
	name = crm_element_name(input);
	CRM_CHECK(name != NULL, return NULL);

	result = create_xml_node(parent, name);
	
	xml_prop_iter(input, p_name, p_value,
		      crm_malloc0(pair, sizeof(name_value_t));
		      pair->name  = p_name;
		      pair->value = p_value;
		      unsorted = g_list_prepend(unsorted, pair);
		      pair = NULL;
		);

	sorted = g_list_sort(unsorted, sort_pairs);
	g_list_foreach(sorted, dump_pair, result);
	g_list_foreach(sorted, free_pair, NULL);
	g_list_free(sorted);

	if(recursive) {
	    xml_child_iter(input, child, sorted_xml(child, result, recursive));
	} else {
	    xml_child_iter(input, child, add_node_copy(result, child));
	}
	
	return result;
}

static void
filter_xml(crm_data_t *data, const char **filter, int filter_len, gboolean recursive) 
{
    int lpc = 0;
    
    for(lpc = 0; lpc < filter_len; lpc++) {
	xml_remove_prop(data, filter[lpc]);
    }

    if(recursive == FALSE) {
	return;
    }
    
    xml_child_iter(data, child, filter_xml(child, filter, filter_len, recursive));
}

/* "c048eae664dba840e1d2060f00299e9d" */
char *
calculate_xml_digest(crm_data_t *input, gboolean sort, gboolean do_filter)
{
	int i = 0;
	int digest_len = 16;
	char *digest = NULL;
	unsigned char *raw_digest = NULL;
	crm_data_t *sorted = NULL;
	char *buffer = NULL;
	size_t buffer_len = 0;

	if(sort || do_filter) {
	    sorted = sorted_xml(input, NULL, TRUE);
	} else {
	    sorted = copy_xml(input);
	}

	if(do_filter) {
	    filter_xml(sorted, filter, DIMOF(filter), TRUE);
	}
	
	buffer = dump_xml_formatted(sorted);
	buffer_len = strlen(buffer);
	
	CRM_CHECK(buffer != NULL && buffer_len > 0,
		  free_xml(sorted); return NULL);

	crm_malloc0(digest, (2 * digest_len + 1));
	crm_malloc0(raw_digest, (digest_len + 1));
	MD5((unsigned char *)buffer, buffer_len, raw_digest);
	for(i = 0; i < digest_len; i++) {
 		sprintf(digest+(2*i), "%02x", raw_digest[i]);
 	}
        crm_debug_2("Digest %s: %s\n", digest, buffer);
	crm_log_xml(LOG_DEBUG_3,  "digest:source", sorted);
	crm_free(buffer);
	crm_free(raw_digest);
	free_xml(sorted);
	return digest;
}


#if HAVE_LIBXML2
#  include <libxml/parser.h>
#  include <libxml/tree.h>
#endif

gboolean
validate_with_dtd(
	crm_data_t *xml_blob, gboolean to_logs, const char *dtd_file) 
{
	gboolean valid = TRUE;
#if HAVE_LIBXML2
	char *buffer = NULL;

 	xmlDocPtr doc = NULL;
	xmlDtdPtr dtd = NULL;
	xmlValidCtxtPtr cvp = NULL;
	
	CRM_CHECK(xml_blob != NULL, return FALSE);
	CRM_CHECK(dtd_file != NULL, return FALSE);

	buffer = dump_xml_formatted(xml_blob);
	CRM_CHECK(buffer != NULL, return FALSE);

 	doc = xmlParseMemory(buffer, strlen(buffer));
	CRM_CHECK(doc != NULL, valid = FALSE; goto cleanup);
	
	dtd = xmlParseDTD(NULL, (const xmlChar *)dtd_file);
	CRM_CHECK(dtd != NULL, goto cleanup);

	cvp = xmlNewValidCtxt();
	CRM_CHECK(cvp != NULL, goto cleanup);

	if(to_logs) {
		cvp->userData = (void *) LOG_ERR;
		cvp->error    = (xmlValidityErrorFunc) cl_log;
		cvp->warning  = (xmlValidityWarningFunc) cl_log;
	} else {
		cvp->userData = (void *) stderr;
		cvp->error    = (xmlValidityErrorFunc) fprintf;
		cvp->warning  = (xmlValidityWarningFunc) fprintf;
	}
	
	if (!xmlValidateDtd(cvp, doc, dtd)) {
		valid = FALSE;
	}
	
  cleanup:
	if(cvp) {
		xmlFreeValidCtxt(cvp);
	}
	if(dtd) {
		xmlFreeDtd(dtd);
	}
	if(doc) {
		xmlFreeDoc(doc);
	}
	if(buffer) {
		crm_free(buffer);
	}
	
#endif	
	return valid;
}
