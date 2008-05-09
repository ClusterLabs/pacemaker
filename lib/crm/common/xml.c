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

struct schema_s 
{
	int type;
	const char *name;
	const char *location;
	const char *transform;
};

struct schema_s known_schemas[] = {
    { 0, "none", NULL, NULL },
    { 1, "pacemaker-0.6", DTD_DIRECTORY"/crm.dtd", DTD_DIRECTORY"/upgrade.xsl" },
    { 2, "pacemaker-0.7", DTD_DIRECTORY"/pacemaker-0.7.rng", NULL },
    { 2, LATEST_SCHEMA_VERSION, DTD_DIRECTORY"/"LATEST_SCHEMA_VERSION".rng", NULL }, /* Just in case I forget */
};

static const char *filter[] = {
    XML_ATTR_ORIGIN,
    XML_DIFF_MARKER,
    XML_CIB_ATTR_WRITTEN,		
};

static void add_ha_nocopy(HA_Message *parent, HA_Message *child, const char *field) 
{
    int next = parent->nfields;
    if (parent->nfields >= parent->nalloc && ha_msg_expand(parent) != HA_OK ) {
	crm_err("Parent expansion failed");
	return;
    }
    
    parent->names[next] = crm_strdup(field);
    parent->nlens[next] = strlen(field);
    parent->values[next] = child;
    parent->vlens[next] = sizeof(HA_Message);
    parent->types[next] = FT_UNCOMPRESS;
    parent->nfields++;	
}

int is_comment_start(const char *input, size_t offset, size_t max);
int is_comment_end(const char *input, size_t offset, size_t max);
gboolean drop_comments(const char *input, size_t *offset, size_t max);

void dump_array(
	int log_level, const char *message, const char **array, int depth);

int print_spaces(char *buffer, int spaces);

int log_data_element(const char *function, const char *prefix, int log_level,
		     int depth, xmlNode *data, gboolean formatted);

int dump_data_element(
	int depth, char **buffer, xmlNode *data, gboolean formatted);

xmlNode *parse_xml(const char *input, size_t *offset);
int get_tag_name(const char *input, size_t offset, size_t max);
int get_attr_name(const char *input, size_t offset, size_t max);
int get_attr_value(const char *input, size_t offset, size_t max);
gboolean can_prune_leaf(xmlNode *xml_node);

void diff_filter_context(int context, int upper_bound, int lower_bound,
		    xmlNode *xml_node, xmlNode *parent);
int in_upper_context(int depth, int context, xmlNode *xml_node);

xmlNode *
find_xml_node(xmlNode *root, const char * search_path, gboolean must_find)
{
	const char *name = "NULL";
	if(must_find || root != NULL) {
		crm_validate_data(root);
	}
	if(root != NULL) {
	    name = crm_element_name(root);
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
		crm_warn("Could not find %s in %s.", search_path, name);
	} else if(root != NULL) {
		crm_debug_3("Could not find %s in %s.", search_path, name);
	} else {
		crm_debug_3("Could not find %s in <NULL>.", search_path);
	}
	
	
	return NULL;
}

xmlNode*
find_xml_node_nested(xmlNode *root, const char **search_path, int len)
{
	int	j;
	gboolean is_found = TRUE;
	xmlNode *match =  NULL;
	xmlNode *lastMatch = root;

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
get_xml_attr_nested(xmlNode *parent,
		    const char **node_path, int length,
		    const char *attr_name, gboolean error)
{
	const char *attr_value = NULL;
	xmlNode *attr_parent = NULL;

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


xmlNode*
find_entity(xmlNode *parent, const char *node_name, const char *id)
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
copy_in_properties(xmlNode* target, xmlNode *src)
{
	crm_validate_data(src);
	crm_validate_data(target);

	if(src == NULL) {
		crm_warn("No node to copy properties from");

	} else if (target == NULL) {
		crm_err("No node to copy properties into");

	} else {
		xml_prop_iter(
			src, local_prop_name, local_prop_value,
			expand_plus_plus(target, local_prop_name, local_prop_value)
			);
		crm_validate_data(target);
	}
	
	return;
}

void fix_plus_plus_recursive(xmlNode* target)
{
    xml_prop_iter(target, name, value, expand_plus_plus(target, name, value));
    xml_child_iter(target, child, fix_plus_plus_recursive(child));
}


void
expand_plus_plus(xmlNode* target, const char *name, const char *value)
{
    int int_value = 0;
    const char *old_value = crm_element_value(target, name);
    int name_len = strlen(name);
    int value_len = strlen(value);
    
    /* if no previous value, set unexpanded */
    if(old_value == NULL
       || value_len < (name_len + 2)
       || value[name_len] != '+'
       || (value[name_len+1] != '+' && value[name_len+1] != '=')
       || strstr(value, name) != value) {
	crm_xml_add(target, name, value);
	return;
    }

    if(safe_str_eq(value, old_value)) {
	int_value = 0;
	
    } else {
	int_value = char2score(old_value);
    }
    
    if(value[name_len+1] == '+') {
	/* if the value is name followed by "++" we need
	 *   to increment the existing value
	 */
	int_value++;
	
    } else {
	const char *offset_s = value+(name_len+2);
	int offset = char2score(offset_s);
	int_value += offset;
    }

    if(int_value > INFINITY) {
	int_value = INFINITY;
    }
    
    crm_xml_add_int(target, name, int_value);
    
    return;
}

xmlNode*
add_node_copy(xmlNode *parent, xmlNode *src_node) 
{
	const char *name = NULL;
	xmlNode *child = NULL;
	CRM_CHECK(src_node != NULL, return NULL);

	crm_validate_data(src_node);

	name = crm_element_name(src_node);
	CRM_CHECK(name != NULL, return NULL);

	child = copy_xml(src_node);
	xmlAddChild(parent, child);
	return child;
}


int
add_node_nocopy(xmlNode *parent, const char *name, xmlNode *child)
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
	
	next = 0;
	xmlAddChild(parent, child);
	return HA_OK;
}

const char *
crm_xml_add(xmlNode* node, const char *name, const char *value)
{
    xmlAttr *attr = NULL;
    const char *old_value = NULL;
    CRM_CHECK(node != NULL, return NULL);
    CRM_CHECK(name != NULL && name[0] != 0, return NULL);
    /* CRM_CHECK(value != NULL && value[0] != 0, return NULL); */
    /* CRM_CHECK(strcasecmp(name, F_XML_TAGNAME) != 0, return NULL); */
    old_value = crm_element_value(node, name);

#if 1
    if (old_value != NULL && (value == NULL || value[0] == 0)) {
	crm_err("Unsetting %s with crm_xml_add()", name);
	xml_remove_prop(node, name);
	return NULL;
    }
#endif

    if(old_value == value) {
	return value;
    }
    
    attr = xmlSetProp(node, (const xmlChar*)name, (const xmlChar*)value);
    CRM_CHECK(attr && attr->children && attr->children->content, return NULL);
    return (char *)attr->children->content;
}

const char *
crm_xml_add_int(xmlNode* node, const char *name, int value)
{
    char *number = crm_itoa(value);
    const char *added = crm_xml_add(node, name, number);
    crm_free(number);
    return added;
}

xmlNode*
create_xml_node(xmlNode *parent, const char *name)
{
	xmlNode *ret_value = NULL;	

	if (name == NULL || name[0] == 0) {
		ret_value = NULL;
	} else if(parent == NULL) {
		ret_value = xmlNewNode(NULL, (const xmlChar*)name);
	} else {
		ret_value = xmlNewChild(parent, NULL, (const xmlChar*)name, NULL);
	}
	return ret_value;
}

void
free_xml_from_parent(xmlNode *parent, xmlNode *a_node)
{
	CRM_CHECK(parent != NULL, return);
	CRM_CHECK(a_node != NULL, return);

	xmlUnlinkNode(a_node);
	a_node->doc = NULL;
	free_xml(a_node);
}

xmlNode*
copy_xml(xmlNode *src_node)
{
	return xmlCopyNode(src_node, 1);
}

xmlNode*
string2xml(const char *input)
{
	xmlNode *output = parse_xml(input, NULL);
	if(output != NULL) {
		crm_validate_data(output);
	}
	return output;
}

xmlNode *
stdin2xml(void) 
{
 	size_t data_length = 0;
 	size_t read_chars = 0;
  
  	char *xml_buffer = NULL;
  	xmlNode *xml_obj = NULL;
  
 	do {
 		crm_realloc(xml_buffer, XML_BUFFER_SIZE + data_length + 1);
 		read_chars = fread(xml_buffer + data_length, 1, XML_BUFFER_SIZE, stdin);
 		data_length += read_chars;
 	} while (read_chars > 0);

	if(data_length == 0) {
	    crm_warn("No XML supplied on stdin");
	    return NULL;
	}

 	xml_buffer[data_length] = '\0';

	xml_obj = string2xml(xml_buffer);
	crm_free(xml_buffer);

	crm_log_xml_debug_3(xml_obj, "Created fragment");
	return xml_obj;
}


xmlNode*
file2xml(FILE *input, gboolean compressed)
{
	char *buffer = NULL;
	gboolean work_done = FALSE;
	xmlNode *new_obj = NULL;
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
write_xml_file(xmlNode *xml_node, const char *filename, gboolean compress) 
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
	    bz_file = BZ2_bzWriteOpen(&rc, file_output_strm, 5, 0, 30);
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
		    xmlNode *msg, const char *text)
{
	if(msg == NULL) {
		do_crm_log(log_level, "%s: %s: NULL", function, crm_str(text));
		return;
	}

	crm_validate_data(msg);
	log_data_element(function, text, log_level, 0, msg, TRUE);
	return;
}

static HA_Message*
convert_xml_message_struct(HA_Message *parent, xmlNode *src_node, const char *field) 
{
    xmlNode *child = NULL;
    xmlNode *__crm_xml_iter = src_node->children;
    xmlAttrPtr prop_iter = src_node->properties;
    const char *name = NULL;
    const char *value = NULL;

    HA_Message *result = ha_msg_new(3);
    ha_msg_add(result, F_XML_TAGNAME, (const char *)src_node->name);
    
    while(prop_iter != NULL) {
	name = (const char *)prop_iter->name;
	value = (const char *)xmlGetProp(src_node, prop_iter->name);
	prop_iter = prop_iter->next;
	ha_msg_add(result, name, value);
    }

    while(__crm_xml_iter != NULL) {
	child = __crm_xml_iter;
	__crm_xml_iter = __crm_xml_iter->next;
	convert_xml_message_struct(result, child, NULL);
    }

    if(parent == NULL) {
	return result;
    }
    
    if(field) {
	HA_Message *holder = holder = ha_msg_new(3);
	CRM_ASSERT(holder != NULL);
	
	ha_msg_add(holder, F_XML_TAGNAME, field);
	add_ha_nocopy(holder, result, (const char*)src_node->name);
	
	ha_msg_addstruct_compress(parent, field, holder);
	ha_msg_del(holder);

    } else {
	add_ha_nocopy(parent, result, (const char*)src_node->name);
    }
    return result;
}

static void
convert_xml_child(HA_Message *msg, xmlNode *xml) 
{
    int orig = 0;
    int rc = BZ_OK;
    unsigned int len = 0;
    
    char *buffer = NULL;
    char *compressed = NULL;
    const char *name = NULL;

    name = (const char *)xml->name;
    buffer = dump_xml_unformatted(xml);
    orig = strlen(buffer);
    if(orig < 512) {
	ha_msg_add(msg, name, buffer);
	goto done;
    }
    
    len = (orig * 1.1) + 600; /* recomended size */
    
    crm_malloc0(compressed, len);
    rc = BZ2_bzBuffToBuffCompress(compressed, &len, buffer, orig, 3, 0, 30);
    
    if(rc != BZ_OK) {
	crm_err("Compression failed: %d", rc);
	crm_free(compressed);
	convert_xml_message_struct(msg, xml, name);
	goto done;
    }
    
    crm_free(buffer);
    buffer = compressed;
    crm_debug_2("Compression details: %d -> %d", orig, len);
    ha_msg_addbin(msg, name, buffer, len);
  done:
    crm_free(buffer);


#  if 0
    {
	unsigned int used = orig;
	char *uncompressed = NULL;
	
	crm_debug("Trying to decompress %d bytes", len);
	crm_malloc0(uncompressed, orig);
	rc = BZ2_bzBuffToBuffDecompress(
	    uncompressed, &used, compressed, len, 1, 0);
	CRM_CHECK(rc == BZ_OK, ;);
	CRM_CHECK(used == orig, ;);
	crm_debug("rc=%d, used=%d", rc, used);
	if(rc != BZ_OK) {
	    exit(100);
	}
	crm_debug("Original %s, decompressed %s", buffer, uncompressed);
	crm_free(uncompressed);
    }
#  endif 
}

HA_Message*
convert_xml_message(xmlNode *xml) 
{
    HA_Message *result = NULL;

    result = ha_msg_new(3);
    ha_msg_add(result, F_XML_TAGNAME, (const char *)xml->name);

    xml_prop_iter(xml, name, value, ha_msg_add(result, name, value));
    xml_child_iter(xml, child, convert_xml_child(result, child));

    return result;
}

static void
convert_ha_field(xmlNode *parent, HA_Message *msg, int lpc) 
{
    int type = 0;
    const char *name = NULL;
    const char *value = NULL;
    xmlNode *xml = NULL;
    
    int rc = BZ_OK;
    size_t orig_len = 0;
    unsigned int used = 0;
    char *uncompressed = NULL;
    char *compressed = NULL;
    int size = orig_len * 10;
    
    CRM_CHECK(parent != NULL, return);
    CRM_CHECK(msg != NULL, return);
	
    name = msg->names[lpc];
    type = cl_get_type(msg, name);

    switch(type) {
	case FT_COMPRESS:
	case FT_STRUCT:
	    convert_ha_message(parent, msg->values[lpc], name);
	    break;
	case FT_UNCOMPRESS:
	    convert_ha_message(parent, cl_get_struct(msg, name), name);
	    break;
	case FT_STRING:
	    value = cl_get_string(msg, name);
	    if( value == NULL || value[0] != '<' ) {
		crm_xml_add(parent, name, value);
		break;
	    }
	    
	    /* unpack xml string */
	    xml = string2xml(value);
	    if(xml == NULL) {
		crm_xml_add(parent, name, value);
		break;
	    }
	    
	    add_node_nocopy(parent, name, xml);
	    break;

	case FT_BINARY:
	    value = cl_get_binary(msg, name, &orig_len);
	    size = orig_len * 10;

	    if(orig_len < 3
	       || value[0] != 'B'
	       || value[1] != 'Z'
	       || value[2] != 'h') {
		if(strstr(name, "uuid") == NULL) {
		    crm_err("Skipping non-bzip binary field: %s", name);
		}
		return;
	    }

	    crm_malloc0(compressed, orig_len);
	    memcpy(compressed, value, orig_len);
	    
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
		crm_err("Decompression of %s (%d bytes) into %d failed: %d",
			name, (int)orig_len, size, rc);
		
	    } else {
		xml = string2xml(uncompressed);
	    }

	    if(xml != NULL) {
		add_node_nocopy(parent, name, xml);
	    }
	    
	    crm_free(uncompressed);
	    crm_free(compressed);		
	    break;
    }
}

xmlNode *
convert_ha_message(xmlNode *parent, HA_Message *msg, const char *field) 
{
    int lpc = 0;
    xmlNode *child = NULL;
    const char *tag = NULL;
    
    CRM_CHECK(msg != NULL, crm_err("Empty message for %s", field); return parent);
    
    tag = cl_get_string(msg, F_XML_TAGNAME);
    if(tag == NULL) {
	tag = field;
    }
    
    if(parent == NULL) {
	parent = create_xml_node(NULL, tag);
	child = parent;
	
    } else {
	child = create_xml_node(parent, tag);
    }

    for (lpc = 0; lpc < msg->nfields; lpc++) {
	convert_ha_field(child, msg, lpc);
    }
    
    return parent;
}

xmlNode *convert_ipc_message(IPC_Message *msg, const char *field)
{
    HA_Message *hmsg = wirefmt2msg((char *)msg->msg_body, msg->msg_len, 0);
    xmlNode *xml = convert_ha_message(NULL, hmsg, __FUNCTION__);
    crm_msg_del(hmsg);
    return xml;
}

xmlNode *
get_message_xml(xmlNode *msg, const char *field) 
{
    xmlNode *tmp = first_named_child(msg, field);
    return first_named_child(tmp, NULL);
}

gboolean
add_message_xml(xmlNode *msg, const char *field, xmlNode *xml) 
{
    xmlNode *holder = create_xml_node(msg, field);
    add_node_copy(holder, xml);
    return TRUE;
}

char *
dump_xml_formatted(xmlNode *an_xml_node)
{
	char *buffer     = NULL;
	char *mutable_ptr = NULL;
	if(an_xml_node == NULL) {
		return NULL;
	}
	crm_malloc0(buffer, 1024*1024);
	mutable_ptr = buffer;
	
	crm_validate_data(an_xml_node);
	CRM_CHECK(dump_data_element(
			  0, &mutable_ptr, an_xml_node, TRUE) >= 0,
		  crm_crit("Could not dump the whole message"));
	crm_debug_4("Dumped: %s", buffer);
	return buffer;
}
	
char *
dump_xml_unformatted(xmlNode *an_xml_node)
{
	char *buffer     = NULL;
	char *mutable_ptr = NULL;

  	crm_malloc0(buffer, 1024*1024);
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
	xmlNode *data, gboolean formatted) 
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
	int depth, char **buffer,  xmlNode *data, gboolean formatted) 
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
xml_has_children(const xmlNode *xml_root)
{
	if(xml_root != NULL && xml_root->children != NULL) {
	    return TRUE;
	}
	return FALSE;
}

void
xml_validate(const xmlNode *xml_root)
{
	CRM_ASSERT(xml_root != NULL);
}

int
crm_element_value_int(xmlNode *data, const char *name, int *dest)
{
    const char *value = crm_element_value(data, name);
    CRM_CHECK(dest != NULL, return -1);
    if(value) {
	*dest = crm_parse_int(value, NULL);
	return 0;
    }
    return -1;
}

const char *
crm_element_value(xmlNode *data, const char *name)
{
    xmlAttr *attr = NULL;
    
    CRM_CHECK(data != NULL, return NULL);
    CRM_CHECK(name != NULL, return NULL);
    
    attr = xmlHasProp(data, (const xmlChar*)name);
    if(attr && attr->children) {
	return (const char*)attr->children->content;
    }
    return NULL;
}

const char *
crm_element_value_const(const xmlNode *data, const char *name)
{
    return crm_element_value(data, name);
}

char *
crm_element_value_copy(xmlNode *data, const char *name)
{
	char *value_copy = NULL;
	const char *value = crm_element_value(data, name);
	if(value != NULL) {
		value_copy = crm_strdup(value);
	}
	return value_copy;
}

const char *
crm_element_name(const xmlNode *data)
{
    return (data ? (const char *)data->name : NULL);
}

void
xml_remove_prop(xmlNode *obj, const char *name)
{
    xmlUnsetProp(obj, (const xmlChar*)name);
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
	crm_err("Error parsing token near %.40s: (lpc=%d, ch='%c') %s",
		input+offset, (int)(lpc-offset), ch, crm_str(error));
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
	crm_err("Error parsing token near %.40s: %s", input+offset, crm_str(error));
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

xmlNode*
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
	xmlNode *new_obj = NULL;

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
	
	new_obj = xmlNewNode(NULL, (xmlChar*)tag_name);
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
					xmlNode *child = NULL;
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
					
					crm_xml_add(new_obj, attr_name, attr_value);
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
		crm_err("Error at or before: %.40s", our_input+lpc-3);
		crm_free(tag_name);
		free_xml(new_obj);
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
		    cl_log(LOG_ERR, "%s: Parsed %d characters of a possible %d.  Trailing text was: \'%.40s\'...",
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
log_xml_diff(unsigned int log_level, xmlNode *diff, const char *function)
{
	xmlNode *added = find_xml_node(diff, "diff-added", FALSE);
	xmlNode *removed = find_xml_node(diff, "diff-removed", FALSE);
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
purge_diff_markers(xmlNode *a_node)
{
	CRM_CHECK(a_node != NULL, return);

	xml_remove_prop(a_node, XML_DIFF_MARKER);
	xml_child_iter(a_node, child,
		       purge_diff_markers(child);
		);
}

gboolean
apply_xml_diff(xmlNode *old, xmlNode *diff, xmlNode **new)
{
	gboolean result = TRUE;
	const char *digest = crm_element_value(diff, XML_ATTR_DIGEST);
	xmlNode *added = find_xml_node(diff, "diff-added", FALSE);
	xmlNode *removed = find_xml_node(diff, "diff-removed", FALSE);

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
		xmlNode *intermediate = NULL;
		xmlNode *diff_of_diff = NULL;
		xmlNode *calc_added = NULL;
		xmlNode *calc_removed = NULL;

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


xmlNode *
diff_xml_object(xmlNode *old, xmlNode *new, gboolean suppress)
{
	xmlNode *diff = NULL;
	xmlNode *tmp1 = NULL;
	xmlNode *added = NULL;
	xmlNode *removed = NULL;

	tmp1 = subtract_xml_object(old, new, "removed:top");
	if(tmp1 != NULL) {
		if(suppress && can_prune_leaf(tmp1)) {
			free_xml(tmp1);

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
			free_xml(tmp1);
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
can_prune_leaf(xmlNode *xml_node)
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
				free_xml(child);
		       } else {
			       can_prune = FALSE;
		       }
		);
	return can_prune;
}


void
diff_filter_context(int context, int upper_bound, int lower_bound,
		    xmlNode *xml_node, xmlNode *parent) 
{
	xmlNode *us = NULL;
	xmlNode *new_parent = parent;
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
in_upper_context(int depth, int context, xmlNode *xml_node)
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


xmlNode *
subtract_xml_object(xmlNode *left, xmlNode *right, const char *marker)
{
	gboolean skip = FALSE;
	gboolean differences = FALSE;
	xmlNode *diff = NULL;
	xmlNode *child_diff = NULL;
	xmlNode *right_child = NULL;

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
		xmlNode *deleted = NULL;

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
add_xml_object(xmlNode *parent, xmlNode *target, xmlNode *update)
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
update_xml_child(xmlNode *child, xmlNode *to_update)
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
find_xml_children(xmlNode **children, xmlNode *root,
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
replace_xml_child(xmlNode *parent, xmlNode *child, xmlNode *update, gboolean delete_only)
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
		    free_xml(child);
		    
		} else {	
		    xmlNode *tmp = copy_xml(update);
		    xmlNode *old = xmlReplaceNode(child, tmp);
		    free_xml(old);
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

	xmlNode *xml_node  = user_data;
	xmlNode *xml_child = create_xml_node(xml_node, XML_CIB_TAG_NVPAIR);

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

	xmlNode *xml_node  = user_data;

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
xml2list_202(xmlNode *parent)
{
	xmlNode *nvpair_list = NULL;
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
xml2list(xmlNode *parent)
{
	xmlNode *nvpair_list = NULL;
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
assign_uuid(xmlNode *xml_obj) 
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
do_id_check(xmlNode *xml_obj, GHashTable *id_hash,
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
	xmlNode *parent = user_data;
	crm_xml_add(parent, pair->name, pair->value);
}

static void
free_pair(gpointer data, gpointer user_data)
{
	name_value_t *pair = data;
	crm_free(pair);
}

static xmlNode *
sorted_xml(xmlNode *input, xmlNode *parent, gboolean recursive)
{
	GListPtr sorted = NULL;
	GListPtr unsorted = NULL;
	name_value_t *pair = NULL;
	xmlNode *result = NULL;
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
filter_xml(xmlNode *data, const char **filter, int filter_len, gboolean recursive) 
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
calculate_xml_digest(xmlNode *input, gboolean sort, gboolean do_filter)
{
	int i = 0;
	int digest_len = 16;
	char *digest = NULL;
	unsigned char *raw_digest = NULL;
	xmlNode *sorted = NULL;
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
#  include <libxml/relaxng.h>
#  include <libxslt/xslt.h>
#  include <libxslt/transform.h>
#endif

static gboolean
validate_with_dtd(
	xmlDocPtr doc, gboolean to_logs, const char *dtd_file) 
{
	gboolean valid = TRUE;

	xmlDtdPtr dtd = NULL;
	xmlValidCtxtPtr cvp = NULL;
	
	CRM_CHECK(doc != NULL, return FALSE);
	CRM_CHECK(dtd_file != NULL, return FALSE);

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
	
	return valid;
}

xmlNode *first_named_child(xmlNode *parent, const char *name) 
{
    xml_child_iter_filter(parent, match, name, return match);
    return NULL;
}

#if 0
static void relaxng_invalid_stderr(void * userData, xmlErrorPtr error)
{
    /*
Structure xmlError
struct _xmlError {
    int	domain	: What part of the library raised this er
    int	code	: The error code, e.g. an xmlParserError
    char *	message	: human-readable informative error messag
    xmlErrorLevel	level	: how consequent is the error
    char *	file	: the filename
    int	line	: the line number if available
    char *	str1	: extra string information
    char *	str2	: extra string information
    char *	str3	: extra string information
    int	int1	: extra number information
    int	int2	: column number of the error or 0 if N/A
    void *	ctxt	: the parser context if available
    void *	node	: the node in the tree
}
     */
    crm_err("Structured error: line=%d, level=%d %s",
	    error->line, error->level, error->message);
}
#endif

static gboolean
validate_with_relaxng(
    xmlDocPtr doc, gboolean to_logs, const char *relaxng_file) 
{
    gboolean valid = TRUE;
#if HAVE_LIBXML2
    int rc = 0;

    xmlRelaxNGPtr rng = NULL;
    xmlRelaxNGValidCtxtPtr valid_ctx = NULL;
    xmlRelaxNGParserCtxtPtr parser_ctx = NULL;
    
    CRM_CHECK(doc != NULL, return FALSE);
    CRM_CHECK(relaxng_file != NULL, return FALSE);

    xmlLoadExtDtdDefaultValue = 1;
    parser_ctx = xmlRelaxNGNewParserCtxt(relaxng_file);
    CRM_CHECK(parser_ctx != NULL, goto cleanup);

    if(to_logs) {
	xmlRelaxNGSetParserErrors(parser_ctx,
				  (xmlRelaxNGValidityErrorFunc) cl_log,
				  (xmlRelaxNGValidityWarningFunc) cl_log,
				  LOG_ERR);
    } else {
	xmlRelaxNGSetParserErrors(parser_ctx,
				  (xmlRelaxNGValidityErrorFunc) fprintf,
				  (xmlRelaxNGValidityWarningFunc) fprintf,
				  stderr);
    }

    rng = xmlRelaxNGParse(parser_ctx);
    CRM_CHECK(rng != NULL, goto cleanup);

    valid_ctx = xmlRelaxNGNewValidCtxt(rng);
    CRM_CHECK(valid_ctx != NULL, goto cleanup);

    if(to_logs) {
	xmlRelaxNGSetValidErrors(valid_ctx,
				 (xmlRelaxNGValidityErrorFunc) cl_log,
				 (xmlRelaxNGValidityWarningFunc) cl_log,
				 LOG_ERR);
    } else {
	xmlRelaxNGSetValidErrors(valid_ctx,
				 (xmlRelaxNGValidityErrorFunc) fprintf,
				 (xmlRelaxNGValidityWarningFunc) fprintf,
				 stderr);
    }

    /* xmlRelaxNGSetValidStructuredErrors( */
    /* 	valid_ctx, relaxng_invalid_stderr, valid_ctx); */
    
    xmlLineNumbersDefault(1);
    rc = xmlRelaxNGValidateDoc(valid_ctx, doc);
    if (rc > 0) {
	valid = FALSE;

    } else if (rc < 0) {
	crm_err("Internal libxml error during validation\n");
    }

  cleanup:
    if(parser_ctx != NULL) {
	xmlRelaxNGFreeParserCtxt(parser_ctx);
    }

    if(valid_ctx != NULL) {
	xmlRelaxNGFreeValidCtxt(valid_ctx);
    }
    
    if (rng != NULL) {
	xmlRelaxNGFree(rng);    
    }

#endif	
    return valid;
}

static gboolean validate_with(xmlNode *xml, int method, gboolean to_logs) 
{
    xmlDocPtr doc = NULL;
    gboolean valid = FALSE;
    int type = known_schemas[method].type;
    const char *file = known_schemas[method].location;
    

    CRM_CHECK(xml != NULL, return FALSE);
    doc = xml->doc;
    if(xml->doc == NULL) {
	doc = xmlNewDoc((const xmlChar *)"1.0");
	xmlDocSetRootElement(doc, xml);
    }
    
    crm_info("Validating %p with: %s (type=%d)", xml, crm_str(file), type);
    switch(type) {
	case 0:
	    valid = TRUE;
	    break;
	case 1:
	    valid = validate_with_dtd(doc, to_logs, file);
	    break;
	case 2:
	    valid = validate_with_relaxng(doc, to_logs, file);
	    break;
	default:
	    crm_err("Unknown validator type: %d", type);
	    break;
    }

    return valid;
}

gboolean validate_xml(xmlNode *xml_blob, const char *validation, gboolean to_logs)
{
    int lpc = 0;
    static int max = DIMOF(known_schemas);
    
    if(validation == NULL) {
	validation = crm_element_value(xml_blob, XML_ATTR_VALIDATION);
    }

    if(validation == NULL) {
	/* Compatibility for 0.6 */
	const char *value = crm_element_value(xml_blob, "ignore_dtd");
	if(value != NULL && crm_is_true(value) == FALSE) {
	    validation = "crm.dtd";
	}
    }
    
    if(validation == NULL || safe_str_eq(validation, "none")) {
	return TRUE;
    }
    
    for(; lpc < max; lpc++) {
	if(safe_str_eq(validation, known_schemas[lpc].name)) {
	    if(to_logs) {
		crm_info("Validating configuration with %s: %s",
			 known_schemas[lpc].name, known_schemas[lpc].location);
	    }
	    return validate_with(xml_blob, lpc, to_logs);
	}
    }

    crm_err("Unknown validator: %s", validation);
    return FALSE;
}

static xmlNode *apply_transformation(xmlNode *xml, const char *transform) 
{
    xmlNode *out = NULL;
    xmlDocPtr res = NULL;
    xmlDocPtr doc = NULL;
    xsltStylesheet *xslt = NULL;

    CRM_CHECK(xml != NULL, return FALSE);
    doc = xml->doc;
    if(xml->doc == NULL) {
	doc = xmlNewDoc((const xmlChar *)"1.0");
	xmlDocSetRootElement(doc, xml);
    }

    xmlLoadExtDtdDefaultValue = 1;
    xmlSubstituteEntitiesDefault(1);
    
    xslt = xsltParseStylesheetFile((const xmlChar *)transform);
    CRM_CHECK(xslt != NULL, goto cleanup);
    
    res = xsltApplyStylesheet(xslt, doc, NULL);
    CRM_CHECK(res != NULL, goto cleanup);

    out = xmlDocGetRootElement(res);
    
  cleanup:
    if(xslt) {
	xsltFreeStylesheet(xslt);
    }

    xsltCleanupGlobals();
    xmlCleanupParser();
    
    return out;
}

/* set which validation to use */
xmlNode *update_validation(xmlNode *xml_blob, gboolean transform, gboolean to_logs) 
{
    int lpc = 0, match = 0, best = 0;
    static int max = DIMOF(known_schemas);
    const char *value = crm_element_value(xml_blob, XML_ATTR_VALIDATION);

    if(safe_str_eq(value, "none")) {
	/* they dont want any */
	return xml_blob;

    } else if(safe_str_eq(value, LATEST_SCHEMA_VERSION)) {
	return xml_blob;
    }

    if(value != NULL) {
	for(; lpc < max; lpc++) {
	    if(safe_str_eq(value, known_schemas[lpc].name)) {
		match = lpc;
		lpc++;
		break;
	    }
	}
    }
    
    for(; lpc < max; lpc++) {
	gboolean valid = TRUE;
	crm_debug("Testing '%s' validation", known_schemas[lpc].name);
	valid = validate_with(xml_blob, lpc, to_logs);
	
	if(valid) {
	    best = lpc;
	}
	
	if(valid && transform && known_schemas[lpc].transform != NULL) {
	    xmlNode *upgrade = NULL;
	    crm_notice("Upgrading %s-style configuration to %s with %s",
		       known_schemas[lpc].name, known_schemas[lpc+1].name, known_schemas[lpc].transform);
	    upgrade = apply_transformation(xml_blob, known_schemas[lpc].transform);
	    if(upgrade == NULL) {
		crm_err("Transformation %s failed", known_schemas[lpc].transform);
		
	    } else if(validate_with(upgrade, lpc+1, to_logs)) {
		crm_info("Transformation %s successful", known_schemas[lpc].transform);
		free_xml(xml_blob);
		xml_blob = upgrade;
		
	    } else {
		crm_err("Transformation %s did not produce a valid configuration", known_schemas[lpc].transform);
		crm_log_xml_debug(upgrade, "transform:bad");
		free_xml(upgrade);
	    }
	}
    }
    
    if(best > match) {
	crm_notice("Upgrading from %s to %s validation", value?value:"<none>", known_schemas[best].name);
	crm_xml_add(xml_blob, XML_ATTR_VALIDATION, known_schemas[best].name);
    }

    return xml_blob;
}

