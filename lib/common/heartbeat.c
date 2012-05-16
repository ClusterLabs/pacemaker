/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <crm/crm.h>
#include <crm/common/xml.h>

#include <ha_msg.h>
#if HAVE_BZLIB_H
#  include <bzlib.h>
#endif

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
	HA_Message *holder = ha_msg_new(3);
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
    if(orig < CRM_BZ2_THRESHOLD) {
	ha_msg_add(msg, name, buffer);
	goto done;
    }
    
    len = (orig * 1.1) + 600; /* recomended size */
    
    crm_malloc(compressed, len);
    rc = BZ2_bzBuffToBuffCompress(compressed, &len, buffer, orig, CRM_BZ2_BLOCKS, 0, CRM_BZ2_WORK);
    
    if(rc != BZ_OK) {
	crm_err("Compression failed: %d", rc);
	crm_free(compressed);
	convert_xml_message_struct(msg, xml, name);
	goto done;
    }
    
    crm_free(buffer);
    buffer = compressed;
    crm_trace("Compression details: %d -> %d", orig, len);
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
    xmlNode *child = NULL;
    HA_Message *result = NULL;

    result = ha_msg_new(3);
    ha_msg_add(result, F_XML_TAGNAME, (const char *)xml->name);

    xml_prop_iter(xml, name, value, ha_msg_add(result, name, value));
    for(child = __xml_first_child(xml); child != NULL; child = __xml_next(child)) {
	convert_xml_child(result, child);
    }

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
	case FT_STRUCT:
	    convert_ha_message(parent, msg->values[lpc], name);
	    break;
	case FT_COMPRESS:
	case FT_UNCOMPRESS:
	    convert_ha_message(parent, cl_get_struct(msg, name), name);
	    break;
	case FT_STRING:
	    value = msg->values[lpc];
	    CRM_CHECK(value != NULL, return);
	    crm_trace("Converting %s/%d/%s", name, type, value[0] == '<' ? "xml":"field");

	    if( value[0] != '<' ) {
		crm_xml_add(parent, name, value);
		break;
	    }
	    
	    /* unpack xml string */
	    xml = string2xml(value);
	    if(xml == NULL) {
		crm_err("Conversion of field '%s' failed", name);
		return;
	    }

	    add_node_nocopy(parent, NULL, xml);
	    break;

	case FT_BINARY:
	    value = cl_get_binary(msg, name, &orig_len);
	    size = orig_len * 10 + 1; /* +1 because an exact 10x compression factor happens occasionally */

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
	    
	    crm_trace("Trying to decompress %d bytes", (int)orig_len);
	retry:
	    crm_realloc(uncompressed, size);
	    memset(uncompressed, 0, size);
	    used = size - 1; /* always leave room for a trailing '\0'
			      * BZ2_bzBuffToBuffDecompress wont say anything if
			      * the uncompressed data is exactly 'size' bytes 
			      */
	    
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
		
	    } else if(used >= size) {
		CRM_ASSERT(used < size);

	    } else {
		CRM_LOG_ASSERT(uncompressed[used] == 0);
		uncompressed[used] = 0;
		xml = string2xml(uncompressed);
	    }

	    if(xml != NULL) {
		add_node_copy(parent, xml);
		free_xml(xml);
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

    } else if(parent && safe_str_neq(field, tag)) {
	/* For compatability with 0.6.x */
	crm_debug("Creating intermediate parent %s between %s and %s", field, crm_element_name(parent), tag);
	parent = create_xml_node(parent, field);
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
