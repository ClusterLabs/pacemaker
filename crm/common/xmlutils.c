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

// all manipulations should be done in and on the XML Doc


#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <libxml/tree.h>
#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h> 

#include <crm.h>
//#include <crmutils.h>
#include <xmlutils.h>
#include <xmltags.h>

/* int		xmlGetDocCompressMode	(xmlDocPtr doc); */
/* void		xmlSetDocCompressMode	(xmlDocPtr doc, */
/* 					 int mode); */
/* int		xmlGetCompressMode	(void); */
/* void		xmlSetCompressMode	(int mode); */

/* void		xmlDocDumpMemory	(xmlDocPtr cur, */
/* 					 xmlChar **mem, */
/* 					 int *size); */

/* int		xmlNodeDump		(xmlBufferPtr buf, */
/* 					 xmlDocPtr doc, */
/* 					 xmlNodePtr cur, */
/* 					 int level, */
/* 					 int format); */

xmlNodePtr
findDeepNode(xmlNodePtr root, const char **search_path, int len)
{
    // debug tools:
    // xmlChar *	xmlGetNodePath		(xmlNodePtr node);
    // long		xmlGetLineNo		(xmlNodePtr node);

    if(root == NULL)
    {
	CRM_DEBUG("Will never find anything in NULL :)");
	return NULL;
    }
    int	j;
    CRM_DEBUG("looking for...");
    for (j=0; j < len; ++j)
    {
	if(search_path[j] == NULL) break;
	CRM_DEBUG2(" --> (%s).", search_path[j]);
    }
    
    xmlNodePtr child = root->children, lastMatch = NULL;
    for (j=0; j < len; ++j)
    {
	gboolean is_found = FALSE;
	if(search_path[j] == NULL) break;
	
	while(child != NULL)
	{
	    const char * child_name = (const char*)child->name;
	    CRM_DEBUG3("comparing (%s) with (%s).", search_path[j], child->name);
	    if(strcmp(child_name, search_path[j]) == 0)
	    {
		lastMatch = child;
		child = lastMatch->children;
		CRM_DEBUG3("found node (%s) @line (%ld).", search_path[j], xmlGetLineNo(child));
		is_found = TRUE;
		break;
	    }
	    child = child->next;
	}
	if(is_found == FALSE)
	{
	    CRM_DEBUG2("No more siblings left... %s cannot be found.", search_path[j]);
	    break;
	}
    }

    if(j == len && lastMatch != NULL && strcmp(lastMatch->name, search_path[j-1]) == 0)
    {
	CRM_DEBUG2("returning node (%s).", xmlGetNodePath(lastMatch));
	return lastMatch;
    }

    cl_log(LOG_DEBUG,
	   "Could not find the full path to the node you specified."
	   "  Closest point was node (%s).", xmlGetNodePath(lastMatch));
    return NULL;
    
}

xmlNodePtr
findNode(xmlNodePtr root, const char * search_path)
{
    return findDeepNode(root, &search_path, 1);
}

xmlNodePtr
findEntity(xmlNodePtr parent, const char *node_name, const char *id, gboolean siblings)
{
    return findEntityAdvanced(parent, node_name, NULL, NULL, id, siblings);
}

xmlNodePtr
findEntityAdvanced(xmlNodePtr parent, const char *node_name, const char *elem_filter_name, const char *elem_filter_value, const char *id, gboolean siblings)
{
    // debug tools:
    // xmlChar *	xmlGetNodePath		(xmlNodePtr node);
    // long		xmlGetLineNo		(xmlNodePtr node);

    cl_log(LOG_DEBUG, "Looking for %s elem with id=%s.", node_name, id);

    xmlNodePtr child;

    while(parent != NULL)
    {
	CRM_DEBUG2("examining (%s).", xmlGetNodePath(parent));
	child = parent->children;
	
	while(child != NULL)
	{
	    
	    CRM_DEBUG2("looking for (%s) [name].", node_name);
	    if(node_name != NULL && strcmp(child->name, node_name) != 0)
	    {    
		CRM_DEBUG3("skipping entity (%s=%s) [node_name].", xmlGetNodePath(child), child->name);
		break;
	    }
	    else if(elem_filter_name != NULL && elem_filter_value != NULL)
	    {
		const char* child_value = (const char*)xmlGetProp(child, elem_filter_name);
		cl_log(LOG_DEBUG, "comparing (%s) with (%s) [attr_value].", child_value, elem_filter_value);
		if(strcmp(child_value, elem_filter_value))
		{
		    CRM_DEBUG2("skipping entity (%s) [attr_value].", xmlGetNodePath(child));
		    break;
		}
	    }
		
//	    cl_log(LOG_DEBUG, "looking for entity (%s) in %s.", id, xmlGetNodePath(child));
	    while(child != NULL)
	    {
		cl_log(LOG_DEBUG, "looking for entity (%s) in %s.", id, xmlGetNodePath(child));
		xmlChar *child_id = xmlGetProp(child, "id");
		if(child_id == NULL)
		{
		    cl_log(LOG_CRIT, "Entity (%s) has id=NULL... Cib not valid!", xmlGetNodePath(child));
		}
		else if(strcmp(id, child_id) == 0)
		{
		    CRM_DEBUG2("found entity (%s).", id);
		    return child;
		}   
		child = child->next;
	    }
	}

	if(siblings == TRUE)
	{
	    CRM_DEBUG("Nothing yet... checking siblings");	    
	    parent = parent->next;
	}
	else
	    parent = NULL;
    }
    CRM_DEBUG("Couldnt find anything appropriate");	    
    return NULL;
    
}


int
addNode(xmlNodePtr cib, const char *node_path, xmlNodePtr xml_node)
{
    xmlNodePtr parent = findNode(cib, node_path);

    if(parent == NULL)
    {
	CRM_DEBUG2("could not find parent for new node (%s).", xml_node->name);
	return -1;
    }
    
    if(xmlAddChild(parent, xml_node) != NULL) return 0;

    
    return -2;
}

void
copyInProperties(xmlNodePtr src, xmlNodePtr target)
{
    xmlAttrPtr property = src->properties;
    char *node_id = xmlGetProp(src, "id");
    while(property != NULL)
    {
	cl_log(LOG_DEBUG, "Update: (%s) with property:value (%s:%s)", node_id, property->name, xmlGetProp(src, property->name));
	xmlSetProp(target, property->name, xmlGetProp(src, property->name));
	property = property->next;
    }
}


xmlNodePtr
xmlLinkedCopyNoSiblings(xmlNodePtr src, int recursive)
{
    /*
     * keep the properties linked so there is only one point of update
     *   but we dont want the sibling pointers
     */
    xmlNodePtr node_copy = xmlCopyNode(src, recursive);
    //node_copy->properties = src->properties;
    return node_copy;
}

char * 
dump_xml(xmlNodePtr msg)
{
    return dump_xml_node(msg, FALSE);
}

char * 
dump_xml_node(xmlNodePtr msg, gboolean whole_doc)
{
    CRM_DEBUG("delete me - 2.");
    xmlChar *xml_message = NULL;
    if(msg == NULL) return NULL;

    int msg_size = -1;

    CRM_DEBUG("delete me - 3.");
    xmlInitParser();
    CRM_DEBUG("delete me - 4.");

    if(whole_doc)
    {
	CRM_DEBUG("delete me - 5.");
	if(msg->doc == NULL)
	{
	    cl_log(LOG_ERR, "XML doc was NULL");
	    return NULL;
	}
	xmlDocDumpMemory(msg->doc, &xml_message, &msg_size);
	CRM_DEBUG("delete me - 5.5");
    }
    else
    {
	CRM_DEBUG("delete me - 6.");
/* 	if(0) */
/* 	{ */

	CRM_DEBUG2("mem used by xml: %d", xmlMemUsed());
    
	xmlMemoryDump ();
	
	xmlBufferPtr xml_buffer = xmlBufferCreate();
	CRM_DEBUG("About to dump XML into buffer");
	msg_size = xmlNodeDump(xml_buffer, msg->doc, msg, 0, 0);

	CRM_DEBUG2("Dumped XML into buffer: [%s]", xmlBufferContent(xml_buffer));
	
	xml_message = (xmlChar*)strdup((char*)xml_buffer->content); 
	if(!xml_message) {
		cl_log(LOG_ERR, "memory allocation failed in dump_xml_node()");
		return NULL;
	}
	
//	CRM_DEBUG2("Before free: [%s]", xml_message);
	xmlBufferFree(xml_buffer);
//	CRM_DEBUG2("After free: [%s]", xml_message);
    }
    CRM_DEBUG2("Dumped %d XML characters into buffer", msg_size);

    // HA wont send messages with newlines in them.
    int lpc = 0;
    for(; lpc < msg_size; lpc++)
	if(xml_message[lpc] == '\n')
	    xml_message[lpc] = ' ';
    
    return (char*)xml_message; 
}

/* typedef enum { */
/*     XML_ELEMENT_NODE=           1, */
/*     XML_ATTRIBUTE_NODE=         2, */
/*     XML_TEXT_NODE=              3, */
/*     XML_CDATA_SECTION_NODE=     4, */
/*     XML_ENTITY_REF_NODE=        5, */
/*     XML_ENTITY_NODE=            6, */
/*     XML_PI_NODE=                7, */
/*     XML_COMMENT_NODE=           8, */
/*     XML_DOCUMENT_NODE=          9, */
/*     XML_DOCUMENT_TYPE_NODE=     10, */
/*     XML_DOCUMENT_FRAG_NODE=     11, */
/*     XML_NOTATION_NODE=          12, */
/*     XML_HTML_DOCUMENT_NODE=     13, */
/*     XML_DTD_NODE=               14, */
/*     XML_ELEMENT_DECL=           15, */
/*     XML_ATTRIBUTE_DECL=         16, */
/*     XML_ENTITY_DECL=            17, */
/*     XML_NAMESPACE_DECL=         18, */
/*     XML_XINCLUDE_START=         19, */
/*     XML_XINCLUDE_END=           20 */
/* #ifdef LIBXML_DOCB_ENABLED */
/*    ,XML_DOCB_DOCUMENT_NODE=     21 */
/* #endif */
/* } xmlElementType; */

/* typedef struct _xmlAttribute xmlAttribute; */
/* typedef xmlAttribute *xmlAttributePtr; */
/* struct _xmlAttribute { */
/*     void           *_private;           /\* application data *\/ */
/*     xmlElementType          type;       /\* XML_ATTRIBUTE_DECL, must be second ! *\/ */
/*     const xmlChar          *name;       /\* Attribute name *\/ */
/*     struct _xmlNode    *children;       /\* NULL *\/ */
/*     struct _xmlNode        *last;       /\* NULL *\/ */
/*     struct _xmlDtd       *parent;       /\* -> DTD *\/ */
/*     struct _xmlNode        *next;       /\* next sibling link  *\/ */
/*     struct _xmlNode        *prev;       /\* previous sibling link  *\/ */
/*     struct _xmlDoc          *doc;       /\* the containing document *\/ */
                                                                                         
/*     struct _xmlAttribute  *nexth;       /\* next in hash table *\/ */
/*     xmlAttributeType       atype;       /\* The attribute type *\/ */
/*     xmlAttributeDefault      def;       /\* the default *\/ */
/*     const xmlChar  *defaultValue;       /\* or the default value *\/ */
/*     xmlEnumerationPtr       tree;       /\* or the enumeration tree if any *\/ */
/*     const xmlChar        *prefix;       /\* the namespace prefix if any *\/ */
/*     const xmlChar          *elem;       /\* Element holding the attribute *\/ */
/* }; */

/* typedef struct _xmlElementContent xmlElementContent; */
/* typedef xmlElementContent *xmlElementContentPtr; */
/* struct _xmlElementContent { */
/*     xmlElementContentType     type;     /\* PCDATA, ELEMENT, SEQ or OR *\/ */
/*     xmlElementContentOccur    ocur;     /\* ONCE, OPT, MULT or PLUS *\/ */
/*     const xmlChar             *name;    /\* Element name *\/ */
/*     struct _xmlElementContent *c1;      /\* first child *\/ */
/*     struct _xmlElementContent *c2;      /\* second child *\/ */
/*     struct _xmlElementContent *parent;  /\* parent *\/ */
/*     const xmlChar             *prefix;  /\* Namespace prefix *\/ */
/* }; */

/* typedef struct _xmlElement xmlElement; */
/* typedef xmlElement *xmlElementPtr; */
/* struct _xmlElement { */
/*     void           *_private;           /\* application data *\/ */
/*     xmlElementType          type;       /\* XML_ELEMENT_DECL, must be second ! *\/ */
/*     const xmlChar          *name;       /\* Element name *\/ */
/*     struct _xmlNode    *children;       /\* NULL *\/ */
/*     struct _xmlNode        *last;       /\* NULL *\/ */
/*     struct _xmlDtd       *parent;       /\* -> DTD *\/ */
/*     struct _xmlNode        *next;       /\* next sibling link  *\/ */
/*     struct _xmlNode        *prev;       /\* previous sibling link  *\/ */
/*     struct _xmlDoc          *doc;       /\* the containing document *\/ */
 
/*     xmlElementTypeVal      etype;       /\* The type *\/ */
/*     xmlElementContentPtr content;       /\* the allowed element content *\/ */
/*     xmlAttributePtr   attributes;       /\* List of the declared attributes *\/ */
/*     const xmlChar        *prefix;       /\* the namespace prefix if any *\/ */
/* #ifdef LIBXML_REGEXP_ENABLED */
/*     xmlRegexpPtr       contModel;       /\* the validating regexp *\/ */
/* #else */
/*     void              *contModel; */
/* #endif */
/* }; */

/* typedef struct _xmlAttr xmlAttr; */
/* typedef xmlAttr *xmlAttrPtr; */
/* struct _xmlAttr { */
/*     void           *_private;   /\* application data *\/ */
/*     xmlElementType   type;      /\* XML_ATTRIBUTE_NODE, must be second ! *\/ */
/*     const xmlChar   *name;      /\* the name of the property *\/ */
/*     struct _xmlNode *children;  /\* the value of the property *\/ */
/*     struct _xmlNode *last;      /\* NULL *\/ */
/*     struct _xmlNode *parent;    /\* child->parent link *\/ */
/*     struct _xmlAttr *next;      /\* next sibling link  *\/ */
/*     struct _xmlAttr *prev;      /\* previous sibling link  *\/ */
/*     struct _xmlDoc  *doc;       /\* the containing document *\/ */
/*     xmlNs           *ns;        /\* pointer to the associated namespace *\/ */
/*     xmlAttributeType atype;     /\* the attribute type if validating *\/ */
/* }; */



/* typedef struct _xmlNode xmlNode; */
/* typedef xmlNode *xmlNodePtr; */
/* struct _xmlNode { */
/*     void           *_private;	/\* application data *\/ */
/*     xmlElementType   type;	/\* type number, must be second ! *\/ */
/*     const xmlChar   *name;      /\* the name of the node, or the entity *\/ */
/*     struct _xmlNode *children;	/\* parent->childs link *\/ */
/*     struct _xmlNode *last;	/\* last child link *\/ */
/*     struct _xmlNode *parent;	/\* child->parent link *\/ */
/*     struct _xmlNode *next;	/\* next sibling link  *\/ */
/*     struct _xmlNode *prev;	/\* previous sibling link  *\/ */
/*     struct _xmlDoc  *doc;	/\* the containing document *\/ */

/*     /\* End of common part *\/ */
/*     xmlNs           *ns;        /\* pointer to the associated namespace *\/ */
/*     xmlChar         *content;   /\* the content *\/ */
/*     struct _xmlAttr *properties;/\* properties list *\/ */
/*     xmlNs           *nsDef;     /\* namespace definitions on this node *\/ */
/* }; */



// /usr/include/libxml2/libxml/tree.h

//----- READ()
//xmlDocPtr xmlParseMemory(char *buffer, int size);
//xmlDocPtr xmlParseFile(const char *filename);

//----- SAVE()
//int xmlSaveFile(const char *filename, xmlDocPtr cur);
//    Saves the document to a file. In this case, the compression interface is triggered if it has been turned on.
//void xmlDocDumpMemory(xmlDocPtr cur, xmlChar**mem, int *size);
//    Returns a buffer into which the document has been saved.

//-----	Compression
/* The library transparently handles compression when doing file-based accesses. The level of compression on saves can be turned on either globally or individually for one file: */
/* int xmlGetDocCompressMode (xmlDocPtr doc); */
/*     Gets the document compression ratio (0-9). */
/* void xmlSetDocCompressMode (xmlDocPtr doc, int mode); */
/*     Sets the document compression ratio. */
/* int xmlGetCompressMode(void); */
/*     Gets the default compression ratio. */
/* void xmlSetCompressMode(int mode); */
/*     Sets the default compression ratio. */

//----- Modify()

// to get the root element:  xmlDocGetRootElement()

/* Functions are provided for reading and writing the document content. Here is an excerpt from the tree API: */
/* xmlAttrPtr xmlSetProp(xmlNodePtr node, const xmlChar *name, const xmlChar *value); */
/*     This sets (or changes) an attribute carried by an ELEMENT node. The value can be NULL. */
/* const xmlChar *xmlGetProp(xmlNodePtr node, const xmlChar *name); */
/*     This function returns a pointer to new copy of the property content. Note that the user must deallocate the result. */
/* Two functions are provided for reading and writing the text associated with elements: */
/* xmlNodePtr xmlStringGetNodeList(xmlDocPtr doc, const xmlChar *value); */
/*     This function takes an "external" string and converts it to one text node or possibly to a list of entity and text nodes. All non-predefined entity references like &Gnome; will be stored internally as entity nodes, hence the result of the function may not be a single node. */
/* xmlChar *xmlNodeListGetString(xmlDocPtr doc, xmlNodePtr list, int inLine); */
/*     This function is the inverse of xmlStringGetNodeList(). It generates a new string containing the content of the text and entity nodes. Note the extra argument inLine. If this argument is set to 1, the function will expand entity references. For example, instead of returning the &Gnome; XML encoding in the string, it will substitute it with its value (say, "GNU Network Object Model Environment"). */

/* //----- CREATE() */
/* xmlDocPtr */
/* createTree(void) */
/* {     */
/*     xmlDocPtr doc; */
/*     xmlNodePtr tree, subtree; */

/*     doc = xmlNewDoc("1.0"); */
/*     doc->children = xmlNewDocNode(doc, NULL, "EXAMPLE", NULL); */
/*     xmlSetProp(doc->children, "prop1", "gnome is great"); */
/*     xmlSetProp(doc->children, "prop2", "& linux too"); */
/*     tree = xmlNewChild(doc->children, NULL, "head", NULL); */
/*     subtree = xmlNewChild(tree, NULL, "title", "Welcome to Gnome"); */
/*     tree = xmlNewChild(doc->children, NULL, "chapter", NULL); */
/*     subtree = xmlNewChild(tree, NULL, "title", "The Linux adventure"); */
/*     subtree = xmlNewChild(tree, NULL, "p", "bla bla bla ..."); */
/*     subtree = xmlNewChild(tree, NULL, "image", NULL); */
/*     xmlSetProp(subtree, "href", "linus.gif"); */

/*     return doc;    */
/* } */
