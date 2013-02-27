/*
  Copyright Red Hat, Inc. 2004

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the
  Free Software Foundation; either version 2, or (at your option) any
  later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING.  If not, write to the
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
  MA 02110-1301 USA
*/
#include <stdio.h>
#include <assert.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <string.h>
#include <xmlconf.h>

static xmlDocPtr conf_doc = NULL;
static const char *conffile = "/etc/cluster/cluster.conf";

/**
   Execute an XPath query, returning the first match.  Multiple matches are
   ignored.  Please be advised that this is quite inefficient.

   @param doc		Loaded XML document to search
   @param ctx		Predefined XML XPath context
   @param query		Query to execute.
   @return		newly allocated pointer to value or NULL if not found.
 */
char *
xpath_get_one(xmlDocPtr __attribute__ ((unused)) doc, xmlXPathContextPtr ctx, char *query)
{
    char *val = NULL, *ret = NULL;
    xmlXPathObjectPtr obj;
    xmlNodePtr node;
    size_t size = 0;
    int nnv = 0;

    obj = xmlXPathEvalExpression((unsigned char *)query, ctx);
    if (!obj)
        return NULL;
    if (!obj->nodesetval)
        goto out;
    if (obj->nodesetval->nodeNr <= 0)
        goto out;

    node = obj->nodesetval->nodeTab[0];
    if (!node)
        goto out;

    if (((node->type == XML_ATTRIBUTE_NODE) && strstr(query, "@*")) ||
        ((node->type == XML_ELEMENT_NODE) && strstr(query, "child::*"))) {
        if (node->children && node->children->content)
            size = strlen((char *)node->children->content) + strlen((char *)node->name) + 2;
        else
            size = strlen((char *)node->name) + 2;
        nnv = 1;
    } else {
        if (node->children && node->children->content) {
            size = strlen((char *)node->children->content) + 1;
        } else {
            goto out;
        }
    }

    val = (char *)malloc(size);
    if (!val)
        goto out;
    memset(val, 0, size);
    if (nnv) {
        sprintf(val, "%s=%s", node->name, (node->children && node->children->content) ?
                (char *)node->children->content : "");
    } else {
        sprintf(val, "%s", (node->children && node->children->content) ? node->children->content :
                node->name);
    }

    ret = val;
  out:
    xmlXPathFreeObject(obj);

    return ret;
}

int
conf_open(void)
{
    xmlInitParser();
    conf_doc = xmlParseFile(conffile);
    if (!conf_doc)
        return -1;
    return 0;
}

xmlDocPtr
conf_get_doc(void)
{
    return conf_doc;
}

int
conf_close(void)
{
    xmlFreeDoc(conf_doc);
    conf_doc = NULL;
    return 0;
}

void
conf_setconfig(char *path)
{
    conffile = path;
}

int
conf_get(char *path, char **value)
{
    char *foo;
    xmlXPathContextPtr ctx;

    ctx = xmlXPathNewContext(conf_doc);
    foo = xpath_get_one(conf_doc, ctx, path);
    xmlXPathFreeContext(ctx);

    if (foo) {
        *value = foo;
        return 0;
    }
    return 1;
}
