/*
  Copyright Red Hat, Inc. 2004-2010

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
#include <libxml/parser.h>
#include <libxml/xmlmemory.h>
#include <libxml/xpath.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <resgroup.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <list.h>
#include <ctype.h>
#include <reslist.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/wait.h>
#include <xmlconf.h>

/**
   Store a new resource rule in the given rule list.

   @param rulelist	List of rules to store new rule in.
   @param newrule	New rule to store.
   @return		0 on success or -1 if rule with same name
			already exists in rulelist
 */
static int
store_rule(resource_rule_t ** rulelist, resource_rule_t * newrule)
{
    resource_rule_t *curr;

    list_do(rulelist, curr) {
        if (!strcmp(newrule->rr_type, curr->rr_type)) {
            fprintf(stderr, "Error storing %s: Duplicate\n", newrule->rr_type);
            return -1;
        }

    }
    while (!list_done(rulelist, curr)) ;

    list_insert(rulelist, newrule);
    return 0;
}

/**
   Obliterate a resource_rule_t structure.

   @param rr		Resource rule to free.
 */
static void
destroy_resource_rule(resource_rule_t * rr)
{
    int x;

    if (rr->rr_type)
        free(rr->rr_type);
    if (rr->rr_agent)
        free(rr->rr_agent);
    if (rr->rr_version)
        free(rr->rr_version);

    if (rr->rr_attrs) {
        for (x = 0; rr->rr_attrs && rr->rr_attrs[x].ra_name; x++) {
            free(rr->rr_attrs[x].ra_name);
            if (rr->rr_attrs[x].ra_value)
                free(rr->rr_attrs[x].ra_value);
        }

        free(rr->rr_attrs);
    }

    if (rr->rr_actions) {
        for (x = 0; rr->rr_actions && rr->rr_actions[x].ra_name; x++) {
            free(rr->rr_actions[x].ra_name);
        }

        free(rr->rr_actions);
    }

    if (rr->rr_childtypes) {
        for (x = 0; rr->rr_childtypes && rr->rr_childtypes[x].rc_name; x++)
            free(rr->rr_childtypes[x].rc_name);
        free(rr->rr_childtypes);
    }

    free(rr);
}

/**
   Destroy a list of resource rules.

   @param rules		List of rules to destroy.
 */
void
destroy_resource_rules(resource_rule_t ** rules)
{
    resource_rule_t *rr;

    while ((rr = *rules)) {
        list_remove(rules, rr);
        destroy_resource_rule(rr);
    }
}

/**
   Get and store the maxparents (max instances) attribute for a given
   resource rule set.

   @param doc		Pre-parsed XML document pointer.
   @param ctx		Pre-allocated XML XPath context pointer.
   @param base		XPath prefix to search
   @param rr		Resource rule to store new information in.
 */
static void
_get_maxparents(xmlDocPtr doc, xmlXPathContextPtr ctx, char *base, resource_rule_t * rr)
{
    char xpath[256];
    char *ret = NULL;

    snprintf(xpath, sizeof(xpath), "%s/attributes/@maxinstances", base);
    ret = xpath_get_one(doc, ctx, xpath);
    if (ret) {
        rr->rr_maxrefs = atoi(ret);
        if (rr->rr_maxrefs < 0)
            rr->rr_maxrefs = 0;
        free(ret);
    }
}

/**
   Get and store a bit field.

   @param doc		Pre-parsed XML document pointer.
   @param ctx		Pre-allocated XML XPath context pointer.
   @param base		XPath prefix to search
   @param rr		Resource rule to store new information in.
 */
static void
_get_rule_flag(xmlDocPtr doc, xmlXPathContextPtr ctx, const char *base,
               resource_rule_t * rr, const char *flag, int bit)
{
    char xpath[256];
    char *ret = NULL;

    snprintf(xpath, sizeof(xpath), "%s/attributes/@%s", base, flag);
    ret = xpath_get_one(doc, ctx, xpath);
    if (ret) {
        if (atoi(ret)) {
            rr->rr_flags |= bit;
        } else {
            rr->rr_flags &= ~bit;
        }
        free(ret);
    }
}

/**
   Get and store the version

   @param doc		Pre-parsed XML document pointer.
   @param ctx		Pre-allocated XML XPath context pointer.
   @param base		XPath prefix to search
   @param rr		Resource rule to store new information in.
 */
static void
_get_version(xmlDocPtr doc, xmlXPathContextPtr ctx, char *base, resource_rule_t * rr)
{
    char xpath[256];
    char *ret = NULL;

    snprintf(xpath, sizeof(xpath), "%s/@version", base);
    ret = xpath_get_one(doc, ctx, xpath);
    if (ret) {
        rr->rr_version = ret;
        free(ret);
    }
    rr->rr_version = NULL;
}

int
expand_time(char *val)
{
    int curval, len;
    int ret = 0;
    char *start = val, ival[16];

    if (!val)
        return (time_t) 0;

    while (start[0]) {

        len = 0;
        curval = 0;
        memset(ival, 0, sizeof(ival));

        while (isdigit(start[len])) {
            ival[len] = start[len];
            len++;
        }

        if (len) {
            curval = atoi(ival);
        } else {
            len = 1;
        }

        switch (start[len]) {
            case 0:
            case 'S':
            case 's':
                break;
            case 'M':
            case 'm':
                curval *= 60;
                break;
            case 'h':
            case 'H':
                curval *= 3600;
                break;
            case 'd':
            case 'D':
                curval *= 86400;
                break;
            case 'w':
            case 'W':
                curval *= 604800;
                break;
            case 'y':
            case 'Y':
                curval *= 31536000;
                break;
            default:
                curval = 0;
        }

        ret += (time_t) curval;
        start += len;
    }

    return ret;
}

/**
 * Store a resource action
 * @param actsp		Action array; may be modified and returned!
 * @param name		Name of the action
 * @param depth		Resource depth (status/monitor; -1 means *ALL LEVELS*
 * 			... this means that only the highest-level check depth
 * 			will ever be performed!)
 * @param timeout	Timeout (not used)
 * @param interval	Time interval for status/monitor
 * @return		0 on success, -1 on failure
 *
 */
int
store_action(resource_act_t ** actsp, char *name, int depth, int timeout, int interval)
{
    int x = 0, replace = 0;
    resource_act_t *acts = *actsp;

    if (!name)
        return -1;

    if (depth < 0 && timeout < 0 && interval < 0)
        return -1;

    if (!acts) {
        /* Can't create with anything < 0 */
        if (depth < 0 || timeout < 0 || interval < 0)
            return -1;

        acts = malloc(sizeof(resource_act_t) * 2);
        if (!acts)
            return -1;
        acts[0].ra_name = name;
        acts[0].ra_depth = depth;
        acts[0].ra_timeout = timeout;
        acts[0].ra_interval = interval;
        acts[0].ra_last = 0;
        acts[1].ra_name = NULL;

        *actsp = acts;
        return 0;
    }

    for (x = 0; acts[x].ra_name; x++) {
        if (!strcmp(acts[x].ra_name, name) && (depth == acts[x].ra_depth || depth == -1)) {
            fprintf(stderr, "Replacing action '%s' depth %d: ", name, acts[x].ra_depth);
            if (timeout >= 0) {
                fprintf(stderr, "timeout: %d->%d ", (int)acts[x].ra_timeout, (int)timeout);
                acts[x].ra_timeout = timeout;
            }
            if (interval >= 0) {
                fprintf(stderr, "interval: %d->%d", (int)acts[x].ra_interval, (int)interval);
                acts[x].ra_interval = interval;
            }
            fprintf(stderr, "\n");
            replace = 1;
        }
    }

    if (replace)
        /* If we replaced something, we're done */
        return 1;

    /* Can't create with anything < 0 */
    if (depth < 0 || timeout < 0 || interval < 0)
        return -1;

    acts = realloc(acts, sizeof(resource_act_t) * (x + 2));
    if (!acts)
        return -1;

    acts[x].ra_name = name;
    acts[x].ra_depth = depth;
    acts[x].ra_timeout = timeout;
    acts[x].ra_interval = interval;
    acts[x].ra_last = 0;

    acts[x + 1].ra_name = NULL;

    *actsp = acts;
    return 0;
}

static void
_get_actions(xmlDocPtr doc, xmlXPathContextPtr ctx, char *base, resource_rule_t * rr)
{
    char xpath[256];
    int idx = 0;
    char *act, *ret;
    int interval, timeout, depth;

    do {
        interval = 0;
        depth = 0;
        act = NULL;
        timeout = 0;

        snprintf(xpath, sizeof(xpath), "%s/action[%d]/@name", base, ++idx);

        act = xpath_get_one(doc, ctx, xpath);
        if (!act)
            break;

        snprintf(xpath, sizeof(xpath), "%s/action[%d]/@timeout", base, idx);
        ret = xpath_get_one(doc, ctx, xpath);
        if (ret) {
            timeout = expand_time(ret);
            if (timeout < 0)
                timeout = 0;
            free(ret);
        }

        snprintf(xpath, sizeof(xpath), "%s/action[%d]/@interval", base, idx);
        ret = xpath_get_one(doc, ctx, xpath);
        if (ret) {
            interval = expand_time(ret);
            if (interval < 0)
                interval = 0;
            free(ret);
        }

        if (!strcmp(act, "status") || !strcmp(act, "monitor")) {
            snprintf(xpath, sizeof(xpath), "%s/action[%d]/@depth", base, idx);
            ret = xpath_get_one(doc, ctx, xpath);
            if (ret) {
                depth = atoi(ret);
                if (depth < 0)
                    depth = 0;
                free(ret);
            }
        }

        if (store_action(&rr->rr_actions, act, depth, timeout, interval) != 0)
            free(act);
    } while (1);
}

/**
   Store an attribute with the given name, value, and flags in a resource_t
   structure.
   XXX This could be rewritten to use the list macros.

   @param attrsp	Attribute array to store new attribute in.
   @param name		Name of attribute (must be non-null)
   @param value		Value of attribute
   @param flags		Attribute flags, or 0 if none.
   @return		0 on success, nonzero on error/failure
 */
int
store_attribute(resource_attr_t ** attrsp, char *name, char *value, int flags)
{
    int x = 0;
    resource_attr_t *attrs = *attrsp;

    if (!name)
        return -1;

    if (!attrs) {
        attrs = malloc(sizeof(resource_attr_t) * 2);
        if (!attrs)
            return -1;
        attrs[0].ra_name = name;
        attrs[0].ra_value = value;
        attrs[0].ra_flags = flags;
        attrs[1].ra_name = NULL;
        attrs[1].ra_value = NULL;

        *attrsp = attrs;
        return 0;
    }

    for (x = 0; attrs[x].ra_name; x++) ;

    attrs = realloc(attrs, sizeof(resource_attr_t) * (x + 2));
    if (!attrs)
        return -1;

    /* Primary attribute goes first.  This makes this interaction
       with CCS work way faster. */
    if (flags & RA_PRIMARY) {
        attrs[x].ra_name = attrs[0].ra_name;
        attrs[x].ra_value = attrs[0].ra_value;
        attrs[x].ra_flags = attrs[0].ra_flags;
        attrs[0].ra_name = name;
        attrs[0].ra_value = value;
        attrs[0].ra_flags = flags;
    } else {
        attrs[x].ra_name = name;
        attrs[x].ra_value = value;
        attrs[x].ra_flags = flags;
    }
    attrs[x + 1].ra_name = NULL;
    attrs[x + 1].ra_value = NULL;

    *attrsp = attrs;
    return 0;
}

/**
   Store a child type in the child array of a resource rule.
   XXX Could be rewritten to use list macros.

   @param childp	Child array.  Might be modified.
   @param name		Name of child type
   @param start		Start level
   @param stop		Stop level
   @param forbid	Do NOT allow this child type to exist
   @param flags		set to 1 to note that it was defined inline
   @return		0 on success, nonzero on failure
 */
static int
store_childtype(resource_child_t ** childp, char *name, int start, int stop, int forbid, int flags)
{
    int x = 0;
    resource_child_t *child = *childp;

    if (!name)
        return -1;

    if (!child) {
        child = malloc(sizeof(resource_child_t) * 2);
        if (!child)
            return -1;
        child[0].rc_name = name;
        child[0].rc_startlevel = start;
        child[0].rc_stoplevel = stop;
        child[0].rc_forbid = forbid;
        child[0].rc_flags = flags;
        child[1].rc_name = NULL;

        *childp = child;
        return 0;
    }

    for (x = 0; child[x].rc_name; x++) ;

    child = realloc(child, sizeof(resource_child_t) * (x + 2));
    if (!child)
        return -1;

    child[x].rc_name = name;
    child[x].rc_startlevel = start;
    child[x].rc_stoplevel = stop;
    child[x].rc_forbid = forbid;
    child[x].rc_flags = flags;
    child[x + 1].rc_name = NULL;

    *childp = child;
    return 0;
}

/**
   Get and store attributes for a given instance of a resource rule.

   @param doc		Pre-parsed XML document pointer.
   @param ctx		Pre-allocated XML XPath context pointer.
   @param base		XPath prefix to search
   @param rr		Resource rule to store new information in.
   @return		0
 */
static int
_get_rule_attrs(xmlDocPtr doc, xmlXPathContextPtr ctx, const char *base, resource_rule_t * rr)
{
    char *ret, *attrname, *dflt = NULL, xpath[256];
    int x, flags, primary_found = 0;

    for (x = 1; 1; x++) {
        snprintf(xpath, sizeof(xpath), "%s/parameter[%d]/@name", base, x);

        ret = xpath_get_one(doc, ctx, xpath);
        if (!ret)
            break;

        flags = 0;
        attrname = ret;

        /*
           See if there's a default value.
         */
        snprintf(xpath, sizeof(xpath), "%s/parameter[%d]/content/@default", base, x);
        dflt = xpath_get_one(doc, ctx, xpath);

        /*
           See if this is either the primary identifier or
           a required field.
         */
        snprintf(xpath, sizeof(xpath), "%s/parameter[%d]/@required", base, x);
        if ((ret = xpath_get_one(doc, ctx, xpath))) {
            if ((atoi(ret) != 0) || (ret[0] == 'y'))
                flags |= RA_REQUIRED;
            free(ret);
        }

        /*
           See if this is supposed to be unique
         */
        snprintf(xpath, sizeof(xpath), "%s/parameter[%d]/@unique", base, x);
        if ((ret = xpath_get_one(doc, ctx, xpath))) {
            if ((atoi(ret) != 0) || (ret[0] == 'y'))
                flags |= RA_UNIQUE;
            free(ret);
        }

        snprintf(xpath, sizeof(xpath), "%s/parameter[%d]/@primary", base, x);
        if ((ret = xpath_get_one(doc, ctx, xpath))) {
            if ((atoi(ret) != 0) || (ret[0] == 'y')) {
                if (primary_found) {
                    free(ret);
                    fprintf(stderr, "Multiple primary "
                            "definitions for " "resource type %s\n", rr->rr_type);
                    return -1;
                }
                flags |= RA_PRIMARY;
                primary_found = 1;
            }
            free(ret);
        }

        /*
           See if this can be reconfigured on the fly without a
           stop/start
         */
        snprintf(xpath, sizeof(xpath), "%s/parameter[%d]/@reconfig", base, x);
        if ((ret = xpath_get_one(doc, ctx, xpath))) {
            if ((atoi(ret) != 0) || (ret[0] == 'y'))
                flags |= RA_RECONFIG;
            free(ret);
        }

        /*
           See if this is supposed to be inherited
         */
        snprintf(xpath, sizeof(xpath), "%s/parameter[%d]/@inherit", base, x);
        if ((ret = xpath_get_one(doc, ctx, xpath))) {
            flags |= RA_INHERIT;

            if (flags & (RA_REQUIRED | RA_PRIMARY | RA_UNIQUE)) {
                free(ret);
                fprintf(stderr, "Can not inherit and be primary, " "unique, or required\n");
                return -1;
            }
            /*
               don't free ret.  Store as attr value.  If we had
               a default value specified from above, free it;
               inheritance supercedes a specified default value.
             */
            if (dflt)
                free(dflt);
        } else {
            /*
               Use default value, if specified, as the attribute
               value.
             */
            ret = dflt;
        }

        /*
           Store the attribute.  We'll ensure all required
           attributes are present soon.
         */
        if (attrname)
            store_attribute(&rr->rr_attrs, attrname, ret, flags);
    }

    return 0;
}

/**
   Get and store attributes for a given instance of a resource.

   @param doc		Pre-parsed XML document pointer.
   @param ctx		Pre-allocated XML XPath context pointer.
   @param base		XPath prefix to search
   @param rr		Resource rule to store new information in.
   @return		0
 */
static int
_get_childtypes(xmlDocPtr doc, xmlXPathContextPtr ctx, char *base, resource_rule_t * rr)
{
    char *ret, *childname, xpath[256];
    int x, startlevel = 0, stoplevel = 0, forbid = 0;

    for (x = 1; 1; x++) {
        snprintf(xpath, sizeof(xpath), "%s/child[%d]/@type", base, x);

        ret = xpath_get_one(doc, ctx, xpath);
        if (!ret)
            break;

        startlevel = stoplevel = forbid = 0;
        childname = ret;

        /*
           Try to get the start level if it exists
         */
        snprintf(xpath, sizeof(xpath), "%s/child[%d]/@start", base, x);
        if ((ret = xpath_get_one(doc, ctx, xpath))) {
            startlevel = atoi(ret);
            free(ret);
        }

        /*
           Try to get the stop level if it exists
         */
        snprintf(xpath, sizeof(xpath), "%s/child[%d]/@stop", base, x);
        if ((ret = xpath_get_one(doc, ctx, xpath))) {
            stoplevel = atoi(ret);
            free(ret);
        }

        /*
           Get the 'forbidden' flag if it exists
         */
        snprintf(xpath, sizeof(xpath), "%s/child[%d]/@forbid", base, x);
        if ((ret = xpath_get_one(doc, ctx, xpath))) {
            forbid = atoi(ret);
            free(ret);
        }

        /*
           Store the attribute.  We'll ensure all required
           attributes are present soon.
         */
        if (childname)
            store_childtype(&rr->rr_childtypes, childname, startlevel, stoplevel, forbid, 0);
    }

    return 0;
}

/**
  Read a file from a stdout pipe.
 */
static int
read_pipe(int fd, char **file, size_t * length)
{
    char buf[4096];
    int n, done = 0;

    *file = NULL;
    *length = 0;

    while (!done) {

        n = read(fd, buf, sizeof(buf));
        if (n < 0) {

            if (errno == EINTR)
                continue;

            if (*file)
                free(*file);
            return -1;
        }

        if (n == 0 && (!*length))
            return 0;

        if (n == 0) {
            done = 1;
        }

        if (*file)
            *file = realloc(*file, (*length) + n + done);
        else
            *file = malloc(n + done);

        if (!*file)
            return -1;

        memcpy((*file) + (*length), buf, n);
        *length += (done + n);
    }

    /* Null terminator */
    (*file)[(*length) - 1] = 0;

    return 0;
}

static xmlDocPtr
read_resource_agent_metadata(char *filename)
{
    int pid;
    int _pipe[2];
    char *data;
    size_t size;
    xmlDocPtr doc;

    if (pipe(_pipe) == -1)
        return NULL;

    pid = fork();
    if (pid == -1) {
        close(_pipe[0]);
        close(_pipe[1]);
    }

    if (pid == 0) {
        /* child */
        close(0);
        close(1);
        close(2);

        close(_pipe[0]);
        dup2(_pipe[1], 1);
        close(_pipe[1]);

        /* exec */
        execl(filename, filename, "meta-data", NULL);
        exit(1);
    }

    close(_pipe[1]);
    /* parent */
    if (read_pipe(_pipe[0], &data, &size) == -1) {
        close(_pipe[0]);
        return NULL;
    }

    waitpid(pid, NULL, 0);
    close(_pipe[0]);

    if (!size)
        return NULL;

    doc = xmlParseMemory(data, size);
    free(data);
    return doc;
}

/**
   Load the XML rule set for a resource and store attributes, constructing
   a new resource_t structure.

   @param filename	File name to load rules from
   @param rules		Rule list to add new rules to
   @return		0
 */
static int
load_resource_rulefile(char *filename, resource_rule_t ** rules)
{
    resource_rule_t *rr = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctx = NULL;
    int ruleid = 0;
    char *type;
    char base[256];

    doc = read_resource_agent_metadata(filename);
    if (!doc)
        return 0;
    ctx = xmlXPathNewContext(doc);

    do {
        /* Look for resource types */
        snprintf(base, sizeof(base), "/resource-agent[%d]/@name", ++ruleid);
        type = xpath_get_one(doc, ctx, base);
        if (!type)
            break;

        if (!strcasecmp(type, "action")) {
            fprintf(stderr, "Error: Resource type '%s' is reserved", type);
            free(type);
            break;
        }

        rr = malloc(sizeof(*rr));
        if (!rr)
            break;
        memset(rr, 0, sizeof(*rr));

        rr->rr_flags = RF_INIT | RF_DESTROY;
        rr->rr_type = type;
        snprintf(base, sizeof(base), "/resource-agent[%d]", ruleid);

        /*
           First, grab the global attributes if existent
         */
        _get_version(doc, ctx, base, rr);

        snprintf(base, sizeof(base), "/resource-agent[%d]/special[@tag=\"rgmanager\"]", ruleid);
        _get_maxparents(doc, ctx, base, rr);
        _get_rule_flag(doc, ctx, base, rr, "init_on_add", RF_INIT);
        _get_rule_flag(doc, ctx, base, rr, "destroy_on_delete", RF_DESTROY);
        rr->rr_agent = strdup(filename);

        /*
           Second, add the children fields
         */
        _get_childtypes(doc, ctx, base, rr);

        /*
           Get the OCF status check intervals/monitor.
         */
        snprintf(base, sizeof(base), "/resource-agent[%d]/actions", ruleid);
        _get_actions(doc, ctx, base, rr);

        /*
           Last, load the attributes from our XML file and their
           respective instantiations from CCS
         */
        snprintf(base, sizeof(base), "/resource-agent[%d]/parameters", ruleid);
        if (_get_rule_attrs(doc, ctx, base, rr) < 0) {
            destroy_resource_rule(rr);
            rr = NULL;
        }

        if (!rr)
            continue;

        if (store_rule(rules, rr) != 0) {
            destroy_resource_rule(rr);
            rr = NULL;
        }
    } while (1);

    if (ctx)
        xmlXPathFreeContext(ctx);
    if (doc)
        xmlFreeDoc(doc);

    return 0;
}

/**
   Load all the resource rules we can find from our resource root
   directory.

   @param rules		Rule list to create/add to
   @return		0 on success, -1 on failure.  Sucess does not
   			imply any rules have been found; only that no
			errors were encountered.
  */
int
load_resource_rules(const char *rpath, resource_rule_t ** rules)
{
    DIR *dir;
    struct dirent *de;
    char *fn, *dot;
    char path[2048];
    struct stat st_buf;

    dir = opendir(rpath);
    if (!dir)
        return -1;

    xmlInitParser();
    while ((de = readdir(dir))) {

        fn = basename(de->d_name);
        if (!fn)
            continue;

        /* Ignore files with common backup extension */
        if ((fn != NULL) && (strlen(fn) > 0) && (fn[strlen(fn) - 1] == '~'))
            continue;

        /* Ignore hidden files */
        if (*fn == '.')
            continue;

        dot = strrchr(fn, '.');
        if (dot) {
            /* Ignore RPM installed save files, patches,
               diffs, etc. */
            if (!strncasecmp(dot, ".rpm", 4)) {
                fprintf(stderr, "Warning: "
                        "Ignoring %s/%s: Bad extension %s\n", rpath, de->d_name, dot);
                continue;
            }
        }

        snprintf(path, sizeof(path), "%s/%s", rpath, de->d_name);

        if (stat(path, &st_buf) < 0)
            continue;

        if (S_ISDIR(st_buf.st_mode))
            continue;

        if (st_buf.st_mode & (S_IXUSR | S_IXOTH | S_IXGRP)) {
            //printf("Loading resource rule from %s\n", path);
            load_resource_rulefile(path, rules);
        }
    }

    closedir(dir);

    return 0;
}

/**
   Find a resource rule given its type.

   @param rulelist	Rule list to search
   @param type		Rule type identifier
   @return		Resource rule or NULL if not found.
 */
resource_rule_t *
find_rule_by_type(resource_rule_t ** rulelist, char *type)
{
    resource_rule_t *curr = NULL;

    list_do(rulelist, curr) {
        if (!strcmp(curr->rr_type, type))
            return curr;
    }
    while (!list_done(rulelist, curr)) ;

    return NULL;
}
