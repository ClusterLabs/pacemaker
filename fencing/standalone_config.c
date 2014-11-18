/* 
 * Copyright (C) 2012
 * David Vossel  <dvossel@redhat.com>
 *
 * This program is crm_free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>
#include <crm/common/xml.h>
#include <crm/msg_xml.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <internal.h>
#include <standalone_config.h>

struct device {
    char *name;
    char *agent;
    char *hostlist;
    char *hostmap;

    struct {
        char *key;
        char *val;
    } key_vals[STANDALONE_CFG_MAX_KEYVALS];
    int key_vals_count;

    struct device *next;
};

struct topology {
    char *node_name;
    struct {
        char *device_name;
        unsigned int level;
    } priority_levels[STANDALONE_CFG_MAX_KEYVALS];
    int priority_levels_count;

    struct topology *next;
};

static struct device *dev_list;
static struct topology *topo_list;

static struct device *
find_device(const char *name)
{
    struct device *dev = NULL;

    for (dev = dev_list; dev != NULL; dev = dev->next) {
        if (!strcasecmp(dev->name, name)) {
            break;
        }
    }

    return dev;
}

static struct topology *
find_topology(const char *name)
{
    struct topology *topo = NULL;

    for (topo = topo_list; topo != NULL; topo = topo->next) {
        if (!strcasecmp(topo->node_name, name)) {
            break;
        }
    }

    return topo;
}

static void
add_device(struct device *dev)
{
    dev->next = dev_list;
    dev_list = dev;
}

static void
add_topology(struct topology *topo)
{
    topo->next = topo_list;
    topo_list = topo;
}

int
standalone_cfg_add_device(const char *device, const char *agent)
{
    struct device *dev = NULL;

    if (!device || !agent) {
        return -1;
    }

    /* just ignore duplicates */
    if (find_device(device)) {
        return 0;
    }
    dev = calloc(1, sizeof(struct device));

    dev->name = strdup(device);
    dev->agent = strdup(agent);
    add_device(dev);

    return 0;
}

int
standalone_cfg_add_device_options(const char *device, const char *key, const char *value)
{
    struct device *dev;

    if (!device || !key || !value) {
        return -1;
    } else if (!(dev = find_device(device))) {
        crm_err("Standalone config error, could not find device %s to add key value %s=%s to",
                device, key, value);
        return -1;
    } else if (dev->key_vals_count >= STANDALONE_CFG_MAX_KEYVALS) {
        return -1;
    }

    dev->key_vals[dev->key_vals_count].key = strdup(key);
    dev->key_vals[dev->key_vals_count].val = strdup(value);
    dev->key_vals_count++;

    return 0;
}

int
standalone_cfg_add_node(const char *node, const char *device, const char *ports)
{
    struct device *dev;
    char **ptr;
    char *tmp;
    size_t len = strlen(":;") + 1;
    size_t offset = 0;

    /* note that ports may be NULL, it is not a required argument */
    if (!node || !device) {
        return -1;
    } else if (!(dev = find_device(device))) {
        crm_err("Standalone config error, could not find device %s to add mode %s to",
                device, node);
        return -1;
    }

    ptr = &dev->hostlist;

    len += strlen(node);
    if (ports) {
        ptr = &dev->hostmap;
        len += strlen(ports);
    }

    tmp = *ptr;

    if (tmp) {
        offset = strlen(tmp);
        tmp = realloc_safe(tmp, len + offset + 1);
    } else {
        tmp = malloc(len);
    }

    *ptr = tmp;
    tmp += offset;

    if (ports) {
        sprintf(tmp, "%s:%s;", node, ports);
    } else {
        sprintf(tmp, "%s ", node);
    }

    return 0;
}

int
standalone_cfg_add_node_priority(const char *node, const char *device, unsigned int level)
{
    struct topology *topo = NULL;
    int new = 0;

    if (!node || !device) {
        return -1;
    }

    if (!(topo = find_topology(node))) {
        new = 1;
        topo = calloc(1, sizeof(struct topology));
        topo->node_name = strdup(node);
    } else if (topo->priority_levels_count >= STANDALONE_CFG_MAX_KEYVALS) {
        return -1;
    }

    topo->priority_levels[topo->priority_levels_count].device_name = strdup(device);
    topo->priority_levels[topo->priority_levels_count].level = level;
    topo->priority_levels_count++;

    if (new) {
        add_topology(topo);
    }

    return 0;
}

static int
destroy_topology(void)
{
    struct topology *topo = NULL;
    int i;

    while (topo_list) {
        topo = topo_list;

        free(topo->node_name);
        for (i = 0; i < topo->priority_levels_count; i++) {
            free(topo->priority_levels[i].device_name);
        }

        topo_list = topo->next;
        free(topo);
    }
    return 0;
}

static int
destroy_devices(void)
{
    struct device *dev = NULL;
    int i;

    while (dev_list) {
        dev = dev_list;

        free(dev->name);
        free(dev->agent);
        free(dev->hostlist);
        free(dev->hostmap);
        for (i = 0; i < dev->key_vals_count; i++) {
            free(dev->key_vals[i].key);
            free(dev->key_vals[i].val);
        }
        dev_list = dev->next;
        free(dev);
    }

    return 0;
}

static int
cfg_register_topology(struct topology *topo)
{
    stonith_key_value_t *devices = NULL;
    xmlNode *data;
    char *dump;
    int i;
    int res = 0;

    for (i = 0; i < topo->priority_levels_count; i++) {
        devices = stonith_key_value_add(devices, NULL, topo->priority_levels[i].device_name);

        data = create_level_registration_xml(topo->node_name,
                                             topo->priority_levels[i].level, devices);

        dump = dump_xml_formatted(data);
        crm_info("Standalone config level being added:\n%s", dump);

        res |= stonith_level_register(data, NULL);
        free(dump);
        free_xml(data);
        stonith_key_value_freeall(devices, 1, 1);
    }

    return res;
}

static int
cfg_register_device(struct device *dev)
{
    stonith_key_value_t *params = NULL;
    xmlNode *data;
    char *dump;
    int i;
    int res;

    /* create the parameter list */
    if (dev->hostlist) {
        params = stonith_key_value_add(params, STONITH_ATTR_HOSTLIST, dev->hostlist);
    }
    if (dev->hostmap) {
        params = stonith_key_value_add(params, STONITH_ATTR_HOSTMAP, dev->hostmap);
    }
    for (i = 0; i < dev->key_vals_count; i++) {
        params stonith_key_value_add(params, dev->key_vals[i].key, dev->key_vals[i].val);
    }

    /* generate xml */
    data = create_device_registration_xml(dev->name, __FUNCTION__, dev->agent, params);

    dump = dump_xml_formatted(data);
    crm_info("Standalone device being added:\n%s", dump);

    res = stonith_device_register(data, NULL);

    free(dump);
    free_xml(data);
    stonith_key_value_freeall(params, 1, 1);
    return res;
}

int
standalone_cfg_commit(void)
{
    struct device *dev = NULL;
    struct topology *topo = NULL;

    for (dev = dev_list; dev != NULL; dev = dev->next) {
        cfg_register_device(dev);
    }

    for (topo = topo_list; topo != NULL; topo = topo->next) {
        cfg_register_topology(topo);
    }

    destroy_devices();
    destroy_topology();
    return 0;
}
