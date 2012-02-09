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


#include <stdio.h>
#include <standalone_config.h>

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <crm/common/xml.h>
#include <crm/msg_xml.h>
#include <crm/stonith-ng.h>
#include <crm/stonith-ng-internal.h>
#include <internal.h>


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

static struct device *__device_list;
static struct topology *__topology_list;

static struct device *
find_device(const char *name)
{
	struct device *dev = NULL;

	for (dev = __device_list; dev != NULL; dev = dev->next) {
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

	for (topo = __topology_list; topo != NULL; topo = topo->next) {
		if (!strcasecmp(topo->node_name, name)) {
			break;
		}
	}

	return topo;
}

static void
add_device(struct device *dev)
{
	dev->next = __device_list;
	__device_list = dev;
}

static void
add_topology(struct topology *topo)
{
	topo->next = __topology_list;
	__topology_list = topo;
}

int
standalone_cfg_add_device(const char *device, const char *agent)
{
	struct device *dev;

	/* just ignore duplicates */
	if (find_device(device)) {
		return 0;
	}
	crm_malloc0(dev, sizeof(*dev));

	dev->name = strdup(device);
	dev->agent = strdup(agent);
	add_device(dev);

	return 0;
}

int
standalone_cfg_add_device_options(const char *device, const char *key, const char *value)
{
	struct device *dev;

	if (!(dev = find_device(device))) {
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

	if (!(dev = find_device(device))) {
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
		crm_realloc(tmp, len + offset + 1);
		*ptr = tmp;
	} else {
		crm_malloc(tmp, len);
		*ptr = tmp;
	}

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
	struct topology *topo;
	int new = 0;

	if (!(topo = find_topology(node))) {
		new = 1;
		crm_malloc0(topo, sizeof(*topo));
		topo->node_name = strdup(node);
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

	while (__topology_list) {
		topo = __topology_list;

		crm_free(topo->node_name);
		for (i = 0; i < topo->priority_levels_count; i++) {
			crm_free(topo->priority_levels[i].device_name);
		}

		__topology_list = topo->next;
		crm_free(topo);
	}
	return 0;
}

static int
destroy_devices(void)
{
	struct device *dev = NULL;
	int i;

	while (__device_list) {
		dev = __device_list;

		crm_free(dev->name);
		crm_free(dev->agent);
		crm_free(dev->hostlist);
		crm_free(dev->hostmap);
		for (i = 0; i < dev->key_vals_count; i++) {
			crm_free(dev->key_vals[i].key);
			crm_free(dev->key_vals[i].val);
		}
		__device_list = dev->next;
		crm_free(dev);
	}

	return 0;
}

static int
__standalone_cfg_register_device(struct device *dev)
{
	int i;
	int res;
	xmlNode *data = create_xml_node(NULL, F_STONITH_DEVICE);
	xmlNode *args = create_xml_node(data, XML_TAG_ATTRS);

	crm_xml_add(data, XML_ATTR_ID, dev->name);
	crm_xml_add(data, "origin", __FUNCTION__);
	crm_xml_add(data, "agent", dev->agent);
	crm_xml_add(data, "namespace", "stonith-ng");

	if (dev->hostlist) {
		crm_xml_add(args, "pcmk_host_list", dev->hostlist);
	}

	if (dev->hostmap) {
		crm_xml_add(args, "pcmk_host_map", dev->hostmap);
	}

	for (i = 0; i < dev->key_vals_count; i++) {
		crm_xml_add(args, dev->key_vals[i].key, dev->key_vals[i].val);
	}

	res = stonith_device_register(data);
	free_xml(data);
	return res;
}

int
standalone_cfg_commit(void)
{
	struct device *dev = NULL;
	struct topology *topo = NULL;
	int i;

	/* TODO - for now just printing out, but build xml once intergrated with stonith. */
	printf("commit!\n");
	printf("--- Devices\n");

	for (dev = __device_list; dev != NULL; dev = dev->next) {
		printf("	name: %s\n", dev->name);
		printf("	agent: %s\n", dev->agent);
		printf("	hostlist: %s\n", dev->hostlist);
		printf("	hostmap: %s\n", dev->hostmap);
		for (i = 0; i < dev->key_vals_count; i++) {
			printf("		%s=%s\n", dev->key_vals[i].key, dev->key_vals[i].val);
		}
		printf("\n");
		__standalone_cfg_register_device(dev);
	}

	printf("--- Topology\n");

	for (topo = __topology_list; topo != NULL; topo = topo->next) {
		printf("	node: %s\n", topo->node_name);
		for (i = 0; i < topo->priority_levels_count; i++) {
			printf("		%d=%s\n",
				topo->priority_levels[i].level,
				topo->priority_levels[i].device_name);
		}
		printf("\n");
	}

	destroy_devices();
	destroy_topology();
	return 0;
}
