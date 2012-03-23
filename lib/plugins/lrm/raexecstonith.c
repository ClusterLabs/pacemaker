/* 
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * File: raexecocf.c
 * Author: Sun Jiang Dong <sunjd@cn.ibm.com>
 * Copyright (c) 2004 International Business Machines
 *
 * This code implements the Resource Agent Plugin Module for LSB style.
 * It's a part of Local Resource Manager. Currently it's used by lrmd only.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <glib.h>

#if HAVE_HB_CONFIG_H
#  include <heartbeat/hb_config.h>
#endif

#if HAVE_GLUE_CONFIG_H
#  include <glue_config.h>
#endif

#include <clplumbing/uids.h>
#include <pils/plugin.h>
#include <dirent.h>
#include <libgen.h>             /* Add it for compiling on OSX */
#include <libxml/entities.h>

#include <lrm/raexec.h>
#include <crm/stonith-ng.h>
#include <stonith/stonith.h>

#define PIL_PLUGINTYPE		RA_EXEC_TYPE
#define PIL_PLUGINTYPE_S	"RAExec"
#define PIL_PLUGINLICENSE	LICENSE_PUBDOM
#define PIL_PLUGINLICENSEURL	URL_PUBDOM

#define PIL_PLUGIN		stonith
#define PIL_PLUGIN_S		"stonith"

static PIL_rc close_stonithRA(PILInterface *, void *ud_interface);

/* The begin of exported function list */
static int execra(const char *rsc_id,
                  const char *rsc_type,
                  const char *provider,
                  const char *op_type, const int timeout, GHashTable * params);
static uniform_ret_execra_t map_ra_retvalue(int ret_execra, const char *op_type,
                                            const char *std_output);
static int get_resource_list(GList ** rsc_info);
static char *get_resource_meta(const char *rsc_type, const char *provider);
static int get_provider_list(const char *op_type, GList ** providers);

/* The end of exported function list */

/* Rource agent execution plugin operations */
static struct RAExecOps raops = { execra,
    map_ra_retvalue,
    get_resource_list,
    get_provider_list,
    get_resource_meta
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug);

static const PILPluginImports *PluginImports;
static PILPlugin *OurPlugin;
static PILInterface *OurInterface;
static void *OurImports;
static void *interfprivate;

/*
 * Our plugin initialization and registration function
 * It gets called when the plugin gets loaded.
 */
PIL_rc PIL_PLUGIN_INIT(PILPlugin * us, const PILPluginImports * imports);

PIL_rc
PIL_PLUGIN_INIT(PILPlugin * us, const PILPluginImports * imports)
{
    /* Force the compiler to do a little type checking */
    (void)(PILPluginInitFun) PIL_PLUGIN_INIT;

    PluginImports = imports;
    OurPlugin = us;

    /* Register ourself as a plugin */
    imports->register_plugin(us, &OurPIExports);

    /*  Register our interfaces */
    return imports->register_interface(us, PIL_PLUGINTYPE_S, PIL_PLUGIN_S,
                                       &raops, close_stonithRA, &OurInterface, &OurImports,
                                       interfprivate);
}

static PIL_rc
close_stonithRA(PILInterface * pif, void *ud_interface)
{
    return PIL_OK;
}

static int
execra(const char *rsc_id, const char *rsc_type, const char *provider,
       const char *op_type, const int timeout, GHashTable * params)
{
    int rc = 0;
    static gboolean log_init = FALSE;

    stonith_key_value_t *device_params = NULL;
    stonith_t *stonith_api = NULL;

    provider = get_stonith_provider(rsc_type, provider);

    if (log_init == FALSE) {
        log_init = TRUE;
        crm_log_init("lrm-stonith", LOG_INFO, FALSE, FALSE, 0, NULL);
    }

    if (0 == STRNCMP_CONST(op_type, "meta-data")) {
        char *meta = get_resource_meta(rsc_type, provider);

        printf("%s", meta);
        free(meta);
        exit(0);
    }

    stonith_api = stonith_api_new();
    rc = stonith_api->cmds->connect(stonith_api, "lrmd", NULL);
    if (provider == NULL) {
        crm_err("No such legacy stonith device: %s", rsc_type);
        rc = st_err_unknown_device;

    } else if (0 == STRNCMP_CONST(op_type, "monitor")) {
        rc = stonith_api->cmds->call(stonith_api, st_opt_sync_call, rsc_id, op_type, NULL, timeout);

    } else if (0 == STRNCMP_CONST(op_type, "start")) {
        char *key = NULL;
        char *value = NULL;
        GHashTableIter iter;
        const char *agent = rsc_type;

        if (0 == STRNCMP_CONST(provider, "heartbeat")) {
            agent = "fence_legacy";
            g_hash_table_replace(params, strdup("plugin"), strdup(rsc_type));
        }

        g_hash_table_iter_init(&iter, params);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            device_params = stonith_key_value_add(device_params, key, value);
        }

        rc = stonith_api->cmds->register_device(stonith_api, st_opt_sync_call, rsc_id, provider,
                                                agent, device_params);
        if (rc == 0) {
            rc = stonith_api->cmds->call(stonith_api, st_opt_sync_call, rsc_id, "monitor", NULL,
                                         timeout);
        }

    } else if (0 == STRNCMP_CONST(op_type, "stop")) {
        rc = stonith_api->cmds->remove_device(stonith_api, st_opt_sync_call, rsc_id);
    }

    crm_debug("%s_%s returned %d", rsc_id, op_type, rc);
    stonith_api->cmds->disconnect(stonith_api);
    stonith_api_delete(stonith_api);

    exit(map_ra_retvalue(rc, op_type, NULL));
}

static uniform_ret_execra_t
map_ra_retvalue(int rc, const char *op_type, const char *std_output)
{
    if (rc == st_err_unknown_device) {
        if (0 == STRNCMP_CONST(op_type, "stop")) {
            rc = 0;

        } else if (0 == STRNCMP_CONST(op_type, "start")) {
            rc = 5;

        } else {
            rc = 7;
        }

    } else if (rc < 0 || rc > EXECRA_STATUS_UNKNOWN) {
        crm_warn("Mapped the invalid return code %d.", rc);
        rc = EXECRA_UNKNOWN_ERROR;
    }
    return rc;
}

static int
get_resource_list(GList ** rsc_info)
{
    stonith_t *stonith_api = NULL;
    stonith_key_value_t *devices = NULL;
    stonith_key_value_t *dIter = NULL;

    if (rsc_info == NULL) {
        crm_err("Parameter error: get_resource_list");
        return -2;
    }

    stonith_api = stonith_api_new();
    stonith_api->cmds->list(stonith_api, st_opt_sync_call, NULL, &devices, 0);
    stonith_api_delete(stonith_api);

    for (dIter = devices; dIter; dIter = dIter->next) {
        *rsc_info = g_list_append(*rsc_info, dIter->value);
    }

    stonith_key_value_freeall(devices, 1, 0);
    return 0;
}

static int
get_provider_list(const char *op_type, GList ** providers)
{
    if (providers == NULL) {
        return -1;
    }

    if (op_type == NULL) {
        *providers = g_list_append(*providers, g_strdup("redhat"));
        *providers = g_list_append(*providers, g_strdup("heartbeat"));
        return 2;

    } else {
        const char *provider = get_stonith_provider(op_type, NULL);

        if (provider) {
            *providers = g_list_append(*providers, g_strdup(provider));
            return 1;
        }
    }

    return 0;
}

static char *
get_resource_meta(const char *rsc_type, const char *provider)
{
    char *buffer = NULL;
    stonith_t *stonith_api = stonith_api_new();

    stonith_api->cmds->metadata(stonith_api, st_opt_sync_call, rsc_type, provider, &buffer, 0);
    stonith_api_delete(stonith_api);
    crm_debug("stonithRA plugin: got metadata: %s", buffer);

    /* TODO: Convert to XML and ensure our standard actions exist */
    return buffer;
}
