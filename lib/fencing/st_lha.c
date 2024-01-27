/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include <dlfcn.h>

#include <crm/crm.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>

#include <stonith/stonith.h>

#include "fencing_private.h"

#define LHA_STONITH_LIBRARY "libstonith.so.1"

static void *lha_agents_lib = NULL;

// @TODO Use XML string constants and maybe a real XML object
static const char META_TEMPLATE[] =
    "<?xml " PCMK_XA_VERSION "=\"1.0\"?>\n"
    "<" PCMK_XE_RESOURCE_AGENT " " PCMK_XA_NAME "=\"%s\">\n"
    "  <" PCMK_XE_VERSION ">1.1</" PCMK_XE_VERSION ">\n"
    "  <" PCMK_XE_LONGDESC " " PCMK_XA_LANG "=\"" PCMK__VALUE_EN "\">\n"
        "%s\n"
    "  </" PCMK_XE_LONGDESC ">\n"
    "  <" PCMK_XE_SHORTDESC " " PCMK_XA_LANG "=\"" PCMK__VALUE_EN "\">"
        "%s"
      "</" PCMK_XE_SHORTDESC ">\n"
    "%s\n"
    "  <" PCMK_XE_ACTIONS ">\n"
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "=\"" PCMK_ACTION_START "\""
                           " " PCMK_META_TIMEOUT "=\"%s\" />\n"
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "=\"" PCMK_ACTION_STOP "\""
                           " " PCMK_META_TIMEOUT "=\"15s\" />\n"
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "=\"" PCMK_ACTION_STATUS "\""
                           " " PCMK_META_TIMEOUT "=\"%s\" />\n"
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "=\"" PCMK_ACTION_MONITOR "\""
                           " " PCMK_META_TIMEOUT "=\"%s\""
                           " " PCMK_META_INTERVAL "=\"3600s\" />\n"
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "=\"" PCMK_ACTION_META_DATA "\""
                           " " PCMK_META_TIMEOUT "=\"15s\" />\n"
    "  </" PCMK_XE_ACTIONS ">\n"
    "  <special tag=\"heartbeat\">\n"
    "    <" PCMK_XE_VERSION ">2.0</" PCMK_XE_VERSION ">\n"
    "  </special>\n"
    "</" PCMK_XE_RESOURCE_AGENT ">\n";

static void *
find_library_function(void **handle, const char *lib, const char *fn)
{
    void *a_function;

    if (*handle == NULL) {
        *handle = dlopen(lib, RTLD_LAZY);
        if ((*handle) == NULL) {
            crm_err("Could not open %s: %s", lib, dlerror());
            return NULL;
        }
    }

    a_function = dlsym(*handle, fn);
    if (a_function == NULL) {
        crm_err("Could not find %s in %s: %s", fn, lib, dlerror());
    }

    return a_function;
}

/*!
 * \internal
 * \brief Check whether a given fence agent is an LHA agent
 *
 * \param[in] agent        Fence agent type
 *
 * \return true if \p agent is an LHA agent, otherwise false
 */
bool
stonith__agent_is_lha(const char *agent)
{
    Stonith *stonith_obj = NULL;

    static bool need_init = true;
    static Stonith *(*st_new_fn) (const char *) = NULL;
    static void (*st_del_fn) (Stonith *) = NULL;

    if (need_init) {
        need_init = false;
        st_new_fn = find_library_function(&lha_agents_lib, LHA_STONITH_LIBRARY,
                                          "stonith_new");
        st_del_fn = find_library_function(&lha_agents_lib, LHA_STONITH_LIBRARY,
                                          "stonith_delete");
    }

    if (lha_agents_lib && st_new_fn && st_del_fn) {
        stonith_obj = (*st_new_fn) (agent);
        if (stonith_obj) {
            (*st_del_fn) (stonith_obj);
            return true;
        }
    }
    return false;
}

int
stonith__list_lha_agents(stonith_key_value_t **devices)
{
    static gboolean need_init = TRUE;

    int count = 0;
    char **entry = NULL;
    char **type_list = NULL;
    static char **(*type_list_fn) (void) = NULL;
    static void (*type_free_fn) (char **) = NULL;

    if (need_init) {
        need_init = FALSE;
        type_list_fn = find_library_function(&lha_agents_lib,
                                             LHA_STONITH_LIBRARY,
                                             "stonith_types");
        type_free_fn = find_library_function(&lha_agents_lib,
                                             LHA_STONITH_LIBRARY,
                                             "stonith_free_hostlist");
    }

    if (type_list_fn) {
        type_list = (*type_list_fn) ();
    }

    for (entry = type_list; entry != NULL && *entry; ++entry) {
        crm_trace("Added: %s", *entry);
        *devices = stonith_key_value_add(*devices, NULL, *entry);
        count++;
    }
    if (type_list && type_free_fn) {
        (*type_free_fn) (type_list);
    }
    return count;
}

static void
stonith_plugin(int priority, const char *fmt, ...) G_GNUC_PRINTF(2, 3);

static void
stonith_plugin(int priority, const char *format, ...)
{
    int err = errno;

    va_list ap;
    int len = 0;
    char *string = NULL;

    va_start(ap, format);

    len = vasprintf (&string, format, ap);
    va_end(ap);
    CRM_ASSERT(len > 0);

    do_crm_log_alias(priority, __FILE__, __func__, __LINE__, "%s", string);

    free(string);
    errno = err;
}

int
stonith__lha_metadata(const char *agent, int timeout, char **output)
{
    int rc = 0;
    char *buffer = NULL;
    static const char *no_parameter_info = "<!-- no value -->";

    Stonith *stonith_obj = NULL;

    static gboolean need_init = TRUE;
    static Stonith *(*st_new_fn) (const char *) = NULL;
    static const char *(*st_info_fn) (Stonith *, int) = NULL;
    static void (*st_del_fn) (Stonith *) = NULL;
    static void (*st_log_fn) (Stonith *, PILLogFun) = NULL;

    if (need_init) {
        need_init = FALSE;
        st_new_fn = find_library_function(&lha_agents_lib, LHA_STONITH_LIBRARY,
                                          "stonith_new");
        st_del_fn = find_library_function(&lha_agents_lib, LHA_STONITH_LIBRARY,
                                          "stonith_delete");
        st_log_fn = find_library_function(&lha_agents_lib, LHA_STONITH_LIBRARY,
                                          "stonith_set_log");
        st_info_fn = find_library_function(&lha_agents_lib, LHA_STONITH_LIBRARY,
                                           "stonith_get_info");
    }

    if (lha_agents_lib && st_new_fn && st_del_fn && st_info_fn && st_log_fn) {
        char *xml_meta_longdesc = NULL;
        char *xml_meta_shortdesc = NULL;

        char *meta_param = NULL;
        char *meta_longdesc = NULL;
        char *meta_shortdesc = NULL;
        const char *timeout_str = NULL;

        stonith_obj = (*st_new_fn) (agent);
        if (stonith_obj) {
            (*st_log_fn) (stonith_obj, (PILLogFun) & stonith_plugin);
            pcmk__str_update(&meta_longdesc,
                             (*st_info_fn) (stonith_obj, ST_DEVICEDESCR));
            if (meta_longdesc == NULL) {
                crm_warn("no long description in %s's metadata.", agent);
                meta_longdesc = strdup(no_parameter_info);
            }

            pcmk__str_update(&meta_shortdesc,
                             (*st_info_fn) (stonith_obj, ST_DEVICEID));
            if (meta_shortdesc == NULL) {
                crm_warn("no short description in %s's metadata.", agent);
                meta_shortdesc = strdup(no_parameter_info);
            }

            pcmk__str_update(&meta_param,
                             (*st_info_fn) (stonith_obj, ST_CONF_XML));
            if (meta_param == NULL) {
                crm_warn("no list of parameters in %s's metadata.", agent);
                meta_param = strdup(no_parameter_info);
            }
            (*st_del_fn) (stonith_obj);
        } else {
            errno = EINVAL;
            crm_perror(LOG_ERR, "Agent %s not found", agent);
            return -EINVAL;
        }

        xml_meta_longdesc =
            (char *)xmlEncodeEntitiesReentrant(NULL, (const unsigned char *)meta_longdesc);
        xml_meta_shortdesc =
            (char *)xmlEncodeEntitiesReentrant(NULL, (const unsigned char *)meta_shortdesc);

        /* @TODO This needs a string that's parsable by crm_get_msec(). In
         * general, pcmk__readable_interval() doesn't provide that. It works
         * here because PCMK_DEFAULT_ACTION_TIMEOUT_MS is 20000 -> "20s".
         */
        timeout_str = pcmk__readable_interval(PCMK_DEFAULT_ACTION_TIMEOUT_MS);
        buffer = crm_strdup_printf(META_TEMPLATE, agent, xml_meta_longdesc,
                                   xml_meta_shortdesc, meta_param,
                                   timeout_str, timeout_str, timeout_str);

        xmlFree(xml_meta_longdesc);
        xmlFree(xml_meta_shortdesc);

        free(meta_shortdesc);
        free(meta_longdesc);
        free(meta_param);
    }
    if (output) {
        *output = buffer;
    } else {
        free(buffer);
    }
    return rc;
}

/* Implement a dummy function that uses -lpils so that linkers don't drop the
 * reference.
 */

#include <pils/plugin.h>

const char *i_hate_pils(int rc);

const char *
i_hate_pils(int rc)
{
    return PIL_strerror(rc);
}

int
stonith__lha_validate(stonith_t *st, int call_options, const char *target,
                      const char *agent, GHashTable *params, int timeout,
                      char **output, char **error_output)
{
    errno = EOPNOTSUPP;
    crm_perror(LOG_ERR, "Cannot validate Linux-HA fence agents");
    return -EOPNOTSUPP;
}
