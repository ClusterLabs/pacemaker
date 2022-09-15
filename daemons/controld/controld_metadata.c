/*
 * Copyright 2017-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <glib.h>
#include <regex.h>

#include <crm/crm.h>
#include <crm/lrmd.h>

#include <pacemaker-controld.h>

#if ENABLE_VERSIONED_ATTRS
static regex_t *version_format_regex = NULL;
#endif

static void
ra_param_free(void *param)
{
    if (param) {
        struct ra_param_s *p = (struct ra_param_s *) param;

        if (p->rap_name) {
            free(p->rap_name);
        }
        free(param);
    }
}

static void
metadata_free(void *metadata)
{
    if (metadata) {
        struct ra_metadata_s *md = (struct ra_metadata_s *) metadata;

        if (md->ra_version) {
            free(md->ra_version);
        }
        g_list_free_full(md->ra_params, ra_param_free);
        free(metadata);
    }
}

GHashTable *
metadata_cache_new(void)
{
    return pcmk__strkey_table(free, metadata_free);
}

void
metadata_cache_free(GHashTable *mdc)
{
    if (mdc) {
        crm_trace("Destroying metadata cache with %d members", g_hash_table_size(mdc));
        g_hash_table_destroy(mdc);
    }
}

void
metadata_cache_reset(GHashTable *mdc)
{
    if (mdc) {
        crm_trace("Resetting metadata cache with %d members",
                  g_hash_table_size(mdc));
        g_hash_table_remove_all(mdc);
    }
}

#if ENABLE_VERSIONED_ATTRS
static gboolean
valid_version_format(const char *version)
{
    if (version == NULL) {
        return FALSE;
    }

    if (version_format_regex == NULL) {
        /* The OCF standard allows free-form versioning, but for our purposes of
         * versioned resource and operation attributes, we constrain it to
         * dot-separated numbers. Agents are still free to use other schemes,
         * but we can't determine attributes based on them.
         */
        const char *regex_string = "^[[:digit:]]+([.][[:digit:]]+)*$";

        version_format_regex = calloc(1, sizeof(regex_t));
        regcomp(version_format_regex, regex_string, REG_EXTENDED | REG_NOSUB);

        /* If our regex doesn't compile, it's a bug on our side, so CRM_CHECK()
         * will give us a core dump to catch it. Pretend the version is OK
         * because we don't want our mistake to break versioned attributes
         * (which should only ever happen in a development branch anyway).
         */
        CRM_CHECK(version_format_regex != NULL, return TRUE);
    }

    return regexec(version_format_regex, version, 0, NULL, 0) == 0;
}
#endif

void
metadata_cache_fini(void)
{
#if ENABLE_VERSIONED_ATTRS
    if (version_format_regex) {
        regfree(version_format_regex);
        free(version_format_regex);
        version_format_regex = NULL;
    }
#endif
}

#if ENABLE_VERSIONED_ATTRS
static char *
ra_version_from_xml(xmlNode *metadata_xml, const lrmd_rsc_info_t *rsc)
{
    const char *version = crm_element_value(metadata_xml, XML_ATTR_VERSION);

    if (version == NULL) {
        crm_debug("Metadata for %s:%s:%s does not specify a version",
                  rsc->standard, rsc->provider, rsc->type);
        version = PCMK_DEFAULT_AGENT_VERSION;

    } else if (!valid_version_format(version)) {
        crm_notice("%s:%s:%s metadata version has unrecognized format",
                  rsc->standard, rsc->provider, rsc->type);
        version = PCMK_DEFAULT_AGENT_VERSION;

    } else {
        crm_debug("Metadata for %s:%s:%s has version %s",
                  rsc->standard, rsc->provider, rsc->type, version);
    }
    return strdup(version);
}
#endif

static struct ra_param_s *
ra_param_from_xml(xmlNode *param_xml)
{
    const char *param_name = crm_element_value(param_xml, "name");
    struct ra_param_s *p;

    p = calloc(1, sizeof(struct ra_param_s));
    if (p == NULL) {
        return NULL;
    }

    p->rap_name = strdup(param_name);
    if (p->rap_name == NULL) {
        free(p);
        return NULL;
    }

    if (pcmk__xe_attr_is_true(param_xml, "reloadable")) {
        controld_set_ra_param_flags(p, ra_param_reloadable);
    }

    if (pcmk__xe_attr_is_true(param_xml, "unique")) {
        controld_set_ra_param_flags(p, ra_param_unique);
    }

    if (pcmk__xe_attr_is_true(param_xml, "private")) {
        controld_set_ra_param_flags(p, ra_param_private);
    }
    return p;
}

static void
log_ra_ocf_version(const char *ra_key, const char *ra_ocf_version)
{
    if (pcmk__str_empty(ra_ocf_version)) {
        crm_warn("%s does not advertise OCF version supported", ra_key);

    } else if (compare_version(ra_ocf_version, "2") >= 0) {
        crm_warn("%s supports OCF version %s (this Pacemaker version supports "
                 PCMK_OCF_VERSION " and might not work properly with agent)",
                 ra_key, ra_ocf_version);

    } else if (compare_version(ra_ocf_version, PCMK_OCF_VERSION) > 0) {
        crm_info("%s supports OCF version %s (this Pacemaker version supports "
                 PCMK_OCF_VERSION " and might not use all agent features)",
                 ra_key, ra_ocf_version);

    } else {
        crm_debug("%s supports OCF version %s", ra_key, ra_ocf_version);
    }
}

struct ra_metadata_s *
controld_cache_metadata(GHashTable *mdc, const lrmd_rsc_info_t *rsc,
                        const char *metadata_str)
{
    char *key = NULL;
    const char *reason = NULL;
    xmlNode *metadata = NULL;
    xmlNode *match = NULL;
    struct ra_metadata_s *md = NULL;
    bool any_private_params = false;
    bool ocf1_1 = false;

    CRM_CHECK(mdc && rsc && metadata_str, return NULL);

    key = crm_generate_ra_key(rsc->standard, rsc->provider, rsc->type);
    if (!key) {
        reason = "Invalid resource agent standard or type";
        goto err;
    }

    metadata = string2xml(metadata_str);
    if (!metadata) {
        reason = "Metadata is not valid XML";
        goto err;
    }

    md = calloc(1, sizeof(struct ra_metadata_s));
    if (md == NULL) {
        reason = "Could not allocate memory";
        goto err;
    }

#if ENABLE_VERSIONED_ATTRS
    md->ra_version = ra_version_from_xml(metadata, rsc);
#endif

    if (strcmp(rsc->standard, PCMK_RESOURCE_CLASS_OCF) == 0) {
        xmlChar *content = NULL;
        xmlNode *version_element = first_named_child(metadata, "version");

        if (version_element != NULL) {
            content = xmlNodeGetContent(version_element);
        }
        log_ra_ocf_version(key, (const char *) content);
        if (content != NULL) {
            ocf1_1 = (compare_version((const char *) content, "1.1") >= 0);
            xmlFree(content);
        }
    }

    // Check supported actions
    match = first_named_child(metadata, "actions");
    for (match = first_named_child(match, "action"); match != NULL;
         match = crm_next_same_xml(match)) {

        const char *action_name = crm_element_value(match, "name");

        if (pcmk__str_eq(action_name, CRMD_ACTION_RELOAD_AGENT,
                         pcmk__str_none)) {
            if (ocf1_1) {
                controld_set_ra_flags(md, key, ra_supports_reload_agent);
            } else {
                crm_notice("reload-agent action will not be used with %s "
                           "because it does not support OCF 1.1 or later", key);
            }

        } else if (!ocf1_1 && pcmk__str_eq(action_name, CRMD_ACTION_RELOAD,
                                           pcmk__str_casei)) {
            controld_set_ra_flags(md, key, ra_supports_legacy_reload);
        }
    }

    // Build a parameter list
    match = first_named_child(metadata, "parameters");
    for (match = first_named_child(match, "parameter"); match != NULL;
         match = crm_next_same_xml(match)) {

        const char *param_name = crm_element_value(match, "name");

        if (param_name == NULL) {
            crm_warn("Metadata for %s:%s:%s has parameter without a name",
                     rsc->standard, rsc->provider, rsc->type);
        } else {
            struct ra_param_s *p = ra_param_from_xml(match);

            if (p == NULL) {
                reason = "Could not allocate memory";
                goto err;
            }
            if (pcmk_is_set(p->rap_flags, ra_param_private)) {
                any_private_params = true;
            }
            md->ra_params = g_list_prepend(md->ra_params, p);
        }
    }

    /* Newer resource agents support the "private" parameter attribute to
     * indicate sensitive parameters. For backward compatibility with older
     * agents, implicitly treat a few common names as private when the agent
     * doesn't specify any explicitly.
     */
    if (!any_private_params) {
        for (GList *iter = md->ra_params; iter != NULL; iter = iter->next) {
            struct ra_param_s *p = iter->data;

            if (pcmk__str_any_of(p->rap_name, "password", "passwd", "user",
                                 NULL)) {
                controld_set_ra_param_flags(p, ra_param_private);
            }
        }
    }

    g_hash_table_replace(mdc, key, md);
    free_xml(metadata);
    return md;

err:
    crm_warn("Unable to update metadata for %s (%s%s%s:%s): %s",
             rsc->id, rsc->standard, ((rsc->provider == NULL)? "" : ":"),
             pcmk__s(rsc->provider, ""), rsc->type, reason);
    free(key);
    free_xml(metadata);
    metadata_free(md);
    return NULL;
}

/*!
 * \internal
 * \brief Get meta-data for a resource
 *
 * \param[in,out] lrm_state  Use meta-data cache from this executor connection
 * \param[in]     rsc        Resource to get meta-data for
 * \param[in]     source     Allowed meta-data sources (bitmask of
 *                           enum controld_metadata_source_e values)
 *
 * \return Meta-data cache entry for given resource, or NULL if not available
 */
struct ra_metadata_s *
controld_get_rsc_metadata(lrm_state_t *lrm_state, const lrmd_rsc_info_t *rsc,
                          uint32_t source)
{
    struct ra_metadata_s *metadata = NULL;
    char *metadata_str = NULL;
    char *key = NULL;
    int rc = pcmk_ok;

    CRM_CHECK((lrm_state != NULL) && (rsc != NULL), return NULL);

    if (pcmk_is_set(source, controld_metadata_from_cache)) {
        key = crm_generate_ra_key(rsc->standard, rsc->provider, rsc->type);
        if (key != NULL) {
            metadata = g_hash_table_lookup(lrm_state->metadata_cache, key);
            free(key);
        }
        if (metadata != NULL) {
            return metadata;
        }
    }

    if (!pcmk_is_set(source, controld_metadata_from_agent)) {
        return NULL;
    }

    /* For now, we always collect resource agent meta-data via a local,
     * synchronous, direct execution of the agent. This has multiple issues:
     * the executor should execute agents, not the controller; meta-data for
     * Pacemaker Remote nodes should be collected on those nodes, not
     * locally; and the meta-data call shouldn't eat into the timeout of the
     * real action being performed.
     *
     * These issues are planned to be addressed by having the scheduler
     * schedule a meta-data cache check at the beginning of each transition.
     * Once that is working, this block will only be a fallback in case the
     * initial collection fails.
     */
    rc = lrm_state_get_metadata(lrm_state, rsc->standard, rsc->provider,
                                rsc->type, &metadata_str, 0);
    if (rc != pcmk_ok) {
        crm_warn("Failed to get metadata for %s (%s%s%s:%s): %s",
                 rsc->id, rsc->standard,
                 ((rsc->provider == NULL)? "" : ":"),
                 ((rsc->provider == NULL)? "" : rsc->provider),
                 rsc->type, pcmk_strerror(rc));
        return NULL;
    }

    metadata = controld_cache_metadata(lrm_state->metadata_cache, rsc,
                                       metadata_str);
    free(metadata_str);
    return metadata;
}
