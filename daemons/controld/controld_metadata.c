/*
 * Copyright 2017-2025 the Pacemaker project contributors
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

static struct ra_param_s *
ra_param_from_xml(xmlNode *param_xml)
{
    const char *param_name = pcmk__xe_get(param_xml, PCMK_XA_NAME);
    struct ra_param_s *p;

    p = pcmk__assert_alloc(1, sizeof(struct ra_param_s));

    p->rap_name = pcmk__str_copy(param_name);

    if (pcmk__xe_attr_is_true(param_xml, PCMK_XA_RELOADABLE)) {
        controld_set_ra_param_flags(p, ra_param_reloadable);
    }

    if (pcmk__xe_attr_is_true(param_xml, PCMK_XA_UNIQUE)) {
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

    metadata = pcmk__xml_parse(metadata_str);
    if (!metadata) {
        reason = "Metadata is not valid XML";
        goto err;
    }

    md = pcmk__assert_alloc(1, sizeof(struct ra_metadata_s));

    if (strcmp(rsc->standard, PCMK_RESOURCE_CLASS_OCF) == 0) {
        xmlChar *content = NULL;
        xmlNode *version_element = pcmk__xe_first_child(metadata,
                                                        PCMK_XE_VERSION, NULL,
                                                        NULL);

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
    match = pcmk__xe_first_child(metadata, PCMK_XE_ACTIONS, NULL, NULL);
    for (match = pcmk__xe_first_child(match, PCMK_XE_ACTION, NULL, NULL);
         match != NULL; match = pcmk__xe_next(match, PCMK_XE_ACTION)) {

        const char *action_name = pcmk__xe_get(match, PCMK_XA_NAME);

        if (pcmk__str_eq(action_name, PCMK_ACTION_RELOAD_AGENT,
                         pcmk__str_none)) {
            if (ocf1_1) {
                controld_set_ra_flags(md, key, ra_supports_reload_agent);
            } else {
                crm_notice("reload-agent action will not be used with %s "
                           "because it does not support OCF 1.1 or later", key);
            }

        } else if (!ocf1_1 && pcmk__str_eq(action_name, PCMK_ACTION_RELOAD,
                                           pcmk__str_casei)) {
            controld_set_ra_flags(md, key, ra_supports_legacy_reload);
        }
    }

    // Build a parameter list
    match = pcmk__xe_first_child(metadata, PCMK_XE_PARAMETERS, NULL, NULL);
    for (match = pcmk__xe_first_child(match, PCMK_XE_PARAMETER, NULL, NULL);
         match != NULL; match = pcmk__xe_next(match, PCMK_XE_PARAMETER)) {

        const char *param_name = pcmk__xe_get(match, PCMK_XA_NAME);

        if (param_name == NULL) {
            crm_warn("Metadata for %s:%s:%s has parameter without a "
                     PCMK_XA_NAME, rsc->standard, rsc->provider, rsc->type);
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
    pcmk__xml_free(metadata);
    return md;

err:
    crm_warn("Unable to update metadata for %s (%s%s%s:%s): %s",
             rsc->id, rsc->standard, ((rsc->provider == NULL)? "" : ":"),
             pcmk__s(rsc->provider, ""), rsc->type, reason);
    free(key);
    pcmk__xml_free(metadata);
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
            crm_debug("Retrieved metadata for %s (%s%s%s:%s) from cache",
                      rsc->id, rsc->standard,
                      ((rsc->provider == NULL)? "" : ":"),
                      ((rsc->provider == NULL)? "" : rsc->provider),
                      rsc->type);
            return metadata;
        }
    }

    if (!pcmk_is_set(source, controld_metadata_from_agent)) {
        return NULL;
    }

    /* For most actions, metadata was cached asynchronously before action
     * execution (via metadata_complete()).
     *
     * However if that failed, and for other actions, retrieve the metadata now
     * via a local, synchronous, direct execution of the agent.
     *
     * This has multiple issues, which is why this is just a fallback: the
     * executor should execute agents, not the controller; metadata for
     * Pacemaker Remote nodes should be collected on those nodes, not locally;
     * the metadata call shouldn't eat into the timeout of the real action being
     * performed; and the synchronous call blocks the controller (which also
     * means that if the metadata action tries to contact the controller,
     * everything will hang until the timeout).
     */
    crm_debug("Retrieving metadata for %s (%s%s%s:%s) synchronously",
              rsc->id, rsc->standard,
              ((rsc->provider == NULL)? "" : ":"),
              ((rsc->provider == NULL)? "" : rsc->provider),
              rsc->type);
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
