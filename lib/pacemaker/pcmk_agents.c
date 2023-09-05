/*
 * Copyright 2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/lrmd_internal.h>
#include <pacemaker.h>
#include <pacemaker-internal.h>

int
pcmk__list_alternatives(pcmk__output_t *out, const char *agent_spec)
{
    int rc = pcmk_rc_ok;
    lrmd_t *lrmd_conn = NULL;
    lrmd_list_t *list = NULL;

    CRM_ASSERT(out != NULL && agent_spec != NULL);

    rc = lrmd__new(&lrmd_conn, NULL, NULL, 0);
    if (rc != pcmk_rc_ok) {
        goto error;
    }

    rc = lrmd_conn->cmds->list_ocf_providers(lrmd_conn, agent_spec, &list);

    if (rc > 0) {
        rc = out->message(out, "alternatives-list", list, agent_spec);
    } else {
        rc = pcmk_rc_error;
    }

error:
    if (rc != pcmk_rc_ok) {
       out->err(out, _("No %s found for %s"), "OCF providers", agent_spec);
       rc = ENXIO;
    }

    lrmd_api_delete(lrmd_conn);
    return rc;
}

// Documented in pacemaker.h
int
pcmk_list_alternatives(xmlNodePtr *xml, const char *agent_spec)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    lrmd__register_messages(out);

    rc = pcmk__list_alternatives(out, agent_spec);
    pcmk__xml_output_finish(out, xml);
    return rc;
}

/*!
 * \internal
 * \brief List all agents available for the named standard and/or provider
 *
 * \param[in,out] out           Output object
 * \param[in]     agent_spec    STD[:PROV]
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__list_agents(pcmk__output_t *out, char *agent_spec)
{
    int rc = pcmk_rc_ok;
    char *provider = NULL;
    lrmd_t *lrmd_conn = NULL;
    lrmd_list_t *list = NULL;

    CRM_ASSERT(out != NULL && agent_spec != NULL);

    rc = lrmd__new(&lrmd_conn, NULL, NULL, 0);
    if (rc != pcmk_rc_ok) {
        goto error;
    }

    provider = strchr(agent_spec, ':');

    if (provider) {
        *provider++ = 0;
    }

    rc = lrmd_conn->cmds->list_agents(lrmd_conn, &list, agent_spec, provider);

    if (rc > 0) {
        rc = out->message(out, "agents-list", list, agent_spec, provider);
    } else {
        rc = pcmk_rc_error;
    }

error:
    if (rc != pcmk_rc_ok) {
        if (provider == NULL) {
           out->err(out, _("No agents found for standard '%s'"), agent_spec);
        } else {
           out->err(out, _("No agents found for standard '%s' and provider '%s'"),
                    agent_spec, provider);
        }
    }

    lrmd_api_delete(lrmd_conn);
    return rc;
}

// Documented in pacemaker.h
int
pcmk_list_agents(xmlNodePtr *xml, char *agent_spec)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    lrmd__register_messages(out);

    rc = pcmk__list_agents(out, agent_spec);
    pcmk__xml_output_finish(out, xml);
    return rc;
}

int
pcmk__list_providers(pcmk__output_t *out, const char *agent_spec)
{
    int rc = pcmk_rc_ok;
    lrmd_t *lrmd_conn = NULL;
    lrmd_list_t *list = NULL;

    CRM_ASSERT(out != NULL);

    rc = lrmd__new(&lrmd_conn, NULL, NULL, 0);
    if (rc != pcmk_rc_ok) {
        goto error;
    }

    rc = lrmd_conn->cmds->list_ocf_providers(lrmd_conn, agent_spec, &list);

    if (rc > 0) {
        rc = out->message(out, "providers-list", list, agent_spec);
    } else {
        rc = pcmk_rc_error;
    }

error:
    if (rc != pcmk_rc_ok) {
        if (agent_spec == NULL) {
           out->err(out, _("No %s found"), "OCF providers");
        } else {
           out->err(out, _("No %s found for %s"), "OCF providers", agent_spec);
        }

        rc = ENXIO;
    }

    lrmd_api_delete(lrmd_conn);
    return rc;
}

// Documented in pacemaker.h
int
pcmk_list_providers(xmlNodePtr *xml, const char *agent_spec)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    lrmd__register_messages(out);

    rc = pcmk__list_providers(out, agent_spec);
    pcmk__xml_output_finish(out, xml);
    return rc;
}

int
pcmk__list_standards(pcmk__output_t *out)
{
    int rc = pcmk_rc_ok;
    lrmd_t *lrmd_conn = NULL;
    lrmd_list_t *list = NULL;

    CRM_ASSERT(out != NULL);

    rc = lrmd__new(&lrmd_conn, NULL, NULL, 0);
    if (rc != pcmk_rc_ok) {
        goto error;
    }

    rc = lrmd_conn->cmds->list_standards(lrmd_conn, &list);

    if (rc > 0) {
        rc = out->message(out, "standards-list", list);
    } else {
        rc = pcmk_rc_error;
    }

error:
    if (rc != pcmk_rc_ok) {
       out->err(out, _("No %s found"), "standards");
       rc = ENXIO;
    }

    lrmd_api_delete(lrmd_conn);
    return rc;
}

// Documented in pacemaker.h
int
pcmk_list_standards(xmlNodePtr *xml)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    lrmd__register_messages(out);

    rc = pcmk__list_standards(out);
    pcmk__xml_output_finish(out, xml);
    return rc;
}
