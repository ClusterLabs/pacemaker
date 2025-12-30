/*
 * Copyright 2020-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <stdarg.h>

#include <crm/lrmd_internal.h>
#include <crm/common/xml.h>

static int
default_list(pcmk__output_t *out, lrmd_list_t *list, const char *title) {
    lrmd_list_t *iter = NULL;

    out->begin_list(out, NULL, NULL, "%s", title);

    for (iter = list; iter != NULL; iter = iter->next) {
        out->list_item(out, NULL, "%s", iter->val);
    }

    out->end_list(out);
    lrmd_list_freeall(list);
    return pcmk_rc_ok;
}

static int
xml_list(pcmk__output_t *out, lrmd_list_t *list, const char *ele) {
    lrmd_list_t *iter = NULL;

    for (iter = list; iter != NULL; iter = iter->next) {
        pcmk__output_create_xml_text_node(out, ele, iter->val);
    }

    lrmd_list_freeall(list);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("alternatives-list", "lrmd_list_t *", "const char *")
static int
lrmd__alternatives_list_xml(pcmk__output_t *out, va_list args) {
    lrmd_list_t *list = va_arg(args, lrmd_list_t *);
    const char *agent_spec = va_arg(args, const char *);

    xmlNode *xml = NULL;
    int rc = pcmk_rc_ok;

    xml = pcmk__output_xml_create_parent(out, PCMK_XE_PROVIDERS);
    pcmk__xe_set(xml, PCMK_XA_FOR, agent_spec);

    rc = xml_list(out, list, PCMK_XE_PROVIDER);
    pcmk__output_xml_pop_parent(out);
    return rc;
}

PCMK__OUTPUT_ARGS("alternatives-list", "lrmd_list_t *", "const char *")
static int
lrmd__alternatives_list(pcmk__output_t *out, va_list args) {
    lrmd_list_t *list = va_arg(args, lrmd_list_t *);
    const char *agent_spec G_GNUC_UNUSED = va_arg(args, const char *);

    return default_list(out, list, "Providers");
}

PCMK__OUTPUT_ARGS("agents-list", "lrmd_list_t *", "const char *", "const char *")
static int
lrmd__agents_list_xml(pcmk__output_t *out, va_list args) {
    lrmd_list_t *list = va_arg(args, lrmd_list_t *);
    const char *agent_spec = va_arg(args, const char *);
    const char *provider = va_arg(args, const char *);

    xmlNode *xml = NULL;
    int rc = pcmk_rc_ok;

    xml = pcmk__output_xml_create_parent(out, PCMK_XE_AGENTS);
    pcmk__xe_set(xml, PCMK_XA_STANDARD, agent_spec);

    if (!pcmk__str_empty(provider)) {
        pcmk__xe_set(xml, PCMK_XA_PROVIDER, provider);
    }

    rc = xml_list(out, list, PCMK_XE_AGENT);
    pcmk__output_xml_pop_parent(out);
    return rc;
}

PCMK__OUTPUT_ARGS("agents-list", "lrmd_list_t *", "const char *", "const char *")
static int
lrmd__agents_list(pcmk__output_t *out, va_list args) {
    lrmd_list_t *list = va_arg(args, lrmd_list_t *);
    const char *agent_spec = va_arg(args, const char *);
    const char *provider = va_arg(args, const char *);

    const char *desc = pcmk__str_empty(provider)? agent_spec : provider;
    char *title = pcmk__assert_asprintf("%s agents",
                                        pcmk__s(desc, "(unknown)"));
    int rc = default_list(out, list, title);

    free(title);
    return rc;
}

PCMK__OUTPUT_ARGS("providers-list", "lrmd_list_t *", "const char *")
static int
lrmd__providers_list_xml(pcmk__output_t *out, va_list args) {
    lrmd_list_t *list = va_arg(args, lrmd_list_t *);
    const char *agent_spec = va_arg(args, const char *);

    xmlNode *xml = NULL;
    int rc = pcmk_rc_ok;

    xml = pcmk__output_xml_create_parent(out, PCMK_XE_PROVIDERS);
    pcmk__xe_set(xml, PCMK_XA_STANDARD, "ocf");
    pcmk__xe_set(xml, PCMK_XA_AGENT, agent_spec);

    rc = xml_list(out, list, PCMK_XE_PROVIDER);
    pcmk__output_xml_pop_parent(out);
    return rc;
}

PCMK__OUTPUT_ARGS("providers-list", "lrmd_list_t *", "const char *")
static int
lrmd__providers_list(pcmk__output_t *out, va_list args) {
    lrmd_list_t *list = va_arg(args, lrmd_list_t *);
    const char *agent_spec G_GNUC_UNUSED = va_arg(args, const char *);

    return default_list(out, list, "Providers");
}

PCMK__OUTPUT_ARGS("standards-list", "lrmd_list_t *")
static int
lrmd__standards_list(pcmk__output_t *out, va_list args) {
    lrmd_list_t *list = va_arg(args, lrmd_list_t *);

    return default_list(out, list, "Standards");
}

static pcmk__message_entry_t fmt_functions[] = {
    { "alternatives-list", "default", lrmd__alternatives_list },
    { "alternatives-list", "xml", lrmd__alternatives_list_xml },
    { "agents-list", "default", lrmd__agents_list },
    { "agents-list", "xml", lrmd__agents_list_xml },
    { "providers-list", "default", lrmd__providers_list },
    { "providers-list", "xml", lrmd__providers_list_xml },
    { "standards-list", "default", lrmd__standards_list },

    { NULL, NULL, NULL }
};

void
lrmd__register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
