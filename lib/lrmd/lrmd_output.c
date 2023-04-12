/*
 * Copyright 2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <stdarg.h>

#include <crm/lrmd_internal.h>
#include <crm/common/output_internal.h>

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

    pcmk__output_xml_create_parent(out, "providers",
                                   "for", agent_spec,
                                   NULL);
    return xml_list(out, list, "provider");
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

    xmlNodePtr node = pcmk__output_xml_create_parent(out, "agents",
                                                     "standard", agent_spec,
                                                     NULL);

    if (!pcmk__str_empty(provider)) {
        crm_xml_add(node, "provider", provider);
    }

    return xml_list(out, list, "agent");
}

PCMK__OUTPUT_ARGS("agents-list", "lrmd_list_t *", "const char *", "const char *")
static int
lrmd__agents_list(pcmk__output_t *out, va_list args) {
    lrmd_list_t *list = va_arg(args, lrmd_list_t *);
    const char *agent_spec = va_arg(args, const char *);
    const char *provider = va_arg(args, const char *);

    int rc;
    char *title = crm_strdup_printf("%s agents", pcmk__str_empty(provider) ? agent_spec : provider);

    rc = default_list(out, list, title);
    free(title);
    return rc;
}

PCMK__OUTPUT_ARGS("providers-list", "lrmd_list_t *", "const char *")
static int
lrmd__providers_list_xml(pcmk__output_t *out, va_list args) {
    lrmd_list_t *list = va_arg(args, lrmd_list_t *);
    const char *agent_spec = va_arg(args, const char *);

    xmlNodePtr node = pcmk__output_xml_create_parent(out, "providers",
                                                     "standard", "ocf",
                                                     NULL);

    if (agent_spec != NULL) {
        crm_xml_add(node, "agent", agent_spec);
    }

    return xml_list(out, list, "provider");
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
