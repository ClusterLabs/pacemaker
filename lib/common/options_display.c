/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include "crmcommon_private.h"

/*!
 * \internal
 * \brief Output an option's possible values
 *
 * \param[in,out] out     Output object
 * \param[in]     option  Option whose possible values to add
 */
static void
add_possible_values_default(pcmk__output_t *out,
                            const pcmk__cluster_option_t *option)
{
    GString *buf = g_string_sized_new(256);

    CRM_ASSERT(option->type != NULL);

    if ((option->values != NULL) && (strcmp(option->type, "select") == 0)) {
        const char *delim = ", ";
        char *str = NULL;
        bool found_default = (option->default_value == NULL);

        pcmk__str_update(&str, option->values);

        for (const char *value = strtok(str, delim); value != NULL;
             value = strtok(NULL, delim)) {

            if (buf->len > 0) {
                g_string_append(buf, delim);
            }
            g_string_append_c(buf, '"');
            g_string_append(buf, value);
            g_string_append_c(buf, '"');

            if (!found_default && (strcmp(value, option->default_value) == 0)) {
                found_default = true;
                g_string_append(buf, _(" (default)"));
            }
        }
        free(str);

    } else if (option->default_value != NULL) {
        pcmk__g_strcat(buf,
                       option->type, _(" (default: \""), option->default_value,
                       "\")", NULL);

    } else {
        pcmk__g_strcat(buf, option->type, _(" (no default)"), NULL);
    }

    out->list_item(out, _("Possible values"), "%s", buf->str);
    g_string_free(buf, TRUE);
}

/*!
 * \internal
 * \brief Output a single option's metadata
 *
 * \param[in,out] out     Output object
 * \param[in]     option  Option to add
 */
static void
add_option_metadata_default(pcmk__output_t *out,
                            const pcmk__cluster_option_t *option)
{
    const char *desc_short = option->description_short;
    const char *desc_long = option->description_long;

    CRM_ASSERT((desc_short != NULL) || (desc_long != NULL));

    if (desc_short == NULL) {
        desc_short = desc_long;
        desc_long = NULL;
    }

    out->list_item(out, option->name, "%s", _(desc_short));

    out->begin_list(out, NULL, NULL, NULL);

    if (desc_long != NULL) {
        out->list_item(out, NULL, "%s", _(desc_long));
    }
    add_possible_values_default(out, option);
    out->end_list(out);
}

/*!
 * \internal
 * \brief Output the metadata for a list of options
 *
 * \param[in,out] out   Output object
 * \param[in]     args  Message-specific arguments
 *
 * \return Standard Pacemaker return code
 *
 * \note \p args should contain the following:
 *       -# Fake resource agent name for the option list (ignored)
 *       -# Short description of option list
 *       -# Long description of option list
 *       -# Filter: Group of <tt>enum pcmk__opt_flags</tt>; output an option
 *          only if its \c flags member has all these flags set
 *       -# <tt>NULL</tt>-terminated list of options whose metadata to format
 */
PCMK__OUTPUT_ARGS("option-list", "const char *", "const char *", "const char *",
                  "uint32_t", "const pcmk__cluster_option_t *")
static int
option_list_default(pcmk__output_t *out, va_list args)
{
    const char *name G_GNUC_UNUSED = va_arg(args, const char *);
    const char *desc_short = va_arg(args, const char *);
    const char *desc_long = va_arg(args, const char *);
    const uint32_t filter = va_arg(args, uint32_t);
    const pcmk__cluster_option_t *option_list =
        va_arg(args, pcmk__cluster_option_t *);

    bool old_fancy = false;

    CRM_ASSERT((out != NULL) && (desc_short != NULL) && (desc_long != NULL)
               && (option_list != NULL));

    old_fancy = pcmk__output_text_get_fancy(out);
    pcmk__output_text_set_fancy(out, true);

    out->info(out, "%s", _(desc_short));
    out->spacer(out);
    out->info(out, "%s", _(desc_long));
    out->begin_list(out, NULL, NULL, NULL);

    for (const pcmk__cluster_option_t *option = option_list;
         option->name != NULL; option++) {

        if (pcmk_all_flags_set(option->flags, filter)) {
            out->spacer(out);
            add_option_metadata_default(out, option);
        }
    }
    out->end_list(out);

    pcmk__output_text_set_fancy(out, old_fancy);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Add a description element to an OCF-like metadata XML node
 *
 * Include a translation based on the current locale if \c ENABLE_NLS is
 * defined.
 *
 * \param[in,out] out       Output object
 * \param[in]     for_long  If \c true, add long description; otherwise, add
 *                          short description
 * \param[in]     desc      Textual description to add
 */
static void
add_desc_xml(pcmk__output_t *out, bool for_long, const char *desc)
{
    const char *tag = (for_long? PCMK_XE_LONGDESC : PCMK_XE_SHORTDESC);
    xmlNode *node = pcmk__output_create_xml_text_node(out, tag, desc);

    crm_xml_add(node, PCMK_XA_LANG, PCMK__VALUE_EN);

#ifdef ENABLE_NLS
    {
        static const char *locale = NULL;

        if (strcmp(desc, _(desc)) == 0) {
            return;
        }

        if (locale == NULL) {
            locale = strtok(setlocale(LC_ALL, NULL), "_");
        }
        node = pcmk__output_create_xml_text_node(out, tag, _(desc));
        crm_xml_add(node, PCMK_XA_LANG, locale);
    }
#endif
}

/*!
 * \internal
 * \brief Output an option's possible values
 *
 * Add a \c PCMK_XE_OPTION element for each of the option's possible values.
 *
 * \param[in,out] out     Output object
 * \param[in]     option  Option whose possible values to add
 */
static void
add_possible_values_xml(pcmk__output_t *out,
                        const pcmk__cluster_option_t *option)
{
    if ((option->values != NULL) && (strcmp(option->type, "select") == 0)) {
        const char *delim = ", ";
        char *str = NULL;
        char *ptr = NULL;

        pcmk__str_update(&str, option->values);
        ptr = strtok(str, delim);

        while (ptr != NULL) {
            pcmk__output_create_xml_node(out, PCMK_XE_OPTION,
                                         PCMK_XA_VALUE, ptr,
                                         NULL);
            ptr = strtok(NULL, delim);
        }
        free(str);
    }
}

/*!
 * \internal
 * \brief Add a \c PCMK_XE_PARAMETER element to an OCF-like metadata XML node
 *
 * \param[in,out] out     Output object
 * \param[in]     option  Option to add as a \c PCMK_XE_PARAMETER element
 */
static void
add_option_metadata_xml(pcmk__output_t *out,
                        const pcmk__cluster_option_t *option)
{
    const char *desc_long = option->description_long;
    const char *desc_short = option->description_short;

    // The standard requires long and short parameter descriptions
    CRM_ASSERT((desc_long != NULL) || (desc_short != NULL));

    if (desc_long == NULL) {
        desc_long = desc_short;
    } else if (desc_short == NULL) {
        desc_short = desc_long;
    }

    // The standard requires a parameter type
    CRM_ASSERT(option->type != NULL);

    pcmk__output_xml_create_parent(out, PCMK_XE_PARAMETER,
                                   PCMK_XA_NAME, option->name,
                                   NULL);
    add_desc_xml(out, true, desc_long);
    add_desc_xml(out, false, desc_short);

    pcmk__output_xml_create_parent(out, PCMK_XE_CONTENT,
                                   PCMK_XA_TYPE, option->type,
                                   PCMK_XA_DEFAULT, option->default_value,
                                   NULL);

    add_possible_values_xml(out, option);

    pcmk__output_xml_pop_parent(out);
    pcmk__output_xml_pop_parent(out);
}

/*!
 * \internal
 * \brief Output the metadata for a list of options as OCF-like XML
 *
 * \param[in,out] out   Output object
 * \param[in]     args  Message-specific arguments
 *
 * \return Standard Pacemaker return code
 *
 * \note \p args should contain the following:
 *       -# Fake resource agent name for the option list
 *       -# Short description of option list
 *       -# Long description of option list
 *       -# Filter: Group of <tt>enum pcmk__opt_flags</tt>; output an option
 *          only if its \c flags member has all these flags set
 *       -# <tt>NULL</tt>-terminated list of options whose metadata to format
 */
PCMK__OUTPUT_ARGS("option-list", "const char *", "const char *", "const char *",
                  "uint32_t", "const pcmk__cluster_option_t *")
static int
option_list_xml(pcmk__output_t *out, va_list args)
{
    const char *name = va_arg(args, const char *);
    const char *desc_short = va_arg(args, const char *);
    const char *desc_long = va_arg(args, const char *);
    const uint32_t filter = va_arg(args, uint32_t);
    const pcmk__cluster_option_t *option_list =
        va_arg(args, pcmk__cluster_option_t *);

    CRM_ASSERT((out != NULL) && (name != NULL) && (desc_short != NULL)
               && (desc_long != NULL) && (option_list != NULL));

    pcmk__output_xml_create_parent(out, PCMK_XE_RESOURCE_AGENT,
                                   PCMK_XA_NAME, name,
                                   PCMK_XA_VERSION, PACEMAKER_VERSION,
                                   NULL);

    pcmk__output_create_xml_text_node(out, PCMK_XE_VERSION, PCMK_OCF_VERSION);
    add_desc_xml(out, true, desc_long);
    add_desc_xml(out, false, desc_short);

    pcmk__output_xml_create_parent(out, PCMK_XE_PARAMETERS, NULL);

    for (const pcmk__cluster_option_t *option = option_list;
         option->name != NULL; option++) {

        if (pcmk_all_flags_set(option->flags, filter)) {
            add_option_metadata_xml(out, option);
        }
    }

    pcmk__output_xml_pop_parent(out);
    pcmk__output_xml_pop_parent(out);
    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "option-list", "default", option_list_default },
    { "option-list", "xml", option_list_xml },

    { NULL, NULL, NULL }
};

/*!
 * \internal
 * \brief Register the formatting functions for option lists
 *
 * \param[in,out] out  Output object
 */
void
pcmk__register_option_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
