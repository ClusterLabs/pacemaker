/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxslt/transform.h>
#include <libxslt/variables.h>
#include <libxslt/xsltutils.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/internal.h>

#include <pacemaker-internal.h>

#define ACL_NS_PREFIX "http://clusterlabs.org/ns/pacemaker/access/"
#define ACL_NS_Q_PREFIX  "pcmk-access-"
#define ACL_NS_Q_WRITABLE (const xmlChar *) ACL_NS_Q_PREFIX   "writable"
#define ACL_NS_Q_READABLE (const xmlChar *) ACL_NS_Q_PREFIX   "readable"
#define ACL_NS_Q_DENIED   (const xmlChar *) ACL_NS_Q_PREFIX   "denied"

static const xmlChar *NS_WRITABLE = (const xmlChar *) ACL_NS_PREFIX "writable";
static const xmlChar *NS_READABLE = (const xmlChar *) ACL_NS_PREFIX "readable";
static const xmlChar *NS_DENIED =   (const xmlChar *) ACL_NS_PREFIX "denied";

/*!
 * \brief This function takes a node and marks it with the namespace
 *        given in the ns parameter.
 *
 * \param[in,out] i_node
 * \param[in] ns
 * \param[in,out] ret
 * \param[in,out] ns_recycle_writable
 * \param[in,out] ns_recycle_readable
 * \param[in,out] ns_recycle_denied
 */
static void
pcmk__acl_mark_node_with_namespace(xmlNode *i_node, const xmlChar *ns, int *ret,
                                   xmlNs **ns_recycle_writable,
                                   xmlNs **ns_recycle_readable,
                                   xmlNs **ns_recycle_denied)
{
    if (ns == NS_WRITABLE)
    {
        if (*ns_recycle_writable == NULL)
        {
            *ns_recycle_writable = xmlNewNs(xmlDocGetRootElement(i_node->doc),
                                           NS_WRITABLE, ACL_NS_Q_WRITABLE);
        }
        xmlSetNs(i_node, *ns_recycle_writable);
        *ret = pcmk_rc_ok;
    }
    else if (ns == NS_READABLE)
    {
        if (*ns_recycle_readable == NULL)
        {
            *ns_recycle_readable = xmlNewNs(xmlDocGetRootElement(i_node->doc),
                                           NS_READABLE, ACL_NS_Q_READABLE);
        }
        xmlSetNs(i_node, *ns_recycle_readable);
        *ret = pcmk_rc_ok;
    }
    else if (ns == NS_DENIED)
    {
        if (*ns_recycle_denied == NULL)
        {
            *ns_recycle_denied = xmlNewNs(xmlDocGetRootElement(i_node->doc),
                                         NS_DENIED, ACL_NS_Q_DENIED);
        };
        xmlSetNs(i_node, *ns_recycle_denied);
        *ret = pcmk_rc_ok;
    }
}

/*!
 * \brief Annotate a given XML element or property and its siblings with
 *        XML namespaces to indicate ACL permissions
 *
 * \param[in,out] xml_modify  XML to annotate
 *
 * \return  A standard Pacemaker return code
 *          Namely:
 *          - pcmk_rc_ok upon success,
 *          - pcmk_rc_already if ACLs were not applicable,
 *          - pcmk_rc_schema_validation if the validation schema version
 *              is unsupported (see note), or
 *          - EINVAL or ENOMEM as appropriate;
 *
 * \note This function is recursive
 */
static int
annotate_with_siblings(xmlNode *xml_modify)
{

    static xmlNs *ns_recycle_writable = NULL,
                 *ns_recycle_readable = NULL,
                 *ns_recycle_denied = NULL;
    static const xmlDoc *prev_doc = NULL;

    xmlNode *i_node = NULL;
    const xmlChar *ns;
    int ret = EINVAL; // nodes have not been processed yet

    if (prev_doc == NULL || prev_doc != xml_modify->doc) {
        prev_doc = xml_modify->doc;
        ns_recycle_writable = ns_recycle_readable = ns_recycle_denied = NULL;
    }

    for (i_node = xml_modify; i_node != NULL; i_node = i_node->next) {
        switch (i_node->type) {
            case XML_ELEMENT_NODE:
                pcmk__xml_doc_set_flags(i_node->doc, pcmk__xf_tracking);

                if (!pcmk__check_acl(i_node, NULL, pcmk__xf_acl_read)) {
                    ns = NS_DENIED;
                } else if (!pcmk__check_acl(i_node, NULL, pcmk__xf_acl_write)) {
                    ns = NS_READABLE;
                } else {
                    ns = NS_WRITABLE;
                }
                pcmk__acl_mark_node_with_namespace(i_node, ns, &ret,
                                                   &ns_recycle_writable,
                                                   &ns_recycle_readable,
                                                   &ns_recycle_denied);
                // @TODO Could replace recursion with iteration to save stack
                if (i_node->properties != NULL) {
                    /* This is not entirely clear, but relies on the very same
                     * class-hierarchy emulation that libxml2 has firmly baked
                     * in its API/ABI
                     */
                    ret |= annotate_with_siblings((xmlNodePtr)
                                                  i_node->properties);
                }
                if (i_node->children != NULL) {
                    ret |= annotate_with_siblings(i_node->children);
                }
                break;

            case XML_ATTRIBUTE_NODE:
                // We can utilize that parent has already been assigned the ns
                if (!pcmk__check_acl(i_node->parent,
                                     (const char *) i_node->name,
                                     pcmk__xf_acl_read)) {
                    ns = NS_DENIED;
                } else if (!pcmk__check_acl(i_node,
                                       (const char *) i_node->name,
                                       pcmk__xf_acl_write)) {
                    ns = NS_READABLE;
                } else {
                    ns = NS_WRITABLE;
                }
                pcmk__acl_mark_node_with_namespace(i_node, ns, &ret,
                                                   &ns_recycle_writable,
                                                   &ns_recycle_readable,
                                                   &ns_recycle_denied);
                break;

            case XML_COMMENT_NODE:
                // We can utilize that parent has already been assigned the ns
                if (!pcmk__check_acl(i_node->parent,
                                     (const char *) i_node->name,
                                     pcmk__xf_acl_read)) {
                    ns = NS_DENIED;
                } else if (!pcmk__check_acl(i_node->parent,
                                            (const char *) i_node->name,
                                            pcmk__xf_acl_write)) {
                    ns = NS_READABLE;
                } else {
                    ns = NS_WRITABLE;
                }
                pcmk__acl_mark_node_with_namespace(i_node, ns, &ret,
                                                   &ns_recycle_writable,
                                                   &ns_recycle_readable,
                                                   &ns_recycle_denied);
                break;

            default:
                break;
        }
    }

    return ret;
}

int
pcmk__acl_annotate_permissions(const char *cred, const xmlDoc *cib_doc,
                               xmlDoc **acl_evaled_doc)
{
    int ret;
    xmlNode *target, *comment;
    const char *validation;

    CRM_CHECK(cred != NULL, return EINVAL);
    CRM_CHECK(cib_doc != NULL, return EINVAL);
    CRM_CHECK(acl_evaled_doc != NULL, return EINVAL);

    /* avoid trivial accidental XML injection */
    if (strpbrk(cred, "<>&") != NULL) {
        return EINVAL;
    }

    if (!pcmk__acl_required(cred)) {
        /* nothing to evaluate */
        return pcmk_rc_already;
    }

    validation = pcmk__xe_get(xmlDocGetRootElement(cib_doc),
                              PCMK_XA_VALIDATE_WITH);

    if (pcmk__cmp_schemas_by_name(PCMK__COMPAT_ACL_2_MIN_INCL,
                                  validation) > 0) {
        return pcmk_rc_schema_validation;
    }

    target = pcmk__xml_copy(NULL, xmlDocGetRootElement((xmlDoc *) cib_doc));
    if (target == NULL) {
        return EINVAL;
    }

    pcmk__enable_acls(target->doc, target->doc, cred);

    ret = annotate_with_siblings(target);

    if (ret == pcmk_rc_ok) {
        char *content = pcmk__assert_asprintf("ACLs as evaluated for user %s",
                                              cred);

        comment = pcmk__xc_create(target->doc, content);
        xmlAddPrevSibling(xmlDocGetRootElement(target->doc), comment);
        *acl_evaled_doc = target->doc;
        free(content);

    } else {
        pcmk__xml_free(target);
    }
    return ret;
}

int
pcmk__acl_evaled_render(xmlDoc *annotated_doc, enum pcmk__acl_render_how how,
                        xmlChar **doc_txt_ptr)
{
    xmlDoc *xslt_doc;
    xsltStylesheet *xslt;
    xsltTransformContext *xslt_ctxt;
    xmlDoc *res;
    char *sfile;
    static const char *params_namespace[] = {
        "accessrendercfg:c-writable",           ACL_NS_Q_PREFIX "writable:",
        "accessrendercfg:c-readable",           ACL_NS_Q_PREFIX "readable:",
        "accessrendercfg:c-denied",             ACL_NS_Q_PREFIX "denied:",
        "accessrendercfg:c-reset",              "",
        "accessrender:extra-spacing",           "no",
        "accessrender:self-reproducing-prefix", ACL_NS_Q_PREFIX,
        NULL
    }, *params_useansi[] = {
        /* start with hard-coded defaults, then adapt per the template ones */
        "accessrendercfg:c-writable",           "\x1b[32m",
        "accessrendercfg:c-readable",           "\x1b[34m",
        "accessrendercfg:c-denied",             "\x1b[31m",
        "accessrendercfg:c-reset",              "\x1b[0m",
        "accessrender:extra-spacing",           "no",
        "accessrender:self-reproducing-prefix", ACL_NS_Q_PREFIX,
        NULL
    }, *params_noansi[] = {
        "accessrendercfg:c-writable",           "vvv---[ WRITABLE ]---vvv",
        "accessrendercfg:c-readable",           "vvv---[ READABLE ]---vvv",
        "accessrendercfg:c-denied",             "vvv---[ ~DENIED~ ]---vvv",
        "accessrendercfg:c-reset",              "",
        "accessrender:extra-spacing",           "yes",
        "accessrender:self-reproducing-prefix", "",
        NULL
    };
    const char **params;
    int rc = pcmk_rc_ok;
    xmlParserCtxtPtr parser_ctxt;

    /* unfortunately, the input (coming from CIB originally) was parsed with
       blanks ignored, and since the output is a conversion of XML to text
       format (we would be covered otherwise thanks to implicit
       pretty-printing), we need to dump the tree to string output first,
       only to subsequently reparse it -- this time with blanks honoured */
    xmlChar *annotated_dump;
    int dump_size;

    pcmk__assert(how != pcmk__acl_render_none);

    // Color is the default render mode for terminals; text is default otherwise
    if (how == pcmk__acl_render_default) {
        if (isatty(STDOUT_FILENO)) {
            how = pcmk__acl_render_color;
        } else {
            how = pcmk__acl_render_text;
        }
    }

    xmlDocDumpFormatMemory(annotated_doc, &annotated_dump, &dump_size, 1);

    /* res does not need private data: it's temporary and used only with libxslt
     * functions
     */
    res = xmlReadDoc(annotated_dump, "on-the-fly-access-render", NULL,
                     XML_PARSE_NONET);
    pcmk__assert(res != NULL);
    xmlFree(annotated_dump);
    pcmk__xml_free_doc(annotated_doc);
    annotated_doc = res;

    sfile = pcmk__xml_artefact_path(pcmk__xml_artefact_ns_base_xslt,
                                    "access-render-2");
    parser_ctxt = xmlNewParserCtxt();

    pcmk__assert(sfile != NULL);
    pcmk__mem_assert(parser_ctxt);

    xslt_doc = xmlCtxtReadFile(parser_ctxt, sfile, NULL, XML_PARSE_NONET);

    xslt = xsltParseStylesheetDoc(xslt_doc);  /* acquires xslt_doc! */
    if (xslt == NULL) {
        pcmk__crit("Problem in parsing %s", sfile);
        rc = EINVAL;
        goto done;
    }
    xmlFreeParserCtxt(parser_ctxt);

    xslt_ctxt = xsltNewTransformContext(xslt, annotated_doc);
    pcmk__mem_assert(xslt_ctxt);

    switch (how) {
        case pcmk__acl_render_namespace:
            params = params_namespace;
            break;
        case pcmk__acl_render_text:
            params = params_noansi;
            break;
        default:
            /* pcmk__acl_render_color is the only remaining option.
             * The compiler complains about params possibly uninitialized if we
             * don't use default here.
             */
            params = params_useansi;
            break;
    }

    xsltQuoteUserParams(xslt_ctxt, params);

    res = xsltApplyStylesheetUser(xslt, annotated_doc, NULL,
                                  NULL, NULL, xslt_ctxt);

    pcmk__xml_free_doc(annotated_doc);
    annotated_doc = NULL;
    xsltFreeTransformContext(xslt_ctxt);
    xslt_ctxt = NULL;

    if (how == pcmk__acl_render_color && params != params_useansi) {
        char **param_i = (char **) params;
        do {
            free(*param_i);
        } while (*param_i++ != NULL);
        free(params);
    }

    if (res == NULL) {
        rc = EINVAL;
    } else {
        int doc_txt_len;
        int temp = xsltSaveResultToString(doc_txt_ptr, &doc_txt_len, res, xslt);

        pcmk__xml_free_doc(res);
        if (temp != 0) {
            rc = EINVAL;
        }
    }

done:
    if (xslt != NULL) {
        xsltFreeStylesheet(xslt);
    }
    free(sfile);
    return rc;
}
