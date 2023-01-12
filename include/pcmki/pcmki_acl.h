/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMK__PCMKI_PCMKI_ACL__H
#define PCMK__PCMKI_PCMKI_ACL__H

#include <crm/common/xml.h>

// How ACLs can be displayed (for cibadmin --show-access)
enum pcmk__acl_render_how {
    pcmk__acl_render_none = 0,
    pcmk__acl_render_namespace,
    pcmk__acl_render_text,
    pcmk__acl_render_color,
    pcmk__acl_render_default,
};

// Minimum CIB schema version that can be used to annotate and display ACLs
#define PCMK__COMPAT_ACL_2_MIN_INCL "pacemaker-2.0"

/*!
 * \brief Annotate CIB with XML namespaces indicating ACL evaluation results
 *
 * \param[in]  cred            Credential whose ACL perspective to switch to
 * \param[in]  cib_doc         CIB XML to annotate
 * \param[out] acl_evaled_doc  Where to store annotated CIB XML
 *
 * \return  A standard Pacemaker return code (pcmk_rc_ok on success,
 *          pcmk_rc_already if ACLs were not applicable,
 *          pcmk_rc_schema_validation if the validation schema version
 *          is unsupported, or EINVAL or ENOMEM when appropriate.
 * \note This supports CIBs validated with the pacemaker-2.0 schema or newer.
 */
int pcmk__acl_annotate_permissions(const char *cred, const xmlDoc *cib_doc,
                                   xmlDoc **acl_evaled_doc);

/*!
 * \internal
 * \brief Create a string representation of a CIB showing ACL evaluation results
 *
 * \param[in,out] annotated_doc  XML annotated by pcmk__acl_annotate_permissions
 * \param[in]     how            Desired rendering
 * \param[out]    doc_txt_ptr    Where to put the final outcome string
 *
 * \return A standard Pacemaker return code
 *
 * \note This function will free \p annotated_doc, which should not be used
 *       after calling this function.
 * \todo This function could use more extensive testing for resource leaks.
 */
int pcmk__acl_evaled_render(xmlDoc *annotated_doc, enum pcmk__acl_render_how,
                            xmlChar **doc_txt_ptr);

#endif
