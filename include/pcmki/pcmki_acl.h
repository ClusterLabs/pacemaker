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

enum pcmk__acl_cred_type {
    pcmk__acl_cred_unset = 0,
    pcmk__acl_cred_user,
    /* XXX no proper support for groups yet */
};

enum pcmk__acl_render_how {
    pcmk__acl_render_none = 0,
    pcmk__acl_render_namespace,
    pcmk__acl_render_text,
    pcmk__acl_render_color,

    //! Context-dependent default render mode
    pcmk__acl_render_default,
};

/*
 * Version compatibility tracking incl. open-ended intervals for occasional
 * bumps (to avoid hard to follow open-coding throughout).  Grouped by context.
 */

/* Schema version vs. evaluate-as-namespace-annotations-per-credentials */

#define PCMK__COMPAT_ACL_2_MIN_INCL "pacemaker-2.0"

/*!
 * \brief Mark CIB with namespace-encoded result of ACLs eval'd per credential
 *
 * \param[in]  cred            Credential whose ACL perspective to switch to
 * \param[in]  cib_doc         CIB XML to annotate
 * \param[out] acl_evaled_doc  Where to store annotated CIB XML
 *
 * \return  A standard Pacemaker return code
 *          Namely:
 *          - pcmk_rc_ok upon success,
 *          - pcmk_rc_already if ACLs were not applicable,
 *          - pcmk_rc_schema_validation if the validation schema version
 *              is unsupported (see note), or
 *          - EINVAL or ENOMEM as appropriate;
 *
 * \note Only supported schemas are those following acls-2.0.rng, that is,
 *       those validated with pacemaker-2.0.rng and newer.
 */
int pcmk__acl_annotate_permissions(const char *cred, const xmlDoc *cib_doc,
                                   xmlDoc **acl_evaled_doc);

/*!
 * \internal
 * \brief Serialize-render already pcmk__acl_annotate_permissions annotated XML
 *
 * \param[in,out] annotated_doc  XML annotated by pcmk__acl_annotate_permissions
 * \param[in]     how            Desired rendering (#pcmk__acl_render_how value)
 * \param[out]    doc_txt_ptr    Where to put the final outcome string
 *
 * \return A standard Pacemaker return code
 *
 * \note Currently, the function did not receive enough of testing regarding
 *       leak of resources, hence it is not recommended for anything other
 *       than short-lived processes at this time.
 * \note This function will free \p annotated_doc, which should not be used
 *       after calling this function.
 */
int pcmk__acl_evaled_render(xmlDoc *annotated_doc, enum pcmk__acl_render_how,
                            xmlChar **doc_txt_ptr);

#endif
