/*
 * Original copyright 2004 International Business Machines
 * Later changes copyright 2008-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <libxml/tree.h>    // xmlNode

#include <crm/common/xml.h>
#include <crm/common/cib.h>

/*
 * Functions to help find particular sections of the CIB
 */

// Map CIB element names to their parent elements and XPath searches
static struct {
    const char *name;   // Name of this CIB element
    const char *parent; // CIB element that this element is a child of
    const char *path;   // XPath to find this CIB element
} cib_sections[] = {
    {
        // This first entry is also the default if a NULL is compared
        PCMK_XE_CIB,
        NULL,
        "//" PCMK_XE_CIB
    },
    {
        PCMK_XE_STATUS,
        "/" PCMK_XE_CIB,
        "//" PCMK_XE_CIB "/" PCMK_XE_STATUS
    },
    {
        PCMK_XE_CONFIGURATION,
        "/" PCMK_XE_CIB,
        "//" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION
    },
    {
        PCMK_XE_CRM_CONFIG,
        "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION,
        "//" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_CRM_CONFIG
    },
    {
        PCMK_XE_NODES,
        "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION,
        "//" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_NODES
    },
    {
        PCMK_XE_RESOURCES,
        "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION,
        "//" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_RESOURCES
    },
    {
        PCMK_XE_CONSTRAINTS,
        "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION,
        "//" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_CONSTRAINTS
    },
    {
        PCMK_XE_OP_DEFAULTS,
        "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION,
        "//" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_OP_DEFAULTS
    },
    {
        PCMK_XE_RSC_DEFAULTS,
        "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION,
        "//" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_RSC_DEFAULTS
    },
    {
        PCMK_XE_ACLS,
        "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION,
        "//" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_ACLS
    },
    {
        PCMK_XE_FENCING_TOPOLOGY,
        "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION,
        "//" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_FENCING_TOPOLOGY
    },
    {
        PCMK_XE_TAGS,
        "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION,
        "//" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_TAGS
    },
    {
        PCMK_XE_ALERTS,
        "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION,
        "//" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_ALERTS
    },
    {
        PCMK__XE_ALL,
        NULL,
        "//" PCMK_XE_CIB
    },
};

/*!
 * \brief Get the relative XPath needed to find a specified CIB element name
 *
 * \param[in] element_name  Name of CIB element
 *
 * \return XPath for finding \p element_name in CIB XML (or NULL if unknown)
 * \note The return value is constant and should not be freed.
 */
const char *
pcmk_cib_xpath_for(const char *element_name)
{
    for (int lpc = 0; lpc < PCMK__NELEM(cib_sections); lpc++) {
        // A NULL element_name will match the first entry
        if (pcmk__str_eq(element_name, cib_sections[lpc].name,
                         pcmk__str_null_matches)) {
            return cib_sections[lpc].path;
        }
    }
    return NULL;
}

/*!
 * \internal
 * \brief Get the absolute XPath needed to find a specified CIB element name
 *
 * \param[in] element  Name of CIB element
 *
 * \return XPath for finding \p element in CIB XML (or \c NULL if unknown)
 */
const char *
pcmk__cib_abs_xpath_for(const char *element)
{
    const char *xpath = pcmk_cib_xpath_for(element);

    // XPaths returned by pcmk_cib_xpath_for() are relative (starting with "//")
    return ((xpath != NULL)? (xpath + 1) : NULL);
}

/*!
 * \brief Get the parent element name of a given CIB element name
 *
 * \param[in] element_name  Name of CIB element
 *
 * \return Parent element of \p element_name (or NULL if none or unknown)
 * \note The return value is constant and should not be freed.
 */
const char *
pcmk_cib_parent_name_for(const char *element_name)
{
    for (int lpc = 0; lpc < PCMK__NELEM(cib_sections); lpc++) {
        // A NULL element_name will match the first entry
        if (pcmk__str_eq(element_name, cib_sections[lpc].name,
                         pcmk__str_null_matches)) {
            return cib_sections[lpc].parent;
        }
    }
    return NULL;
}

/*!
 * \brief Find an element in the CIB
 *
 * \param[in] cib           Top-level CIB XML to search
 * \param[in] element_name  Name of CIB element to search for
 *
 * \return XML element in \p cib corresponding to \p element_name
 *         (or \p cib itself if element is unknown or not found)
 */
xmlNode *
pcmk_find_cib_element(xmlNode *cib, const char *element_name)
{
    return pcmk__xpath_find_one(cib->doc, pcmk_cib_xpath_for(element_name),
                                LOG_TRACE);
}

/*!
 * \internal
 * \brief Check that the feature set in the CIB is supported on this node
 *
 * \param[in] new_version   PCMK_XA_CRM_FEATURE_SET attribute from the CIB
 */
int
pcmk__check_feature_set(const char *cib_version)
{
    if ((cib_version != NULL)
        && (pcmk__compare_versions(cib_version, CRM_FEATURE_SET) > 0)) {
        return EPROTONOSUPPORT;
    }

    return pcmk_rc_ok;
}
