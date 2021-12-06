/*
 * Original copyright 2004 International Business Machines
 * Later changes copyright 2008-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <libxml/tree.h>    // xmlNode

#include <crm/msg_xml.h>

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
        XML_TAG_CIB,
        NULL,
        "//" XML_TAG_CIB
    },
    {
        XML_CIB_TAG_STATUS,
        "/" XML_TAG_CIB,
        "//" XML_TAG_CIB "/" XML_CIB_TAG_STATUS
    },
    {
        XML_CIB_TAG_CONFIGURATION,
        "/" XML_TAG_CIB,
        "//" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION
    },
    {
        XML_CIB_TAG_CRMCONFIG,
        "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION,
        "//" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_CRMCONFIG
    },
    {
        XML_CIB_TAG_NODES,
        "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION,
        "//" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_NODES
    },
    {
        XML_CIB_TAG_RESOURCES,
        "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION,
        "//" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_RESOURCES
    },
    {
        XML_CIB_TAG_CONSTRAINTS,
        "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION,
        "//" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_CONSTRAINTS
    },
    {
        XML_CIB_TAG_OPCONFIG,
        "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION,
        "//" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_OPCONFIG
    },
    {
        XML_CIB_TAG_RSCCONFIG,
        "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION,
        "//" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_RSCCONFIG
    },
    {
        XML_CIB_TAG_ACLS,
        "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION,
        "//" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_ACLS
    },
    {
        XML_TAG_FENCING_TOPOLOGY,
        "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION,
        "//" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_TAG_FENCING_TOPOLOGY
    },
    {
        XML_CIB_TAG_TAGS,
        "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION,
        "//" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_TAGS
    },
    {
        XML_CIB_TAG_ALERTS,
        "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION,
        "//" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_ALERTS
    },
    {
        XML_CIB_TAG_SECTION_ALL,
        NULL,
        "//" XML_TAG_CIB
    },
};

/*!
 * \brief Get the XPath needed to find a specified CIB element name
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
    return get_xpath_object(pcmk_cib_xpath_for(element_name), cib, LOG_TRACE);
}
