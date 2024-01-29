/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <libxml/tree.h>    // xmlNode

#include <pacemaker.h>
#include <pacemaker-internal.h>

/*!
 * \internal
 * \brief List all available cluster options
 *
 * These are options that affect the entire cluster.
 *
 * \param[in,out] out  Output object
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__list_cluster_options(pcmk__output_t *out)
{
    const char *name = "cluster-options";
    const char *desc_short = "Pacemaker cluster options";
    const char *desc_long = NULL;

    // Can't use string constants because desc_long may be translated by gettext
    desc_long = "Also known as properties, these are options that affect "
                "behavior across the entire cluster. They are configured "
                "within cluster_property_set elements inside the crm_config "
                "subsection of the CIB configuration section.";

    return pcmk__output_cluster_options(out, name, desc_short, desc_long,
                                        pcmk__opt_context_none);
}

// Documented in header
int
pcmk_list_cluster_options(xmlNode **xml)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pcmk__register_lib_messages(out);

    rc = pcmk__list_cluster_options(out);

    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}
