/*
 * Copyright 2011-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <crm_internal.h>

#include <stdio.h>

#include <crm/msg_xml.h>
#include <crm/common/attrd_internal.h>

#define LRM_TARGET_ENV "OCF_RESKEY_" CRM_META "_" XML_LRM_ATTR_TARGET

/*!
 * \internal
 */
const char *
pcmk__node_attr_target(const char *name)
{
    if (name == NULL || pcmk__strcase_any_of(name, "auto", "localhost", NULL)) {
        char *target_var = crm_meta_name(XML_RSC_ATTR_TARGET);
        char *phys_var = crm_meta_name(PCMK__ENV_PHYSICAL_HOST);
        const char *target = getenv(target_var);
        const char *host_physical = getenv(phys_var);

        // It is important to use the name by which the scheduler knows us
        if (host_physical && pcmk__str_eq(target, "host", pcmk__str_casei)) {
            name = host_physical;

        } else {
            const char *host_pcmk = getenv(LRM_TARGET_ENV);

            if (host_pcmk) {
                name = host_pcmk;
            }
        }
        free(target_var);
        free(phys_var);

        // TODO? Call get_local_node_name() if name == NULL
        // (currently would require linkage against libcrmcluster)
        return name;
    } else {
        return NULL;
    }
}

/*!
 * \brief Return the name of the node attribute used as a promotion score
 *
 * \param[in] rsc_id  Resource ID that promotion score is for (or NULL to
 *                    check the OCF_RESOURCE_INSTANCE environment variable)
 *
 * \return Newly allocated string with the node attribute name (or NULL on
 *         error, including no ID or environment variable specified)
 * \note It is the caller's responsibility to free() the result.
 */
char *
pcmk_promotion_score_name(const char *rsc_id)
{
    if (rsc_id == NULL) {
        rsc_id = getenv("OCF_RESOURCE_INSTANCE");
        if (rsc_id == NULL) {
            return NULL;
        }
    }
    return crm_strdup_printf("master-%s", rsc_id);
}
