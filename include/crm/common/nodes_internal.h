/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__NODES_INTERNAL__H
#  define PCMK__NODES_INTERNAL__H

/*
 * Special node attributes
 */

#define PCMK__NODE_ATTR_SHUTDOWN            "shutdown"

/* @COMPAT Deprecated since 2.1.8. Use a location constraint with
 * PCMK_XA_RSC_PATTERN=".*" and PCMK_XA_RESOURCE_DISCOVERY="never" instead of
 * PCMK__NODE_ATTR_RESOURCE_DISCOVERY_ENABLED="false".
 */
#define PCMK__NODE_ATTR_RESOURCE_DISCOVERY_ENABLED  "resource-discovery-enabled"

#endif  // PCMK__NODES_INTERNAL__H
