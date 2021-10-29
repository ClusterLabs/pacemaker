/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

/*
 * Rename a variable. This is here as a template; replace "old" and
 * "new" below with the old and new names. Here is an example:
 *
 * @@ @@
 * - xml_private_flags
 * + pcmk__xml_flags
 *
 * Run in the devel directory:
 *
 * make COCCI_FILES=coccinelle/rename-var.cocci cocci-inplace
 *
 * then revert the file before committing.
 */

virtual internal

@@ @@
- old
+ new
