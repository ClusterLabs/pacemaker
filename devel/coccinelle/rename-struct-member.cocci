/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

/*
 * Rename a struct member. This is here as a template; replace the capitalized
 * names below as appropriate. This assumes a struct with a single typedef
 * alias; modify appropriately if not. Then run in the devel directory:
 *
 * make COCCI_FILES=coccinelle/rename-struct-member.cocci cocci-inplace
 *
 * then revert the file before committing.
 *
 * This does not handle the member definition in the struct itself, nor uses in
 * macros or when nested in another struct.
 */

virtual internal

@@
struct STRUCT_NAME s;
@@

- s.OLD_NAME
+ s.NEW_NAME

@@
struct STRUCT_NAME *sp;
@@

- sp->OLD_NAME
+ sp->NEW_NAME

@@
TYPE_ALIAS a;
@@

- a.OLD_NAME
+ a.NEW_NAME

@@
TYPE_ALIAS *ap;
@@

- ap->OLD_NAME
+ ap->NEW_NAME
