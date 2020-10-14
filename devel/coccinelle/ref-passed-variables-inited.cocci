/*
 * Copyright 2019-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 *
 *
 * We require each local variable that
 *
 * - is passed to a function through a dereference (suggesting it serves
 *   possibly also or merely as one of the output value propagators seperate
 *   from actual return value if employed at all) and
 *
 * - is then subsequently reused (possibly naively expecting it will always
 *   have been initialized (in said function at latest) further in its scope,
 *
 * to _always_ be assuredly initialized to some determined value, so as to
 * prevent a risk of accidentally accessing unspecified value subsequent
 * to the return from the considered function, which might not have set
 * that variable at all, lest it would touch it at all.
 */

virtual internal

@ref_passed_variables_inited exists@
identifier f_init, f_consume, var;
type T;
expression E, E_propagate;
@@

  T
- var
+ var /*FIXME:initialize me*/
  ;
  ... when != var = E
  f_init(..., &var, ...)
  ... when != var = E
(
  return var;
|
  f_consume(..., var, ...)
|
  E_propagate = var
|
  &var
|
  *var
)
