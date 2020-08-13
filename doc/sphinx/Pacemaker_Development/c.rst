.. index::
   single: C
   pair: C; guidelines

C Coding Guidelines
-------------------

.. index::
   pair: C; style

Style Guidelines
################

Pacemaker is a large, distributed project accepting contributions from
developers with a wide range of skill levels and organizational affiliations,
and maintained by multiple people over long periods of time. The guidelines in
this section are not technically better than alternative approaches, but make
project management easier.

Many of these simply ensure stylistic consistency, which makes reading,
writing, and reviewing code easier.

.. index::
   pair: C; boilerplate
   pair: license; C
   pair: copyright; C

C Boilerplate
_____________

Every C file should start with a short copyright notice:

.. code-block:: c

   /*
    * Copyright <YYYY[-YYYY]> the Pacemaker project contributors
    *
    * The version control history for this file may have further details.
    *
    * This source code is licensed under <LICENSE> WITHOUT ANY WARRANTY.
    */

*<LICENSE>* should follow the policy set forth in the
`COPYING <https://github.com/ClusterLabs/pacemaker/blob/master/COPYING>`_ file,
generally one of "GNU General Public License version 2 or later (GPLv2+)"
or "GNU Lesser General Public License version 2.1 or later (LGPLv2.1+)".

Header files should additionally protect against multiple inclusion by defining
a unique symbol in the form ``PCMK__<capitalized_header_name>__H``. For example:

.. code-block:: c

   #ifndef PCMK__MY_HEADER_H
   #  define PCMK__MY_HEADER_H

   // header code here

   #endif // PCMK__MY_HEADER_H

Public API header files should additionally declare "C" compatibility for
inclusion by C++, and give a Doxygen file description. For example:

.. code-block:: c

   #ifdef __cplusplus
   extern "C" {
   #endif

   /*!
    * \file
    * \brief My brief description here
    * \ingroup core
    */

   // header code here

   #ifdef __cplusplus
   }
   #endif

.. index::
   pair: C; whitespace

Line Formatting
_______________

* Indentation must be 4 spaces, no tabs.
* Do not leave trailing whitespace.
* Lines should be no longer than 80 characters unless limiting line length
  significantly impacts readability.

.. index::
   pair: C; pointer

Pointers
________

* The ``*`` goes by the variable name, not the type:

.. code-block:: c

   char *foo;

* Use a space before the ``*`` and after the closing parenthesis in a cast:

.. code-block:: c

   char *foo = (char *) bar;


.. index::
   pair: C; function

Function Definitions
____________________

* In the function definition, put the return type on its own line, and place
  the opening brace by itself on a line.
* For functions with enough arguments that they must break to the next line,
  align arguments with the first argument.
* When a function argument is a function itself, use the pointer form.

.. code-block:: c

   static int
   function_name(int bar, const char *a, const char *b,
                 const char *c, void (*d)())
   {

* If a function name gets really long, start the arguments on their own line
  with 8 spaces of indentation:

.. code-block:: c

   static int
   really_really_long_function_name_this_is_getting_silly_now(
           int bar, const char *a, const char *b,
           const char *c, const char *d)
   {

Control Statements (if, else, while, for, switch)
_________________________________________________

* The keyword is followed by one space, then left parenthesis without space,
  condition, right parenthesis, space, opening bracket on the same line.
  ``else`` and ``else if`` are on the same line with the ending brace and
  opening brace, separated by a space.
* Always use braces around control statement blocks, even if they only contain
  one line. This makes code review diffs smaller if a line gets added in the
  future, and avoids any chance of bad indenting making a line incorrectly
  appear to be part of the block.
* Do not put assignments in ``if`` or ``while`` conditionals. This ensures that
  the developer's intent is always clear, making code reviews easier and
  reducing the chance of using assignment where comparison is intended.

.. code-block:: c

   a = f();
   if (a < 0) {
       statement1;
   } else if (some_other_condition) {
       statement2;
   } else {
       statement3;
   }

* In a ``switch`` statement, ``case`` is indented one level, and the body of
  each ``case`` is indented by another level. The opening brace is on the same
  line as ``switch``.

.. code-block:: c

   switch (expression) {
       case 0:
           command1;
           break;
       case 1:
           command2;
           break;
       default:
           command3;
   }

.. index::
   pair: C; operator

Operators
_________

* Operators have spaces from both sides.
* Do not rely on operator precedence; use parentheses when mixing operators
  with different priority.
* No space is used after opening parenthesis and before closing parenthesis.

.. code-block:: c

   x = a + b - (c * d);


Best Practices
##############

The guidelines in this section offer technical advantages.

.. index::
   pair: C; struct
   pair: C; enum

New Struct and Enum Members
___________________________

In the public APIs, always add new ``struct`` members to the end of the
``struct``. This allows us to maintain backward API/ABI compatibility (as long
as the application being linked allocates structs via API functions).

This generally applies to ``enum`` values as well, as the compiler will define
``enum`` values to 0, 1, etc., in the order given, so inserting a value in the
middle will change the numerical values of all later values, making them
backward-incompatible. However, if enum numerical values are explicitly
specified rather than left to the compiler, new values can be added anywhere.

.. index::
   pair: C; API documentation

API documentation
_________________

All public API header files, functions, structs, enums, etc.,
should be documented with Doxygen comment blocks, as Pacemaker's
`online API documentation <https://clusterlabs.org/pacemaker/doxygen/>`_
is automatically generated via Doxygen. It is helpful to document
private symbols in the same way, with an ``\internal`` tag in the
Doxygen comment.

.. index::
   pair: C; naming

Symbol Naming
_____________

* All file and function names should be unique across the entire project,
  to allow for individual tracing via ``PCMK_trace_files`` and
  ``PCMK_trace_functions``, as well as making detail logs easier to follow.
* Any exposed symbols in libraries (non-``static`` function names, type names,
  etc.) must begin with a prefix appropriate to the library, for example,
  ``pcmk_``, ``pe_``, ``st_``, ``lrm_``. This reduces the chance of naming
  collisions with software linked against the library.
* Time intervals are sometimes represented in Pacemaker code as user-defined
  text specifications (e.g. "10s"), other times as an integer number of
  seconds or milliseconds, and still other times as a string representation
  of an integer number. Variables for these should be named with an indication
  of which is being used (e.g. ``interval_spec``, ``interval_ms``, or
  ``interval_ms_s`` instead of ``interval``).

.. index::
   pair: C; memory

Memory Allocation
_________________

* Always use ``calloc()`` rather than ``malloc()``. It has no additional cost on
  modern operating systems, and reduces the severity and security risks of
  uninitialized memory usage bugs.

.. index::
   pair: C; logging

Logging
_______

* When format strings are used for derived data types whose implementation may
  vary across platforms (``pid_t``, ``time_t``, etc.), the safest approach is
  to use ``%lld`` in the format string, and cast the value to ``long long``.

* Do *not* pass ``NULL`` as an argument to satisfy the ``%s`` format specifier
  in logging (and more generally, ``printf``-style) functions. When the string
  "<null>" is a sufficient output representation in such case, you can use the
  ``crm_str()`` convenience macro; otherwise, the ternary operator is an
  obvious choice.

.. index::
   pair: C; regular expression

Regular Expressions
___________________

- Use ``REG_NOSUB`` with ``regcomp()`` whenever possible, for efficiency.
- Be sure to use ``regfree()`` appropriately.

vim Settings
____________

.. index:: vim

Developers who use ``vim`` to edit source code can add the following settings
to their ``~/.vimrc`` file to follow Pacemaker C coding guidelines:

.. code-block:: none

   " follow Pacemaker coding guidelines when editing C source code files
   filetype plugin indent on
   au FileType c   setlocal expandtab tabstop=4 softtabstop=4 shiftwidth=4 textwidth=80
   autocmd BufNewFile,BufRead *.h set filetype=c
   let c_space_errors = 1
