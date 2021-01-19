.. index::
   single: C
   pair: C; guidelines

C Coding Guidelines
-------------------

Pacemaker is a large project accepting contributions from developers with a
wide range of skill levels and organizational affiliations, and maintained by
multiple people over long periods of time. Following consistent guidelines
makes reading, writing, and reviewing code easier, and helps avoid common
mistakes.

Some existing Pacemaker code does not follow these guidelines, for historical
reasons and API backward compatibility, but new code should.


Code Organization
#################

Pacemaker's C code is organized as follows:

+-----------------+-----------------------------------------------------------+
| Directory       | Contents                                                  |
+=================+===========================================================+
| daemons         | the Pacemaker daemons (pacemakerd, pacemaker-based, etc.) |
+-----------------+-----------------------------------------------------------+
| include         | header files for library APIs                             |
+-----------------+-----------------------------------------------------------+
| lib             | libraries                                                 |
+-----------------+-----------------------------------------------------------+
| tools           | command-line tools                                        |
+-----------------+-----------------------------------------------------------+

Source file names should be unique across the entire project, to allow for
individual tracing via ``PCMK_trace_files``.


.. index::
   single: C; library
   single: C library

Pacemaker Libraries
###################

+---------------+---------+---------------+---------------------------+-------------------------------------+
| Library       | Symbol  | Source        | API Headers               | Description                         |
|               | prefix  | location      |                           |                                     |
+===============+=========+===============+===========================+=====================================+
| libcib        | cib     | lib/cib       | | include/crm/cib.h       | .. index::                          |
|               |         |               | | include/crm/cib/*       |    single: C library; libcib        |
|               |         |               |                           |    single: libcib                   |
|               |         |               |                           |                                     |
|               |         |               |                           | API for pacemaker-based IPC and     |
|               |         |               |                           | the CIB                             |
+---------------+---------+---------------+---------------------------+-------------------------------------+
| libcrmcluster | pcmk    | lib/cluster   | | include/crm/cluster.h   | .. index::                          |
|               |         |               | | include/crm/cluster/*   |    single: C library; libcrmcluster |
|               |         |               |                           |    single: libcrmcluster            |
|               |         |               |                           |                                     |
|               |         |               |                           | Abstract interface to underlying    |
|               |         |               |                           | cluster layer                       |
+---------------+---------+---------------+---------------------------+-------------------------------------+
| libcrmcommon  | pcmk    | lib/common    | | include/crm/common/*    | .. index::                          |
|               |         |               | | some of include/crm/*   |    single: C library; libcrmcommon  |
|               |         |               |                           |    single: libcrmcommon             |
|               |         |               |                           |                                     |
|               |         |               |                           | Everything else                     |
+---------------+---------+---------------+---------------------------+-------------------------------------+
| libcrmservice | svc     | lib/services  | | include/crm/services.h  | .. index::                          |
|               |         |               |                           |    single: C library; libcrmservice |
|               |         |               |                           |    single: libcrmservice            |
|               |         |               |                           |                                     |
|               |         |               |                           | Abstract interface to supported     |
|               |         |               |                           | resource types (OCF, LSB, etc.)     |
+---------------+---------+---------------+---------------------------+-------------------------------------+
| liblrmd       | lrmd    | lib/lrmd      | | include/crm/lrmd*.h     | .. index::                          |
|               |         |               |                           |    single: C library; liblrmd       |
|               |         |               |                           |    single: liblrmd                  |
|               |         |               |                           |                                     |
|               |         |               |                           | API for pacemaker-execd IPC         |
+---------------+---------+---------------+---------------------------+-------------------------------------+
| libpacemaker  | pcmk    | lib/pacemaker | | include/pacemaker*.h    | .. index::                          |
|               |         |               | | include/pcmki/*         |    single: C library; libpacemaker  |
|               |         |               |                           |    single: libpacemaker             |
|               |         |               |                           |                                     |
|               |         |               |                           | High-level APIs equivalent to       |
|               |         |               |                           | command-line tool capabilities      |
|               |         |               |                           | (and high-level internal APIs)      |
+---------------+---------+---------------+---------------------------+-------------------------------------+
| libpe_rules   | pe      | lib/pengine   | | include/crm/pengine/*   | .. index::                          |
|               |         |               |                           |    single: C library; libpe_rules   |
|               |         |               |                           |    single: libpe_rules              |
|               |         |               |                           |                                     |
|               |         |               |                           | Scheduler functionality related     |
|               |         |               |                           | to evaluating rules                 |
+---------------+---------+---------------+---------------------------+-------------------------------------+
| libpe_status  | pe      | lib/pengine   | | include/crm/pengine/*   | .. index::                          |
|               |         |               |                           |    single: C library; libpe_status  |
|               |         |               |                           |    single: libpe_status             |
|               |         |               |                           |                                     |
|               |         |               |                           | Low-level scheduler functionality   |
+---------------+---------+---------------+---------------------------+-------------------------------------+
| libstonithd   | stonith | lib/fencing   | | include/crm/stonith-ng.h| .. index::                          |
|               |         |               | | include/crm/fencing/*   |    single: C library; libstonithd   |
|               |         |               |                           |    single: libstonithd              |
|               |         |               |                           |                                     |
|               |         |               |                           | API for pacemaker-fenced IPC        |
+---------------+---------+---------------+---------------------------+-------------------------------------+


Public versus Internal APIs
___________________________

Pacemaker libraries have both internal and public APIs. Internal APIs are those
used only within Pacemaker; public APIs are those offered (via header files and
documentation) for external code to use.

Generic functionality needed by Pacemaker itself, such as string processing or
XML processing, should remain internal, while functions providing useful
high-level access to Pacemaker capabilities should be public. When in doubt,
keep APIs internal, because it's easier to expose a previously internal API
than hide a previously public API.

Internal APIs can be changed as needed.

The public API/ABI should maintain a degree of stability so that external
applications using it do not need to be rewritten or rebuilt frequently. Many
OSes/distributions avoid breaking API/ABI compatibility within a major release,
so if Pacemaker breaks compatibility, that significantly delays when OSes
can package the new version. Therefore, changes to public APIs should be
backward-compatible (as detailed throughout this chapter), unless we are doing
a (rare) release where we specifically intend to break compatibility.

External applications known to use Pacemaker's public C API include
`sbd <https://github.com/ClusterLabs/sbd>`_ and dlm_controld.


.. index::
   pair: C; API documentation
   single: Doxygen

API Documentation
_________________

Pacemaker uses `Doxygen <https://www.doxygen.nl/manual/docblocks.html>`_
to automatically generate its
`online API documentation <https://clusterlabs.org/pacemaker/doxygen/>`_,
so all public API (header files, functions, structs, enums, etc.) should be
documented with Doxygen comment blocks. Other code may be documented in the
same way if desired, with an ``\internal`` tag in the Doxygen comment.

Simple example of an internal function with a Doxygen comment block:

.. code-block:: c

   /*!
    * \internal
    * \brief Return string length plus 1
    *
    * Return the number of characters in a given string, plus one.
    *
    * \param[in] s  A string (must not be NULL)
    *
    * \return The length of \p s plus 1.
    */
   static int
   f(const char *s)
   {
      return strlen(s) + 1;
   }


API Header File Naming
______________________

* Internal API headers should be named ending in ``_internal.h``, in the same
  location as public headers, with the exception of libpacemaker, which for
  historical reasons keeps internal headers in ``include/pcmki/pcmki_*.h``).

* If a library needs to share symbols just within the library, header files for
  these should be named ending in ``_private.h`` and located in the library
  source directory (not ``include``). Such functions should be declared as
  ``G_GNUC_INTERNAL``, to aid compiler efficiency (glib defines this
  symbol appropriately for the compiler).

Header files that are not library API are located in the same locations as
other source code.


.. index::
   pair: C; naming

API Symbol Naming
_________________

Exposed API symbols (non-``static`` function names, ``struct`` and ``typedef``
names in header files, etc.) must begin with the prefix appropriate to the
library (shown in the table at the beginning of this section). This reduces the
chance of naming collisions when external software links against the library.

The prefix is usually lowercase but may be all-caps for some defined constants
and macros.

Public API symbols should follow the library prefix with a single underbar
(for example, ``pcmk_something``), and internal API symbols with a double
underbar (for example, ``pcmk__other_thing``).

File-local symbols (such as static functions) and non-library code do not
require a prefix, though a unique prefix indicating an executable (controld,
crm_mon, etc.) can be helpful to indicate symbols shared between multiple
source files for the executable.


.. index::
   pair: C; boilerplate
   pair: license; C
   pair: copyright; C

C Boilerplate
#############

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
###############

* Indentation must be 4 spaces, no tabs.
* Do not leave trailing whitespace.
* Lines should be no longer than 80 characters unless limiting line length
  significantly impacts readability.

.. index::
   pair: C; pointer

Pointers
########

* The ``*`` goes by the variable name, not the type:

.. code-block:: c

   char *foo;

* Use a space before the ``*`` and after the closing parenthesis in a cast:

.. code-block:: c

   char *foo = (char *) bar;


.. index::
   pair: C; function

Function Definitions
####################

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
#################################################

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
#########

* Operators have spaces from both sides.
* Do not rely on operator precedence; use parentheses when mixing operators
  with different priority.
* No space is used after opening parenthesis and before closing parenthesis.

.. code-block:: c

   x = a + b - (c * d);




.. index::
   pair: C; struct
   pair: C; enum

New Struct and Enum Members
###########################

In the public APIs, always add new ``struct`` members to the end of the
``struct``. This allows us to maintain backward API/ABI compatibility (as long
as the application being linked allocates structs via API functions).

This generally applies to ``enum`` values as well, as the compiler will define
``enum`` values to 0, 1, etc., in the order given, so inserting a value in the
middle will change the numerical values of all later values, making them
backward-incompatible. However, if enum numerical values are explicitly
specified rather than left to the compiler, new values can be added anywhere.




.. index::
   pair: C; naming

Symbol Naming
#############

* All file and function names should be unique across the entire project,
  to allow for individual tracing via ``PCMK_trace_files`` and
  ``PCMK_trace_functions``, as well as making detail logs easier to follow.
* Time intervals are sometimes represented in Pacemaker code as user-defined
  text specifications (e.g. "10s"), other times as an integer number of
  seconds or milliseconds, and still other times as a string representation
  of an integer number. Variables for these should be named with an indication
  of which is being used (e.g. ``interval_spec``, ``interval_ms``, or
  ``interval_ms_s`` instead of ``interval``).

.. index::
   pair: C; memory

Memory Allocation
#################

* Always use ``calloc()`` rather than ``malloc()``. It has no additional cost on
  modern operating systems, and reduces the severity and security risks of
  uninitialized memory usage bugs.

.. index::
   pair: C; logging

Logging
#######

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
###################

- Use ``REG_NOSUB`` with ``regcomp()`` whenever possible, for efficiency.
- Be sure to use ``regfree()`` appropriately.


.. index::
   pair: C; vim settings

vim Settings
############

Developers who use ``vim`` to edit source code can add the following settings
to their ``~/.vimrc`` file to follow Pacemaker C coding guidelines:

.. code-block:: none

   " follow Pacemaker coding guidelines when editing C source code files
   filetype plugin indent on
   au FileType c   setlocal expandtab tabstop=4 softtabstop=4 shiftwidth=4 textwidth=80
   autocmd BufNewFile,BufRead *.h set filetype=c
   let c_space_errors = 1
