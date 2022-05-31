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

Public API Deprecation
______________________

Public APIs may not be removed in most Pacemaker releases, but they may be
deprecated.

When a public API is deprecated, it is moved to a header whose name ends in
``compat.h``. The original header includes the compatibility header only if the
``PCMK_ALLOW_DEPRECATED`` symbol is undefined or defined to 1. This allows
external code to continue using the deprecated APIs, but internal code is
prevented from using them because the ``crm_internal.h`` header defines the
symbol to 0.


.. index::
   pair: C; boilerplate
   pair: license; C
   pair: copyright; C

C Boilerplate
#############

Every C file should start with a short copyright and license notice:

.. code-block:: c

   /*
    * Copyright <YYYY[-YYYY]> the Pacemaker project contributors
    *
    * The version control history for this file may have further details.
    *
    * This source code is licensed under <LICENSE> WITHOUT ANY WARRANTY.
    */

*<LICENSE>* should follow the policy set forth in the
`COPYING <https://github.com/ClusterLabs/pacemaker/blob/main/COPYING>`_ file,
generally one of "GNU General Public License version 2 or later (GPLv2+)"
or "GNU Lesser General Public License version 2.1 or later (LGPLv2.1+)".

Header files should additionally protect against multiple inclusion by defining
a unique symbol of the form ``PCMK__<capitalized_header_name>__H``. For
example:

.. code-block:: c

   #ifndef PCMK__MY_HEADER__H
   #  define PCMK__MY_HEADER__H

   // header code here

   #endif // PCMK__MY_HEADER__H

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
  hurts readability.


.. index::
   pair: C; comment

Comments
########

.. code-block:: c

   /* Single-line comments may look like this */

   // ... or this

   /* Multi-line comments should start immediately after the comment opening.
    * Subsequent lines should start with an aligned asterisk. The comment
    * closing should be aligned and on a line by itself.
    */


.. index::
   single: C; pointer

Variables
#########

* Pointers:

.. code-block:: c

   /* (1) The asterisk goes by the variable name, not the type;
    * (2) Avoid leaving pointers uninitialized, to lessen the impact of
    *     use-before-assignment bugs
    */
   char *my_string = NULL;

   // Use space before asterisk and after closing parenthesis in a cast
   char *foo = (char *) bar;

* Global variables should be avoided in libraries when possible. State
  information should instead be passed as function arguments (often as a
  structure). This is not for thread safety -- Pacemaker's use of forking
  ensures it will never be threaded -- but it does minimize overhead,
  improve readability, and avoid obscure side effects.

* Time intervals are sometimes represented in Pacemaker code as user-defined
  text specifications (for example, "10s"), other times as an integer number of
  seconds or milliseconds, and still other times as a string representation
  of an integer number. Variables for these should be named with an indication
  of which is being used (for example, use ``interval_spec``, ``interval_ms``,
  or ``interval_ms_s`` instead of ``interval``).



.. index::
   pair: C; operator

Operators
#########

.. code-block:: c

   // Operators have spaces on both sides
   x = a;

   /* (1) Do not rely on operator precedence; use parentheses when mixing
    *     operators with different priority, for readability.
    * (2) No space is used after an opening parenthesis or before a closing
    *     parenthesis.
    */
   x = a + b - (c * d);


.. index::
   single: C; if
   single: C; else
   single: C; while
   single: C; for
   single: C; switch

Control Statements (if, else, while, for, switch)
#################################################

.. code-block:: c

   /*
    * (1) The control keyword is followed by a space, a left parenthesis
    *     without a space, the condition, a right parenthesis, a space, and the
    *     opening bracket on the same line.
    * (2) Always use braces around control statement blocks, even if they only
    *     contain one line. This makes code review diffs smaller if a line gets
    *     added in the future, and avoids the chance of bad indenting making a
    *     line incorrectly appear to be part of the block.
    * (3) The closing bracket is on a line by itself.
    */
   if (v < 0) {
       return 0;
   }

   /* "else" and "else if" are on the same line with the previous ending brace
    * and next opening brace, separated by a space. Blank lines may be used
    * between blocks to help readability.
    */
   if (v > 0) {
       return 0;

   } else if (a == 0) {
       return 1;

   } else {
       return 2;
   }

   /* Do not use assignments in conditions. This ensures that the developer's
    * intent is always clear, makes code reviews easier, and reduces the chance
    * of using assignment where comparison is intended.
    */
   // Do this ...
   a = f();
   if (a) {
       return 0;
   }
   // ... NOT this
   if (a = f()) {
       return 0;
   }

   /* It helps readability to use the "!" operator only in boolean
    * comparisons, and explicitly compare numeric values against 0,
    * pointers against NULL, etc. This helps remind the reader of the
    * type being compared.
    */
   int i = 0;
   char *s = NULL;
   bool cond = false;

   if (!cond) {
       return 0;
   }
   if (i == 0) {
       return 0;
   }
   if (s == NULL) {
       return 0;
   }

   /* In a "switch" statement, indent "case" one level, and indent the body of
    * each "case" another level.
    */
   switch (expression) {
       case 0:
           command1;
           break;
       case 1:
           command2;
           break;
       default:
           command3;
           break;
   }


.. index::
   single: C; struct

Structures
##########

Changes to structures defined in public API headers (adding or removing
members, or changing member types) are generally not possible without breaking
API compatibility. However, there are exceptions:

* Public API structures can be designed such that they can be allocated only
  via API functions, not declared directly or allocated with standard memory
  functions using ``sizeof``.

  * This can be enforced simply by documentating the limitation, in which case
    new ``struct`` members can be added to the end of the structure without
    breaking compatibility.

  * Alternatively, the structure definition can be kept in an internal header,
    with only a pointer type definition kept in a public header, in which case
    the structure definition can be changed however needed.


.. index::
   single: C; enum

Enumerations
############

* Enumerations should not have a ``typedef``, and do not require any naming
  convention beyond what applies to all exposed symbols.

* New values should usually be added to the end of public API enumerations,
  because the compiler will define the values to 0, 1, etc., in the order
  given, and inserting a value in the middle would change the numerical values
  of all later values, breaking code compiled with the old values. However, if
  enum numerical values are explicitly specified rather than left to the
  compiler, new values can be added anywhere.

* When defining constant integer values, enum should be preferred over
  ``#define`` or ``const`` when possible. This allows type checking without
  consuming memory.

Flag groups
___________

Pacemaker often uses flag groups (also called bit fields or bitmasks) for a
collection of boolean options (flags/bits).

This is more efficient for storage and manipulation than individual booleans,
but its main advantage is when used in public APIs, because using another bit
in a bitmask is backward compatible, whereas adding a new function argument (or
sometimes even a structure member) is not.

.. code-block:: c

   #include <stdint.h>

   /* (1) Define an enumeration to name the individual flags, for readability.
    *     An enumeration is preferred to a series of "#define" constants
    *     because it is typed, and logically groups the related names.
    * (2) Define the values using left-shifting, which is more readable and
    *     less error-prone than hexadecimal literals (0x0001, 0x0002, 0x0004,
    *     etc.).
    * (3) Using a comma after the last entry makes diffs smaller for reviewing
    *     if a new value needs to be added or removed later.
    */
   enum pcmk__some_bitmask_type {
       pcmk__some_value    = (1 << 0),
       pcmk__other_value   = (1 << 1),
       pcmk__another_value = (1 << 2),
   };

   /* The flag group itself should be an unsigned type from stdint.h (not
    * the enum type, since it will be a mask of the enum values and not just
    * one of them). uint32_t is the most common, since we rarely need more than
    * 32 flags, but a smaller or larger type could be appropriate in some
    * cases.
    */
   uint32_t flags = pcmk__some_value|pcmk__other_value;

   /* If the values will be used only with uint64_t, define them accordingly,
    * to make compilers happier.
    */
   enum pcmk__something_else {
       pcmk__whatever    = (UINT64_C(1) << 0),
   };

We have convenience functions for checking flags (see ``pcmk_any_flags_set()``,
``pcmk_all_flags_set()``, and ``pcmk_is_set()``) as well as setting and
clearing them (see ``pcmk__set_flags_as()`` and ``pcmk__clear_flags_as()``,
usually used via wrapper macros defined for specific flag groups). These
convenience functions should be preferred to direct bitwise arithmetic, for
readability and logging consistency.


.. index::
   pair: C; booleans
   pair: C; bool
   pair: C; gboolean

Booleans
########

Boolean Types
_____________

Booleans in C can be represented by an integer type, ``bool``, or ``gboolean``.

Integers are sometimes useful for storing booleans when they must be converted
to and from a string, such as an XML attribute value (for which
``crm_element_value_int()`` can be used). Integer booleans use 0 for false and
nonzero (usually 1) for true.

``gboolean`` should be used with glib APIs that specify it. ``gboolean`` should
always be used with glib's ``TRUE`` and ``FALSE`` constants.

Otherwise, ``bool`` should be preferred. ``bool`` should be used with the
``true`` and ``false`` constants from the ``stdbool.h`` header.

Testing Booleans
________________

Do not use equality operators when testing booleans. For example:

.. code-block:: c

   // Do this
   if (bool1) {
       fn();
   }
   if (!bool2) {
       fn2();
   }

   // Not this
   if (bool1 == true) {
       fn();
   }
   if (bool2 == false) {
       fn2();
   }

   // Otherwise there's no logical end ...
   if ((bool1 == false) == true) {
       fn();
   }

Conversely, equality operators *should* be used with non-boolean variables,
even when just testing zero or nonzero:

.. code-block:: c

   int var1 = fn();

   // Prefer this, because it gives a hint to the type when reading it
   if (var1 == 0) {
       fn2();
   }

   // Not this, because a reader could mistakenly assume it is a boolean
   if (!var1) {
       fn2();
   }


.. index::
   pair: C; function

Functions
#########

Function names should be unique across the entire project, to allow for
individual tracing via ``PCMK_trace_functions``, and make it easier to search
code and follow detail logs.


Function Definitions
____________________

.. code-block:: c

   /*
    * (1) The return type goes on its own line
    * (2) The opening brace goes by itself on a line
    * (3) Use "const" with pointer arguments whenever appropriate, to allow the
    *     function to be used by more callers.
    */
   int
   my_func1(const char *s)
   {
       return 0;
   }

   /* Functions with no arguments must explicitly list them as void,
    * for compatibility with strict compilers
    */
   int
   my_func2(void)
   {
       return 0;
   }

   /*
    * (1) For functions with enough arguments that they must break to the next
    *     line, align arguments with the first argument.
    * (2) When a function argument is a function itself, use the pointer form.
    * (3) Declare functions and file-global variables as ``static`` whenever
    *     appropriate. This gains a slight efficiency in shared libraries, and
    *     helps the reader know that it is not used outside the one file.
    */
   static int
   my_func3(int bar, const char *a, const char *b, const char *c,
            void (*callback)())
   {
       return 0;
   }


Return Values
_____________

Functions that need to indicate success or failure should follow one of the
following guidelines. More details, including functions for using them in user
messages and converting from one to another, can be found in
``include/crm/common/results.h``.

* A **standard Pacemaker return code** is one of the ``pcmk_rc_*`` enum values
  or a system errno code, as an ``int``.

* ``crm_exit_t`` (the ``CRM_EX_*`` enum values) is a system-independent code
  suitable for the exit status of a process, or for interchange between nodes.

* Other special-purpose status codes exist, such as ``enum ocf_exitcode`` for
  the possible exit statuses of OCF resource agents (along with some
  Pacemaker-specific extensions). It is usually obvious when the context calls
  for such.

* Some older Pacemaker APIs use the now-deprecated "legacy" return values of
  ``pcmk_ok`` or the positive or negative value of one of the ``pcmk_err_*``
  constants or system errno codes.

* Functions registered with external libraries (as callbacks for example)
  should use the appropriate signature defined by those libraries, rather than
  follow Pacemaker guidelines.

Of course, functions may have return values that aren't success/failure
indicators, such as a pointer, integer count, or bool.


Public API Functions
____________________

Unless we are doing a (rare) release where we break public API compatibility,
new public API functions can be added, but existing function signatures (return
type, name, and argument types) should not be changed. To work around this, an
existing function can become a wrapper for a new function.


.. index::
   pair: C; memory

Memory Management
#################

* Always use ``calloc()`` rather than ``malloc()``. It has no additional cost on
  modern operating systems, and reduces the severity and security risks of
  uninitialized memory usage bugs.

* Ensure that all dynamically allocated memory is freed when no longer needed,
  and not used after it is freed. This can be challenging in the more
  event-driven, callback-oriented sections of code.

* Free dynamically allocated memory using the free function corresponding to
  how it was allocated. For example, use ``free()`` with ``calloc()``, and
  ``g_free()`` with most glib functions that allocate objects.


.. index::
   pair: C; logging
   pair: C; output

Logging and Output
##################

Logging Vs. Output
__________________

Log messages and output messages are logically similar but distinct.
Oversimplifying a bit, daemons log, and tools output.

Log messages are intended to help with troubleshooting and debugging.
They may have a high level of technical detail, and are usually filtered by
severity -- for example, the system log by default gets messages of notice
level and higher.

Output is intended to let the user know what a tool is doing, and is generally
terser and less technical, and may even be parsed by scripts. Output might have
"verbose" and "quiet" modes, but it is not filtered by severity.

Common Guidelines for All Messages
__________________________________

* When format strings are used for derived data types whose implementation may
  vary across platforms (``pid_t``, ``time_t``, etc.), the safest approach is
  to use ``%lld`` in the format string, and cast the value to ``long long``.

* Do not rely on ``%s`` handling ``NULL`` values properly. While the standard
  library functions might, not all functions using printf-style formatting
  does, and it's safest to get in the habit of always ensuring format values
  are non-NULL. If a value can be NULL, the ``pcmk__s()`` function is a
  convenient way to say "this string if not NULL otherwise this default".

* The convenience macros ``pcmk__plural_s()`` and ``pcmk__plural_alt()`` are
  handy when logging a word that may be singular or plural.

Logging
_______

Pacemaker uses libqb for logging, but wraps it with a higher level of
functionality (see ``include/crm/common/logging*h``).

A few macros ``crm_err()``, ``crm_warn()``, etc. do most of the heavy lifting.

By default, Pacemaker sends logs at notice level and higher to the system log,
and logs at info level and higher to the detail log (typically
``/var/log/pacemaker/pacemaker.log``). The intent is that most users will only
ever need the system log, but for deeper troubleshooting and developer
debugging, the detail log may be helpful, at the cost of being more technical
and difficult to follow.

The same message can have more detail in the detail log than in the system log,
using libqb's "extended logging" feature:

.. code-block:: c

   /* The following will log a simple message in the system log, like:

          warning: Action failed: Node not found

      with extra detail in the detail log, like:

          warning: Action failed: Node not found | rc=-1005 id=hgjjg-51006
   */
   crm_warn("Action failed: %s " CRM_XS " rc=%d id=%s",
            pcmk_rc_str(rc), rc, id);


Output
______

Pacemaker has a somewhat complicated system for tool output. The main benefit
is that the user can select the output format with the ``--output-as`` option
(usually "text" for human-friendly output or "xml" for reliably script-parsable
output, though ``crm_mon`` additionally supports "console" and "html").

A custom message can be defined with a unique string identifier, plus
implementation functions for each supported format. The caller invokes the
message using the identifier. The user selects the output format via
``--output-as``, and the output code automatically calls the appropriate
implementation function.

The interface (most importantly ``pcmk__output_t``) is declared in
``include/crm/common/output*h``. See the API comments and existing tools for
examples.


.. index::
   pair: C; strings

String Handling
###############

Define Constants for Magic Strings
__________________________________

A "magic" string is one used for control purposes rather than human reading,
and which must be exactly the same every time it is used. Examples would be
configuration option names, XML attribute names, or environment variable names.

These should always be defined constants, rather than using the string literal
everywhere. If someone mistypes a defined constant, the code won't compile, but
if they mistype a literal, it could go unnoticed until a user runs into a
problem.


Library Functions
_________________

Pacemaker's libcrmcommon has a large number of functions to assist in string
handling. The most commonly used ones are:

* ``pcmk__str_eq()`` tests string equality (similar to ``strcmp()``), but can
  handle NULL, and takes options for case-insensitive, whether NULL should be
  considered a match, etc.
* ``crm_strdup_printf()`` takes ``printf()``-style arguments and creates a
  string from them (dynamically allocated, so it must be freed with
  ``free()``). It asserts on memory failure, so the return value is always
  non-NULL.

String handling functions should almost always be internal API, since Pacemaker
isn't intended to be used as a general-purpose library. Most are declared in
``include/crm/common/strings_internal.h``. ``util.h`` has some older ones that
are public API (for now, but will eventually be made internal).


char*, gchar*, and GString
__________________________

When using dynamically allocated strings, be careful to always use the
appropriate free function.

* ``char*`` strings allocated with something like ``calloc()`` must be freed
  with ``free()``. Most Pacemaker library functions that allocate strings use
  this implementation.
* glib functions often use ``gchar*`` instead, which must be freed with
  ``g_free()``.
* Occasionally, it's convenient to use glib's flexible ``GString*`` type, which
  must be freed with ``g_string_free()``.

.. index::
   pair: C; regular expression

Regular Expressions
###################

- Use ``REG_NOSUB`` with ``regcomp()`` whenever possible, for efficiency.
- Be sure to use ``regfree()`` appropriately.


.. index::
   single: Makefile.am

Makefiles
#########

Pacemaker uses
`automake <https://www.gnu.org/software/automake/manual/automake.html>`_
for building, so the Makefile.am in each directory should be edited rather than
Makefile.in or Makefile, which are automatically generated.

* Public API headers are installed (by adding them to a ``HEADERS`` variable in
  ``Makefile.am``), but internal API headers are not (by adding them to
  ``noinst_HEADERS``).


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
