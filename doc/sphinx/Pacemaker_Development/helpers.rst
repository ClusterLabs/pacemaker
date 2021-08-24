C Development Helpers
---------------------

.. index::
   single: unit testing

Refactoring
###########

Pacemaker uses an optional tool called `coccinelle <https://coccinelle.gitlabpages.inria.fr/website/>`_
to do automatic refactoring.  coccinelle is a very complicated tool that can be
difficult to understand, and the existing documentation makes it pretty tough
to get started.  Much of the documentation is either aimed at kernel developers
or takes the form of grammars.

However, it can apply very complex transformations across an entire source tree.
This is useful for tasks like code refactoring, changing APIs (number or type of
arguments, etc.), catching functions that should not be called, and changing
existing patterns.

coccinelle is driven by input scripts called `semantic patches <https://coccinelle.gitlabpages.inria.fr/website/docs/index.html>`_
written in its own language.  These scripts bear a passing resemblance to source
code patches and tell coccinelle how to match and modify a piece of source
code.  They are stored in ``devel/coccinelle`` and each script either contains
a single source transformation or several related transformations.  In general,
we try to keep these as simple as possible.

In Pacemaker development, we use a couple targets in ``devel/Makefile.am`` to
control coccinelle.  The ``cocci`` target tries to apply each script to every
Pacemaker source file, printing out any changes it would make to the console.
The ``cocci-inplace`` target does the same but also makes those changes to the
source files.  A variety of warnings might also be printed.  If you aren't working
on a new script, these can usually be ignored.

If you are working on a new coccinelle script, it can be useful (and faster) to
skip everything else and only run the new script.  The ``COCCI_FILES`` variable
can be used for this:

.. code-block:: none

   $ make -C devel COCCI_FILES=coccinelle/new-file.cocci cocci

This variable is also used for preventing some coccinelle scripts in the Pacemaker
source tree from running.  Some scripts are disabled because they are not currently
fully working or because they are there as templates.  When adding a new script,
remember to add it to this variable if it should always be run.

One complication when writing coccinelle scripts is that certain Pacemaker source
files may not use private functions (those whose name starts with ``pcmk__``).
Handling this requires work in both the Makefile and in the coccinelle scripts.

The Makefile deals with this by maintaining two lists of source files: those that
may use private functions and those that may not.  For those that may, a special
argument (``-D internal``) is added to the coccinelle command line.  This creates
a virtual dependency named ``internal``.

In the coccinelle scripts, those transformations that modify source code to use
a private function also have a dependency on ``internal``.  If that dependency
was given on the command line, the transformation will be run.  Otherwise, it will
be skipped.

This means that not all instances of an older style of code will be changed after
running a given transformation.  Some developer intervention is still necessary
to know whether a source code block should have been changed or not.

Probably the easiest way to learn how to use coccinelle is by following other
people's scripts.  In addition to the ones in the Pacemaker source directory,
there's several others on the `coccinelle website <https://coccinelle.gitlabpages.inria.fr/website/rules/>`_.

Unit Testing
############

Where possible, changes to the C side of Pacemaker should be accompanied by unit
tests.  Much of Pacemaker cannot effectively be unit tested (and there are other
testing systems used for those parts), but the ``lib`` subdirectory is pretty easy
to write tests for.

Pacemaker uses the `GLib unit testing framework
<https://developer.gnome.org/glib/stable/glib-Testing.html>`_ which looks a lot
like other unit testing frameworks for C and should be fairly familiar.

Organization
____________

Pay close attention to the organization and naming of test cases to ensure the
unit tests continue to work as they should.

Tests are spread throughout the source tree, alongside the source code they test.
For instance, all the tests for the source code in ``lib/common/`` are in the
``lib/common/tests`` directory.  If there is no ``tests`` subdirectory, there are no
tests for that library yet.

Under that directory, there is a ``Makefile.am`` and additional subdirectories.  Each
subdirectory contains the tests for a single library source file.  For instance,
all the tests for ``lib/common/strings.c`` are in the ``lib/common/tests/strings``
directory.  Note that the test subdirectory does not have a ``.c`` suffix.  If there
is no test subdirectory, there are no tests for that file yet.

Finally, under that directory, there is a ``Makefile.am`` and then various source
files.  Each of these source files tests the single function that it is named
after.  For instance, ``lib/common/tests/strings/pcmk__btoa_test.c`` tests the
``pcmk__btoa_test()`` function in ``lib/common/strings.c``.  If there is no test
source file, there are no tests for that function yet.

The ``_test`` suffix on the test source file is important.  All tests have this
suffix, which means all the compiled test cases will also end with this suffix.
That lets us ignore all the compiled tests with a single line in ``.gitignore``:

.. code-block:: none

   /lib/*/tests/*/*_test

Adding a test
_____________

Testing a new function in an already testable source file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Follow these steps if you want to test a function in a source file where there
are already other tested functions.  For the purposes of this example, we will
add a test for the ``pcmk__scan_port()`` function in ``lib/common/strings.c``.  As
you can see, there are already tests for other functions in this same file in
the ``lib/common/tests/strings`` directory.

* cd into ``lib/common/tests/strings``
* Add the new file to the the ``test_programs`` variable in ``Makefile.am``, making
  it something like this:

  .. code-block:: none

      test_programs = pcmk__add_word_test             \
                      pcmk__btoa_test                 \
                      pcmk__scan_port_test

* Create a new ``pcmk__scan_port_test.c`` file, copying the copyright and include
  boilerplate from another file in the same directory.
* Continue with the steps in `Writing the test`_.

Testing a function in a source file without tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Follow these steps if you want to test a function in a source file where there
are not already other tested functions, but there are tests for other files in
the same library.  For the purposes of this example, we will add a test for the
``pcmk_acl_required()`` function in ``lib/common/acls.c``.  At the time of this
documentation being written, no tests existed for that source file, so there
is no ``lib/common/tests/acls`` directory.

* Add to ``AC_CONFIG_FILES`` in the top-level ``configure.ac`` file so the build
  process knows to use directory we're about to create.  That variable would
  now look something like:

  .. code-block:: none

     dnl Other files we output
     AC_CONFIG_FILES(Makefile                                            \
                     ...
                     lib/common/tests/Makefile                           \
                     lib/common/tests/acls/Makefile                      \
                     lib/common/tests/agents/Makefile                    \
                     ...
     )

* cd into ``lib/common/tests``
* Add to the ``SUBDIRS`` variable in ``Makefile.am``, making it something like:

  .. code-block:: none

     SUBDIRS = agents acls cmdline flags operations strings utils xpath results

* Create a new ``acls`` directory, copying the ``Makefile.am`` from some other
  directory.
* cd into ``acls``
* Get rid of any existing values for ``test_programs``, ``dist_test_data``, and
  ``test_data`` in ``Makefile.am``.  Set ``test_programs`` to ``pcmk_acl_required_test``,
  like so:

  .. code-block:: none

     test_programs = pcmk_acl_required_test

* Follow the steps in `Testing a new function in an already testable source file`_
  to create the new ``pcmk_acl_required_test.c`` file.

Testing a function in a library without tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Adding a test case for a function in a library that doesn't have any test cases
to begin with is only slightly more complicated.  In general, the steps are the
same as for the previous section, except with an additional layer of directory
creation.

For the purposes of this example, we will add a test case for the
``lrmd_send_resource_alert()`` function in ``lib/lrmd/lrmd_alerts.c``.  Note that this
may not be a very good function or even library to write actual unit tests for.

* Add to ``AC_CONFIG_FILES`` in the top-level ``configure.ac`` file so the build
  process knows to use directory we're about to create.  That variable would
  now look something like:

  .. code-block:: none

     dnl Other files we output
     AC_CONFIG_FILES(Makefile                                            \
                     ...
                     lib/lrmd/Makefile                                   \
                     lib/lrmd/tests/Makefile                             \
                     lib/services/Makefile                               \
                     ...
     )

* cd into ``lib/lrmd``
* Create a ``SUBDIRS`` variable in ``Makefile.am`` if it doesn't already exist.
  Most libraries should not have this variable already.

  .. code-block:: none

     SUBDIRS = tests

* Create a new ``tests`` directory and add a ``Makefile.am`` with the following
  contents:

  .. code-block:: none

     SUBDIRS = lrmd_alerts

* Follow the steps in `Testing a function in a library without tests` to create
  the rest of the new directory structure.

* Follow the steps in `Testing a new function in an already testable source file`_
  to create the new ``lrmd_send_resource_alert_test.c`` file.

Adding to an existing test case
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If all you need to do is add additional test cases to an existing file, none of
the above work is necessary.  All you need to do is find the test source file
with the name matching your function and add to it and then follow the
instructions in `Writing the test`_.

Writing the test
________________

A test case file contains a fair amount of boilerplate.  For this reason, it's
usually easiest to just copy an existing file and adapt it to your needs.  However,
here's the basic structure:

.. code-block:: c

   /*
    * Copyright 2020-2021 the Pacemaker project contributors
    *
    * The version control history for this file may have further details.
    *
    * This source code is licensed under the GNU Lesser General Public License
    * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
    */

   #include <crm_internal.h>

   #include <glib.h>

   /* Put your test-specific includes here */

   /* Put your test functions here */

   int
   main(int argc, char **argv)
   {
       g_test_init(&argc, &argv, NULL);

       /* Register your test functions here */

       return g_test_run();
   }

Each test-specific function should test one aspect of the library function,
though it can include many assertions if there are many ways of testing that
one aspect.  For instance, there might be multiple ways of testing regular
expression matching:

.. code-block:: c

   static void
   regex(void) {
       const char *s1 = "abcd";
       const char *s2 = "ABCD";

       g_assert_cmpint(pcmk__strcmp(NULL, "a..d", pcmk__str_regex), ==, 1);
       g_assert_cmpint(pcmk__strcmp(s1, NULL, pcmk__str_regex), ==, 1);
       g_assert_cmpint(pcmk__strcmp(s1, "a..d", pcmk__str_regex), ==, 0);
   }

Each test-specific function must also be registered or it will not be called.
This is done with ``g_test_add_func()``.  The first argument is a namespace for
tests.  It's best to look at what is being used elsewhere and try to fit your
new functions in.

.. code-block:: c

   g_test_add_func("/common/strings/strcmp/same_pointer", same_pointer);
   g_test_add_func("/common/strings/strcmp/one_is_null", one_is_null);
   g_test_add_func("/common/strings/strcmp/case_matters", case_matters);
   g_test_add_func("/common/strings/strcmp/case_insensitive", case_insensitive);
   g_test_add_func("/common/strings/strcmp/regex", regex);

Finally, be careful when calling the ``g_assert_`` functions.  They are adding
new functions all the time, but we can't use functions newer than the minimum
version of glib supported by Pacemaker.  Luckily, they do a good job of marking
when each function was introduced.  The minimum glib version can be found in
``configure.ac``:

.. code-block:: none

    $ grep -A 1 "Require minimum glib" configure.ac
    # Require minimum glib version
    PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.42.0],

Running
_______

If you had to create any new files or directories, you will first need to run
``./configure`` from the top level of the source directory.  This will regenerate
the Makefiles throughout the tree.  If you skip this step, your changes will be
skipped and you'll be left wondering why the output doesn't match what you
expected.

To run the tests, simply run ``make check`` after previously building the source
with ``make``.  The test cases in each directory will be built and then run.
This should not take long.  If all the tests succeed, you will be back at the
prompt.  Scrolling back through the history, you should see lines like the
following:

.. code-block:: none

    PASS: pcmk__strcmp_test 1 /common/strings/strcmp/same_pointer
    PASS: pcmk__strcmp_test 2 /common/strings/strcmp/one_is_null
    PASS: pcmk__strcmp_test 3 /common/strings/strcmp/case_matters
    PASS: pcmk__strcmp_test 4 /common/strings/strcmp/case_insensitive
    PASS: pcmk__strcmp_test 5 /common/strings/strcmp/regex
    ============================================================================
    Testsuite summary for pacemaker 2.1.0
    ============================================================================
    # TOTAL: 33
    # PASS:  33
    # SKIP:  0
    # XFAIL: 0
    # FAIL:  0
    # XPASS: 0
    # ERROR: 0
    ============================================================================
    make[7]: Leaving directory '/home/clumens/src/pacemaker/lib/common/tests/strings'

The testing process will quit on the first failed test, and you will see lines
like these:

.. code-block:: none

   ERROR: pcmk__scan_double_test - Bail out! ERROR:pcmk__scan_double_test.c:77:trailing_chars: assertion failed (fabs(result - 3.0) < DBL_EPSILON): (1 < 2.22044605e-16)
   PASS: pcmk__str_any_of_test 1 /common/strings/any_of/empty_list
   PASS: pcmk__str_any_of_test 2 /common/strings/any_of/empty_string
   PASS: pcmk__str_any_of_test 3 /common/strings/any_of/in
   PASS: pcmk__str_any_of_test 4 /common/strings/any_of/not_in
   PASS: pcmk__strcmp_test 1 /common/strings/strcmp/same_pointer
   PASS: pcmk__strcmp_test 2 /common/strings/strcmp/one_is_null
   PASS: pcmk__strcmp_test 3 /common/strings/strcmp/case_matters
   PASS: pcmk__strcmp_test 4 /common/strings/strcmp/case_insensitive
   PASS: pcmk__strcmp_test 5 /common/strings/strcmp/regex
   ============================================================================
   Testsuite summary for pacemaker 2.1.0
   ============================================================================
   # TOTAL: 30
   # PASS:  29
   # SKIP:  0
   # XFAIL: 0
   # FAIL:  0
   # XPASS: 0
   # ERROR: 1
   ============================================================================
   See lib/common/tests/strings/test-suite.log
   Please report to users@clusterlabs.org
   ============================================================================
   make[7]: *** [Makefile:1218: test-suite.log] Error 1
   make[7]: Leaving directory '/home/clumens/src/pacemaker/lib/common/tests/strings'

The ``ERROR`` line indicates which test failed, the line the failure occurred on,
and the test result that caused a failure.  For this test case, the result is a
little hard to understand because floating point numbers are involved.  It is
basically saying that it expected ``result`` to be ``3.0``, but this was not the case.

At this point, you need to determine whether your test case is incorrect or
whether the code being tested is incorrect.  Fix whichever is wrong and continue.

Test case failures are usually much easier to understand, for instance:

.. code-block:: none

   ERROR: pcmk__strcmp_test - Bail out! ERROR:pcmk__strcmp_test.c:64:regex: assertion failed (pcmk__strcmp(NULL, "a..d", pcmk__str_regex) == 2): (1 == 2)
