.. index::
   pair: documentation; guidelines

Documentation Guidelines
------------------------

See `doc/README.md
<https://github.com/ClusterLabs/pacemaker/blob/main/doc/README.md>`_ in the
source code repository for the kinds of documentation that Pacemaker provides.

Books
#####

The ``doc/sphinx`` subdirectory has a subdirectory for each book by title. Each
book's directory contains .rst files, which are the chapter sources in
`reStructuredText
<https://www.sphinx-doc.org/en/master/usage/restructuredtext/>`_ format (with
index.rst as the starting point).

Once you have edited the sources as desired, run ``make`` in the ``doc`` or
``doc/sphinx`` directory to generate all the books locally. You can view the
results by pointing your web browser to (replacing PATH\_TO\_CHECKOUT and
BOOK\_TITLE appropriately):

    file:///PATH_TO_CHECKOUT/doc/sphinx/BOOK_TITLE/_build/html/index.html

See the comments at the top of ``doc/sphinx/Makefile.am`` for options you can
use.

Recommended practices:

* Use ``list-table`` instead of ``table`` for tables
* When documenting newly added features and syntax, add "\*(since X.Y.Z)\*"
  with the version introducing them. These comments can be removed when rolling
  upgrades from that version are no longer supported.
