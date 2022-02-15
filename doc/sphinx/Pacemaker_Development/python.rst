.. index::
   single: Python
   pair: Python; guidelines

Python Coding Guidelines
------------------------

.. index::
   pair: Python; boilerplate
   pair: license; Python
   pair: copyright; Python

.. _s-python-boilerplate:

Python Boilerplate
##################

If a Python file is meant to be executed (as opposed to imported), it should
have a ``.in`` extension, and its first line should be:

.. code-block:: python

   #!@PYTHON@

which will be replaced with the appropriate python executable when Pacemaker is
built. To make that happen, add an entry to ``CONFIG_FILES_EXEC()`` in
``configure.ac``, and add the file name without ``.in`` to ``.gitignore`` (see
existing examples).

After the above line if any, every Python file should start like this:

.. code-block:: python

   """ <BRIEF-DESCRIPTION>
   """

   __copyright__ = "Copyright <YYYY[-YYYY]> the Pacemaker project contributors"
   __license__ = "<LICENSE> WITHOUT ANY WARRANTY"

*<BRIEF-DESCRIPTION>* is obviously a brief description of the file's
purpose. The string may contain any other information typically used in
a Python file `docstring <https://www.python.org/dev/peps/pep-0257/>`_.

``<LICENSE>`` should follow the policy set forth in the
`COPYING <https://github.com/ClusterLabs/pacemaker/blob/main/COPYING>`_ file,
generally one of "GNU General Public License version 2 or later (GPLv2+)"
or "GNU Lesser General Public License version 2.1 or later (LGPLv2.1+)".


.. index::
   single: Python; 3
   single: Python; version

Python Version Compatibility
############################

Pacemaker targets compatibility with Python 3.4 and later.

Do not use features not available in all targeted Python versions. An
example is the ``subprocess.run()`` function.


.. index::
   pair: Python; whitespace

Formatting Python Code
######################

* Indentation must be 4 spaces, no tabs.
* Do not leave trailing whitespace.
* Lines should be no longer than 80 characters unless limiting line length
  significantly impacts readability. For Python, this limitation is
  flexible since breaking a line often impacts readability, but
  definitely keep it under 120 characters.
* Where not conflicting with this style guide, it is recommended (but not
  required) to follow `PEP 8 <https://www.python.org/dev/peps/pep-0008/>`_.
* It is recommended (but not required) to format Python code such that
  ``pylint
  --disable=line-too-long,too-many-lines,too-many-instance-attributes,too-many-arguments,too-many-statements``
  produces minimal complaints (even better if you don't need to disable all
  those checks).
