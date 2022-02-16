Frequently Asked Questions
--------------------------

:Q: Who is this document intended for?

:A: Anyone who wishes to read and/or edit the Pacemaker source code.
    Casual contributors should feel free to read just this FAQ, and
    consult other chapters as needed.

----

.. index::
   single: download
   single: source code
   single: git
   single: git; GitHub

:Q: Where is the source code for Pacemaker?
:A: The `source code for Pacemaker <https://github.com/ClusterLabs/pacemaker>`_ is
    kept on `GitHub <https://github.com/>`_, as are all software projects under the
    `ClusterLabs <https://github.com/ClusterLabs>`_ umbrella. Pacemaker uses
    `Git <https://git-scm.com/>`_ for source code management. If you are a Git newbie,
    the `gittutorial(7) man page <http://schacon.github.io/git/gittutorial.html>`_
    is an excellent starting point. If you're familiar with using Git from the
    command line, you can create a local copy of the Pacemaker source code with:
    **git clone https://github.com/ClusterLabs/pacemaker.git**

----

.. index::
   single: git; branch

:Q: What are the different Git branches and repositories used for?
:A: * The `main branch <https://github.com/ClusterLabs/pacemaker/tree/main>`_
      is the primary branch used for development.
    * The `2.1 branch <https://github.com/ClusterLabs/pacemaker/tree/2.1>`_ is
      the current release branch. Normally, it does not receive any changes, but
      during the release cycle for a new release, it will contain release
      candidates. During the release cycle, certain bug fixes will go to the
      2.1 branch first (and be pulled into main later).
    * The `2.0 branch <https://github.com/ClusterLabs/pacemaker/tree/2.0>`_,
      `1.1 branch <https://github.com/ClusterLabs/pacemaker/tree/1.1>`_,
      and separate
      `1.0 repository <https://github.com/ClusterLabs/pacemaker-1.0>`_
      are frozen snapshots of earlier release series, no longer being developed.
    * Messages will be posted to the
      `developers@ClusterLabs.org <https://lists.ClusterLabs.org/mailman/listinfo/developers>`_
      mailing list during the release cycle, with instructions about which
      branches to use when submitting requests.

----

:Q: How do I build from the source code?
:A: See `INSTALL.md <https://github.com/ClusterLabs/pacemaker/blob/main/INSTALL.md>`_
    in the main checkout directory.

----

:Q: What coding style should I follow?
:A: You'll be mostly fine if you simply follow the example of existing code.
    When unsure, see the relevant chapter of this document for language-specific
    recommendations. Pacemaker has grown and evolved organically over many years,
    so you will see much code that doesn't conform to the current guidelines. We
    discourage making changes solely to bring code into conformance, as any change
    requires developer time for review and opens the possibility of adding bugs.
    However, new code should follow the guidelines, and it is fine to bring lines
    of older code into conformance when modifying that code for other reasons.

----

.. index::
   single: git; commit message

:Q: How should I format my Git commit messages?
:A: An example is "Feature: scheduler: wobble the frizzle better".
   
    * The first part is the type of change, used to automatically generate the
      change log for the next release. Commit messages with the following will
      be included in the change log:

      * **Feature** for new features
      * **Fix** for bug fixes (**Bug** or **High** also work)
      * **API** for changes to the public API

      Everything else will *not* automatically be in the change log, and so
      don't really matter, but types commonly used include:

      * **Log** for changes to log messages or handling
      * **Doc** for changes to documentation or comments
      * **Test** for changes in CTS and regression tests
      * **Low**, **Med**, or **Mid** for bug fixes not significant enough for a
        change log entry
      * **Refactor** for refactoring-only code changes
      * **Build** for build process changes
    
    * The next part is the name of the component(s) being changed, for example,
      **controller** or **libcrmcommon** (it's more free-form, so don't sweat
      getting it exact).
    
    * The rest briefly describes the change. The git project recommends the
      entire summary line stay under 50 characters, but more is fine if needed
      for clarity.
      
    * Except for the most simple and obvious of changes, the summary should be
      followed by a blank line and a longer explanation of *why* the change was
      made.  

----

:Q: How can I test my changes?
:A: The source repository has some unit tests for simple functions, though this
    is a recent effort without much coverage yet. Pacemaker's Cluster Test
    Suite (CTS) has regression tests for most major components; these will
    automatically be run for any pull requests submitted through GitHub, and
    are sufficient for most changes. Additionally, CTS has a lab component that
    can be used to set up a test cluster and run a wide variety of complex
    tests, for testing major changes. See cts/README.md in the source
    repository for details.

----

.. index:: license

:Q: What is Pacemaker's license?
:A: Except where noted otherwise in the file itself, the source code for all
    Pacemaker programs is licensed under version 2 or later of the GNU General
    Public License (`GPLv2+ <https://www.gnu.org/licenses/gpl-2.0.html>`_), its
    headers, libraries, and native language translations under version 2.1 or
    later of the less restrictive GNU Lesser General Public License
    (`LGPLv2.1+ <https://www.gnu.org/licenses/lgpl-2.1.html>`_),
    its documentation under version 4.0 or later of the
    Creative Commons Attribution-ShareAlike International Public License
    (`CC-BY-SA-4.0 <https://creativecommons.org/licenses/by-sa/4.0/legalcode>`_),
    and its init scripts under the
    `Revised BSD <https://opensource.org/licenses/BSD-3-Clause>`_ license. If you find
    any deviations from this policy, or wish to inquire about alternate licensing
    arrangements, please e-mail the
    `developers@ClusterLabs.org <https://lists.ClusterLabs.org/mailman/listinfo/developers>`_
    mailing list. Licensing issues are also discussed on the
    `ClusterLabs wiki <https://wiki.ClusterLabs.org/wiki/License>`_.

----

:Q: How can I contribute my changes to the project?
:A: Contributions of bug fixes or new features are very much appreciated!
    Patches can be submitted as
    `pull requests <https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests>`_
    via GitHub (the preferred method, due to its excellent
    `features <https://github.com/features/>`_), or e-mailed to the
    `developers@ClusterLabs.org <https://lists.ClusterLabs.org/mailman/listinfo/developers>`_
    mailing list as an attachment in a format Git can import. Authors may only
    submit changes that they have the right to submit under the open source
    license indicated in the affected files.

----

.. index:: mailing list

:Q: What if I still have questions?
:A: Ask on the
    `developers@ClusterLabs.org <https://lists.ClusterLabs.org/mailman/listinfo/developers>`_
    mailing list for development-related questions, or on the
    `users@ClusterLabs.org <https://lists.ClusterLabs.org/mailman/listinfo/users>`_
    mailing list for general questions about using Pacemaker.
    Developers often also hang out on the
    [ClusterLabs IRC channel](https://wiki.clusterlabs.org/wiki/ClusterLabs_IRC_channel).
