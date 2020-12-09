Advanced Hacking on the Project
-------------------------------

Foreword
########

This chapter aims to be a gentle introduction (or perhaps, rather a
summarization of advanced techniques we developed for backreferences) to how
deal with the Pacemaker internals effectively. For instance, how to:

* debug with an ease
* verify various interesting interaction-based properties

or simply put, all that is in the interest of the core contributors on the
project to know, master, and (preferably) also evolve -- way beyond what is in
the presumed repertoire of a generic contributor role, which is detailed in
other chapters of this guide.

Therefore, if you think you will not benefit from any such details
in the scope of this chapter, feel free to skip it.


Debugging
#########

In the GNU userland tradition, preferred way of debugging is based on ``gdb``
(directly or via specific frontends atop) that is widely available on platforms
(semi-)supported with Pacemaker itself.

To make some advanced debugging easier, we maintain a script defining some
useful helpers in ``devel/gdbhelpers`` file, which you can make available
in the debugging session easily when invoking it as
``gdb -x <path-to-gdbhelpers> ...``.

From within the debugger, you can then invoke the new ``pcmk`` command that
will guide you regarding other helper functions available, so we won't
replicate that here.


Working with mocked daemons
###########################

Since the Pacemaker run-time consists of multiple co-operating daemons
as detailed elsewhere, tracking down the interaction details amongst
them can be rather cumbersome.  Since rebuilding existing daemons in
a more modular way as opposed to clusters of mutually dependent
functions, we elected to grow separate bare-bones counterparts built
evolutionary as skeletons just to get the basic (long-term stabilized)
communication with typical daemon clients going, and to add new modules
in their outer circles (plus minimalistic hook support at those cores)
on a demand-driven basis.

The code for these is located at ``maint/mocked``; for instance,
``based-notifyfenced.c`` module of ``based.c`` skeleton mocking
``pacemaker-based`` daemon was exactly to fulfill investigation helper
role (the case at hand was also an impulse to kick off this very
sort of maintenance support material, to begin with).

Non-trivial knowledge of Pacemaker internals and other skills are
needed to use such devised helpers, but given the other way around,
some sorts of investigation may be even heftier, it may be the least
effort choice.  And when that's the case, advanced contributors are
expected to contribute their own extensions they used to validate
the reproducibility/actual correctness of the fix along the actual
code modifications.  This way, the rest of the development teams is
not required to deal with elaborate preconditions, be at guess, or
even forced to use a blind faith regarding the causes, consequences
and validity regarding the raised issues/fixes, for the greater
benefit of all.
