# Copyright 2009-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU Lesser General Public License
# version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.

import os

from pacemaker.exitstatus import ExitStatus

class Test(object):
    """ The base class for a single regression test.  A single regression test
        may still run multiple commands as part of its execution.
    """

    def __init__(self, name, description, **kwargs):
        """ Create a new Test instance.  This method must be provided by all
            subclasses, which must call Test.__init__ first.

            Arguments:

            description -- A user-readable description of the test, helpful in
                           identifying what test is running or has failed.
            name        -- The name of the test.  Command line tools use this
                           attribute to allow running only tests with the exact
                           name, or tests whose name matches a given pattern.
                           This should be unique among all tests.

            Keyword arguments:

            force_wait  --
            logdir      -- The base directory under which to create a directory
                           to store output and temporary data.
            timeout     -- How long to wait for the test to complete.
            verbose     -- Whether to print additional information, including
                           verbose command output and daemon log files.
        """

        self.description = description
        self.executed = False
        self.name = name

        self.force_wait = kwargs.get("force_wait", False)
        self.logdir = kwargs.get("logdir", "/tmp")
        self.timeout = kwargs.get("timeout", 2)
        self.verbose = kwargs.get("verbose", False)

        self._cmds = []
        self._daemon_location = None
        self._result_exitcode = ExitStatus.OK
        self._result_txt = ""
        self._stonith_process = None

    ###
    ### PROPERTIES
    ###

    @property
    def exitcode(self):
        """ The final exitcode of the Test.  If all commands pass, this property
            will be ExitStatus.OK.  Otherwise, this property will be the exitcode
            of the first command to fail.
        """
        return self._result_exitcode

    @exitcode.setter
    def exitcode(self, value):
        self._result_exitcode = value

    @property
    def logpath(self):
        """ The path to the log for whatever daemon is being tested.  Note that
            this requires all subclasses to sef self._daemon_location before
            accessing this property or an exception will be raised.
        """
        return os.path.join(self.logdir, self._daemon_location + ".log")
