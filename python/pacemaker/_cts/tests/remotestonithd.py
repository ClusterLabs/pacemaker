""" Fail the connection resource and fence the remote node """

__all__ = ["RemoteStonithd"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.remotedriver import RemoteDriver


class RemoteStonithd(RemoteDriver):
    """ A concrete test that fails the connection resource and fences the
        remote node
    """

    def __init__(self, cm):
        """ Create a new RemoteStonithd instance

            Arguments:

            cm -- A ClusterManager instance
        """

        RemoteDriver.__init__(self, cm)

        self.name = "RemoteStonithd"

    def __call__(self, node):
        """ Perform this test """

        if not self.start_new_test(node):
            return self.failure(self.fail_string)

        self.fail_connection(node)
        self.cleanup_metal(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()
        if self.failed:
            return self.failure(self.fail_string)

        return self.success()

    def is_applicable(self):
        """ Return True if this test is applicable in the current test configuration. """

        if not RemoteDriver.is_applicable(self):
            return False

        return self._env.get("DoFencing", True)

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"Lost connection to Pacemaker Remote node",
                 r"Software caused connection abort",
                 r"pacemaker-controld.*:\s+error.*: Operation remote-.*_monitor",
                 r"pacemaker-controld.*:\s+error.*: Result of monitor operation for remote-.*",
                 r"schedulerd.*:\s+Recover\s+remote-.*\s+\(.*\)",
                 r"error: Result of monitor operation for .* on remote-.*: Internal communication failure" ] + super().errors_to_ignore
