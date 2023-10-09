""" Cause the Pacemaker Remote connection resource to fail """

__all__ = ["RemoteRscFailure"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.remotedriver import RemoteDriver

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class RemoteRscFailure(RemoteDriver):
    """ A concrete test that causes the Pacemaker Remote connection resource
        to fail
    """

    def __init__(self, cm):
        """ Create a new RemoteRscFailure instance

            Arguments:

            cm -- A ClusterManager instance
        """

        RemoteDriver.__init__(self, cm)
        self.name = "RemoteRscFailure"

    def __call__(self, node):
        """ Perform this test """

        if not self.start_new_test(node):
            return self.failure(self.fail_string)

        # This is an important step. We are migrating the connection
        # before failing the resource. This verifies that the migration
        # has properly maintained control over the remote-node.
        self.migrate_connection(node)

        self.fail_rsc(node)
        self.cleanup_metal(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()
        if self.failed:
            return self.failure(self.fail_string)

        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"schedulerd.*: Recover\s+remote-rsc\s+\(.*\)",
                 r"Dummy.*: No process state file found" ] + super().errors_to_ignore

    def is_applicable(self):
        """ Return True if this test is applicable in the current test configuration. """

        if not RemoteDriver.is_applicable(self):
            return False

        # This test requires at least three nodes: one to convert to a
        # remote node, one to host the connection originally, and one
        # to migrate the connection to.
        return len(self._env["nodes"]) >= 3
