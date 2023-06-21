""" Start and stop a remote node """

__all__ = ["RemoteBasic"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.remotedriver import RemoteDriver


class RemoteBasic(RemoteDriver):
    """ A concrete test that starts and stops a remote node """

    def __init__(self, cm):
        """ Create a new RemoteBasic instance

            Arguments:

            cm -- A ClusterManager instance
        """

        RemoteDriver.__init__(self, cm)

        self.name = "RemoteBasic"

    def __call__(self, node):
        """ Perform this test """

        if not self.start_new_test(node):
            return self.failure(self.fail_string)

        self.test_attributes(node)
        self.cleanup_metal(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()
        if self.failed:
            return self.failure(self.fail_string)

        return self.success()
