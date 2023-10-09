""" Timer-related utilities for CTS """

__all__ = ["Timer"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import time

class Timer:
    """ A class for measuring the runtime of some task.  A Timer may be used
        manually or as a context manager, like so:

        with Timer(logger, "SomeTest", "SomeTimer"):
            ...

        A Timer runs from when start() is called until the timer is deleted
        or reset() is called.  There is no explicit stop method.
    """

    def __init__(self, logger, test_name, timer_name):
        """ Create a new Timer instance.

            Arguments:

            logger      -- A Logger instance that can be used to record when
                           the timer stopped
            test_name   -- The name of the test this timer is being run for
            timer_name  -- The name of this timer
        """

        self._logger = logger
        self._start_time = None
        self._test_name = test_name
        self._timer_name = timer_name

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self._logger.debug("%s:%s runtime: %.2f" % (self._test_name, self._timer_name, self.elapsed))

    def reset(self):
        """ Restart the timer """

        self.start()

    def start(self):
        """ Start the timer """

        self._start_time = time.time()

    @property
    def start_time(self):
        """ When did the timer start? """

        return self._start_time

    @property
    def elapsed(self):
        """ How long has the timer been running for? """

        return time.time() - self._start_time
