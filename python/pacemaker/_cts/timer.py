"""Timer-related utilities for CTS."""

__all__ = ["Timer"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import time

from pacemaker._cts import logging


class Timer:
    """
    A class for measuring the runtime of some task.

    A Timer may be used manually or as a context manager, like so:

        with Timer("SomeTest", "SomeTimer"):
            ...

    A Timer runs from when start() is called until the timer is deleted or
    reset() is called.  There is no explicit stop method.
    """

    def __init__(self, test_name, timer_name):
        """
        Create a new Timer instance.

        Arguments:
        test_name   -- The name of the test this timer is being run for
        timer_name  -- The name of this timer
        """
        self._start_time = None
        self._test_name = test_name
        self._timer_name = timer_name

    def __enter__(self):
        """When used as a context manager, start the timer."""
        self.start()
        return self

    def __exit__(self, *args):
        """When used as a context manager, log the elapsed time."""
        logging.debug(f"{self._test_name}:{self._timer_name} runtime: {self.elapsed:.2f}")

    def reset(self):
        """Restart the timer."""
        self.start()

    def start(self):
        """Start the timer."""
        self._start_time = time.time()

    @property
    def start_time(self):
        """Return when the timer started."""
        return self._start_time

    @property
    def elapsed(self):
        """Return how long the timer has been running for."""
        return time.time() - self._start_time
