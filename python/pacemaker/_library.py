"""A module providing private library management code."""

__all__ = ["_libcrmcommon"]
__copyright__ = "Copyright 2024-2025 the Pacemaker project contributors"
__license__ = "GNU Lesser General Public License version 2.1 or later (LGPLv2.1+)"

import ctypes
from ctypes.util import find_library
from glob import glob
import os

from pacemaker.buildoptions import BuildOptions


def load_library(basename):
    """Find and load the library with the given base name."""
    path = find_library(basename)

    # If the library was not found anywhere in the default locations, also search
    # for it in the build directory
    if path is None:
        # pylint: disable=protected-access
        for d in glob(f"{BuildOptions._BUILD_DIR}/lib/*/.libs"):
            path = f"{d}/lib{basename}.so"

            if os.path.exists(path):
                break

            path = None

    if path is None:
        raise FileNotFoundError(basename)

    return ctypes.cdll.LoadLibrary(path)


_libcrmcommon = load_library("crmcommon")
_libcrmcommon.crm_exit_str.restype = ctypes.c_char_p
