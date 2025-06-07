"""A module for managing cluster resources."""

__all__ = ["list_standards"]
__copyright__ = "Copyright 2025 the Pacemaker project contributors"
__license__ = "GNU Lesser General Public License version 2.1 or later (LGPLv2.1+)"

import libxml2

import _pcmksupport
from pacemaker.exceptions import PacemakerError


def list_standards():
    """Return a list of supported resource standards."""
    try:
        xml = _pcmksupport.list_standards()
    except _pcmksupport.PacemakerError as e:
        raise PacemakerError(*e.args) from None

    doc = libxml2.xmlDoc(xml)

    return [item.getContent() for item in doc.xpathEval("/pacemaker-result/standards/item")]
