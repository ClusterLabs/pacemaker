Introduction
------------

The Scope of This Document
##########################

Computer clusters can be used to provide highly available services or
resources. The redundancy of multiple machines is used to guard
against failures of many types.

This document will walk through the installation and setup of simple
clusters using the |CFS_DISTRO| distribution, version |CFS_DISTRO_VER|.

The clusters described here will use Pacemaker and Corosync to provide
resource management and messaging. Required packages and modifications
to their configuration files are described along with the use of the
``pcs`` command line tool for generating the XML used for cluster
control.

Pacemaker is a central component and provides the resource management
required in these systems. This management includes detecting and
recovering from the failure of various nodes, resources, and services
under its control.

When more in-depth information is required, and for real-world usage,
please refer to the `Pacemaker Explained <https://www.clusterlabs.org/pacemaker/doc/>`_
manual.

.. include:: ../shared/pacemaker-intro.rst
