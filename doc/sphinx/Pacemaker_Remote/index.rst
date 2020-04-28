Pacemaker Remote
================

*Scaling High Availablity Clusters*


Abstract
--------
This document exists as both a reference and deployment guide for the Pacemaker
Remote service.

The example commands in this document will use:

* |REMOTE_DISTRO| |REMOTE_DISTRO_VER| as the host operating system
* Pacemaker Remote to perform resource management within guest nodes and remote nodes
* KVM for virtualization
* libvirt to manage guest nodes
* Corosync to provide messaging and membership services on cluster nodes
* Pacemaker 1.1.16 [#]_ to perform resource management on cluster nodes

* pcs as the cluster configuration toolset

The concepts are the same for other distributions, virtualization platforms,
toolsets, and messaging layers, and should be easily adaptable.


Table of Contents
-----------------

.. toctree::
   :maxdepth: 3
   :numbered:

   intro
   example
   options
   kvm-tutorial
   baremetal-tutorial
   alternatives

Index
-----

* :ref:`genindex`
* :ref:`search`

.. [#] While this guide is part of the document set for Pacemaker 2.0, it
       demonstrates the version available in the standard |REMOTE_DISTRO| repositories
