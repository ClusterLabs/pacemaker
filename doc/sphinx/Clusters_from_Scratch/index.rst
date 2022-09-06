Clusters from Scratch
=====================

*Step-by-Step Instructions for Building Your First High-Availability Cluster*


Abstract
--------
This document provides a step-by-step guide to building a simple high-availability
cluster using Pacemaker.

The example cluster will use:

* |CFS_DISTRO| |CFS_DISTRO_VER| as the host operating system
* Corosync to provide messaging and membership services
* Pacemaker 2 as the cluster resource manager
* DRBD as a cost-effective alternative to shared storage
* GFS2 as the cluster filesystem (in active/active mode)

Given the graphical nature of the install process, a number of screenshots are
included. However, the guide is primarily composed of commands, the reasons for
executing them, and their expected outputs.


Table of Contents
-----------------

.. toctree::
   :maxdepth: 3
   :numbered:

   intro
   installation
   cluster-setup
   verification
   fencing
   active-passive
   apache
   shared-storage
   active-active
   ap-configuration
   ap-corosync-conf
   ap-reading

Index
-----

* :ref:`genindex`
* :ref:`search`
