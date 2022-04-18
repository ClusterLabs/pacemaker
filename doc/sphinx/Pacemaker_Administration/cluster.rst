.. index::
   single: cluster layer

The Cluster Layer
-----------------

Pacemaker utilizes an underlying cluster layer for two purposes:

* obtaining quorum
* messaging between nodes

.. index::
   single: cluster layer; Corosync
   single: Corosync

Currently, only Corosync 2 and later is supported for this layer.

This document assumes you have configured the cluster nodes in Corosync
already. High-level cluster management tools are available that can configure
Corosync for you. If you want the lower-level details, see the
`Corosync documentation <https://corosync.github.io/corosync/>`_.
