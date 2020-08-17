.. index::
   single: cluster layer

The Cluster Layer
-----------------

Pacemaker and the Cluster Layer
###############################

Pacemaker utilizes an underlying cluster layer for two purposes:

* obtaining quorum
* messaging between nodes

Currently, only Corosync 2 and later is supported for this layer.

.. index::
   single: cluster layer; Corosync
   single: Corosync

Managing Nodes in a Corosync-Based Cluster
##########################################

.. index::
   pair: Corosync; add cluster node

Adding a New Corosync Node
__________________________

To add a new node:

#. Install Corosync and Pacemaker on the new host.
#. Copy ``/etc/corosync/corosync.conf`` and ``/etc/corosync/authkey`` (if it
   exists) from an existing node. You may need to modify the ``mcastaddr``
   option to match the new node's IP address.
#. Start the cluster software on the new host. If a log message containing
   "Invalid digest" appears from Corosync, the keys are not consistent between
   the machines.

.. index::
   pair: Corosync; remove cluster node

Removing a Corosync Node
________________________

Because the messaging and membership layers are the authoritative
source for cluster nodes, deleting them from the CIB is not a complete
solution.  First, one must arrange for corosync to forget about the
node (**pcmk-1** in the example below).

#. Stop the cluster on the host to be removed. How to do this will vary with
   your operating system and installed versions of cluster software, for example,
   ``pcs cluster stop`` if you are using pcs for cluster management.
#. From one of the remaining active cluster nodes, tell Pacemaker to forget
   about the removed host, which will also delete the node from the CIB:

   .. code-block:: none

      # crm_node -R pcmk-1

.. index::
   pair: Corosync; replace cluster node

Replacing a Corosync Node
_________________________

To replace an existing cluster node:

#. Make sure the old node is completely stopped.
#. Give the new machine the same hostname and IP address as the old one.
#. Follow the procedure above for adding a node.
