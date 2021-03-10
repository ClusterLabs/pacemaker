.. index::
   single: remote node; walk-through

Remote Node Walk-through
------------------------

**What this tutorial is:** An in-depth walk-through of how to get Pacemaker to
integrate a remote node into the cluster as a node capable of running cluster
resources.

**What this tutorial is not:** A realistic deployment scenario. The steps shown
here are meant to get users familiar with the concept of remote nodes as
quickly as possible.

This tutorial requires three machines: two to act as cluster nodes, and
a third to act as the remote node.

Configure Remote Node
#####################

.. index::
   single: remote node; firewall

Configure Firewall on Remote Node
_________________________________

Allow cluster-related services through the local firewall:

.. code-block:: none

    # firewall-cmd --permanent --add-service=high-availability
    success
    # firewall-cmd --reload
    success

.. NOTE::

    If you are using iptables directly, or some other firewall solution besides
    firewalld, simply open the following ports, which can be used by various
    clustering components: TCP ports 2224, 3121, and 21064, and UDP port 5405.

    If you run into any problems during testing, you might want to disable
    the firewall and SELinux entirely until you have everything working.
    This may create significant security issues and should not be performed on
    machines that will be exposed to the outside world, but may be appropriate
    during development and testing on a protected host.

    To disable security measures:

    .. code-block:: none

        # setenforce 0
        # sed -i.bak "s/SELINUX=enforcing/SELINUX=permissive/g" /etc/selinux/config
        # systemctl mask firewalld.service
        # systemctl stop firewalld.service
        # iptables --flush

Configure pacemaker_remote on Remote Node
_________________________________________

Install the pacemaker_remote daemon on the remote node.

.. code-block:: none

    # yum install -y pacemaker-remote resource-agents pcs

Create a location for the shared authentication key:

.. code-block:: none

    # mkdir -p --mode=0750 /etc/pacemaker
    # chgrp haclient /etc/pacemaker

All nodes (both cluster nodes and remote nodes) must have the same
authentication key installed for the communication to work correctly.
If you already have a key on an existing node, copy it to the new
remote node. Otherwise, create a new key, for example:

.. code-block:: none

    # dd if=/dev/urandom of=/etc/pacemaker/authkey bs=4096 count=1

Now start and enable the pacemaker_remote daemon on the remote node.

.. code-block:: none

    # systemctl enable pacemaker_remote.service
    # systemctl start pacemaker_remote.service

Verify the start is successful.

.. code-block:: none

    # systemctl status pacemaker_remote
    ● pacemaker_remote.service - Pacemaker Remote executor daemon
       Loaded: loaded (/usr/lib/systemd/system/pacemaker_remote.service; enabled; vendor preset: disabled)
       Active: active (running) since Tue 2021-03-02 10:42:40 EST; 1min 23s ago
         Docs: man:pacemaker-remoted
               https://clusterlabs.org/pacemaker/doc/en-US/Pacemaker/2.0/html-single/Pacemaker_Remote/index.html
     Main PID: 1139 (pacemaker-remot)
        Tasks: 1
       Memory: 5.4M
       CGroup: /system.slice/pacemaker_remote.service
               └─1139 /usr/sbin/pacemaker-remoted
    
    Mar 02 10:42:40 remote1 systemd[1]: Started Pacemaker Remote executor daemon.
    Mar 02 10:42:40 remote1 pacemaker-remoted[1139]:  notice: Additional logging available in /var/log/pacemaker/pacemaker.log
    Mar 02 10:42:40 remote1 pacemaker-remoted[1139]:  notice: Starting Pacemaker remote executor
    Mar 02 10:42:41 remote1 pacemaker-remoted[1139]:  notice: Pacemaker remote executor successfully started and accepting connections


Verify Connection to Remote Node
################################

Before moving forward, it's worth verifying that the cluster nodes
can contact the remote node on port 3121. Here's a trick you can use.
Connect using ssh from each of the cluster nodes. The connection will get
destroyed, but how it is destroyed tells you whether it worked or not.

First, add the remote node's hostname (we're using **remote1** in this tutorial)
to the cluster nodes' ``/etc/hosts`` files if you haven't already. This
is required unless you have DNS set up in a way where remote1's address can be
discovered.

Execute the following on each cluster node, replacing the IP address with the
actual IP address of the remote node.

.. code-block:: none

    # cat << END >> /etc/hosts
    192.168.122.10    remote1
    END

If running the ssh command on one of the cluster nodes results in this
output before disconnecting, the connection works:

.. code-block:: none

    # ssh -p 3121 remote1
    ssh_exchange_identification: read: Connection reset by peer

If you see one of these, the connection is not working:

.. code-block:: none

    # ssh -p 3121 remote1
    ssh: connect to host remote1 port 3121: No route to host

.. code-block:: none

    # ssh -p 3121 remote1
    ssh: connect to host remote1 port 3121: Connection refused

Once you can successfully connect to the remote node from the both
cluster nodes, move on to setting up Pacemaker on the cluster nodes.

Configure Cluster Nodes
#######################

Configure Firewall on Cluster Nodes
___________________________________

On each cluster node, allow cluster-related services through the local
firewall, following the same procedure as in `Configure Firewall on Remote Node`_.

Install Pacemaker on Cluster Nodes
__________________________________

On the two cluster nodes, install the following packages.

.. code-block:: none

    # yum install -y pacemaker corosync pcs resource-agents

Copy Authentication Key to Cluster Nodes
________________________________________

Create a location for the shared authentication key,
and copy it from any existing node:

.. code-block:: none

    # mkdir -p --mode=0750 /etc/pacemaker
    # chgrp haclient /etc/pacemaker
    # scp remote1:/etc/pacemaker/authkey /etc/pacemaker/authkey

Configure Corosync on Cluster Nodes
___________________________________

Corosync handles Pacemaker's cluster membership and messaging. The corosync
config file is located in ``/etc/corosync/corosync.conf``. That config file must be
initialized with information about the two cluster nodes before pacemaker can
start.

To initialize the corosync config file, execute the following pcs command on
both nodes, filling in the information in <> with your nodes' information.

.. code-block:: none

    # pcs cluster setup --force --local --name mycluster <node1 ip or hostname> <node2 ip or hostname>

Start Pacemaker on Cluster Nodes
________________________________

Start the cluster stack on both cluster nodes using the following command.

.. code-block:: none

    # pcs cluster start

Verify corosync membership

.. code-block:: none

    # pcs status corosync
    Membership information
    ----------------------
        Nodeid      Votes Name
             1          1 node1 (local)
             2          1 node2

Verify Pacemaker status. At first, the ``pcs cluster status`` output will look
like this.

.. code-block:: none

    # pcs status
    Cluster name: mycluster
    
    WARNINGS:
    No stonith devices and stonith-enabled is not false
    
    Cluster Summary:
      * Stack: corosync
      * Current DC: NONE
      * Last updated: Wed Mar  3 10:47:03 2021
      * Last change:  Tue Mar  2 15:42:26 2021 by hacluster via crmd on node1
      * 2 nodes configured
      * 0 resource instances configured
    
    Node List:
      * Node node1: UNCLEAN (offline)
      * Node node2: UNCLEAN (offline)
    
    Full List of Resources:
      * No resources

After about a minute, you should see your two cluster nodes come online.

.. code-block:: none

    # pcs status
    Cluster name: mycluster
    
    WARNINGS:
    No stonith devices and stonith-enabled is not false
    
    Cluster Summary:
      * Stack: corosync
      * Current DC: node1 (version 2.0.5-8.el8-ba59be7122) - partition with quorum
      * Last updated: Wed Mar  3 10:47:03 2021
      * Last change:  Tue Mar  2 15:42:26 2021 by hacluster via crmd on node1
      * 2 nodes configured
      * 0 resource instances configured
    
    Node List:
      * Online: [ node1 node2 ]
    
    Full List of Resources:
      * No resources

For the sake of this tutorial, we are going to disable stonith to avoid having
to cover fencing device configuration.

.. code-block:: none

    # pcs property set stonith-enabled=false

Integrate Remote Node into Cluster
##################################

Integrating a remote node into the cluster is achieved through the
creation of a remote node connection resource. The remote node connection
resource both establishes the connection to the remote node and defines that
the remote node exists. Note that this resource is actually internal to
Pacemaker's controller. A metadata file for this resource can be found in
the ``/usr/lib/ocf/resource.d/pacemaker/remote`` file that describes what options
are available, but there is no actual **ocf:pacemaker:remote** resource agent
script that performs any work.

Before we integrate the remote node, we'll need to authorize it.
.. code-block:: none
    # pcs host auth remote1

Now, define the remote node connection resource to our remote node,
**remote1**, using the following command on any cluster node.

.. code-block:: none
    # pcs cluster node add-remote remote1

That's it.  After a moment you should see the remote node come online.

.. code-block:: none
    # pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: node1 (version 2.0.5-8.el8-ba59be7122) - partition with quorum
      * Last updated: Wed Mar  3 11:02:03 2021
      * Last change:  Wed Mar  3 11:01:57 2021 by root via cibadmin on node1
      * 3 nodes configured
      * 1 resource instance configured
    
    Node List:
      * Online: [ node1 node2 ]
      * RemoteOnline: [ remote1 ]
    
    Full List of Resources:
      * remote1	(ocf::pacemaker:remote):	 Started node1

Starting Resources on Remote Node
#################################

Once the remote node is integrated into the cluster, starting resources on a
remote node is the exact same as on cluster nodes. Refer to the
`Clusters from Scratch <http://clusterlabs.org/doc/>`_ document for examples of
resource creation.

.. WARNING::

    Never involve a remote node connection resource in a resource group,
    colocation constraint, or order constraint.


.. index::
   single: remote node; fencing

Fencing Remote Nodes
####################

Remote nodes are fenced the same way as cluster nodes. No special
considerations are required. Configure fencing resources for use with
remote nodes the same as you would with cluster nodes.

Note, however, that remote nodes can never 'initiate' a fencing action. Only
cluster nodes are capable of actually executing a fencing operation against
another node.

Accessing Cluster Tools from a Remote Node
##########################################

Besides allowing the cluster to manage resources on a remote node,
pacemaker_remote has one other trick. The pacemaker_remote daemon allows
nearly all the pacemaker tools (``crm_resource``, ``crm_mon``,
``crm_attribute``, ``crm_master``, etc.) to work on remote nodes natively.

Try it: Run ``crm_mon`` on the remote node after pacemaker has
integrated it into the cluster. These tools just work. These means resource
agents such as promotable resources (which need access to tools like
``crm_master``) work seamlessly on the remote nodes.

Higher-level command shells such as ``pcs`` may have partial support
on remote nodes, but it is recommended to run them from a cluster node.
