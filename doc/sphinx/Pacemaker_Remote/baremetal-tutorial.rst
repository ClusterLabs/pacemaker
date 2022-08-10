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

Configure Cluster Nodes
#######################

This walk-through assumes you already have a Pacemaker cluster configured. For examples, we will use a cluster with two cluster nodes named pcmk-1 and pcmk-2. You can substitute whatever your node names are, for however many nodes you have. If you are not familiar with setting up basic Pacemaker clusters, follow the walk-through in the Clusters From Scratch document before attempting this one.

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

    If you are using some other firewall solution besides firewalld,
    simply open the following ports, which can be used by various
    clustering components: TCP ports 2224, 3121, and 21064.

    If you run into any problems during testing, you might want to disable
    the firewall and SELinux entirely until you have everything working.
    This may create significant security issues and should not be performed on
    machines that will be exposed to the outside world, but may be appropriate
    during development and testing on a protected host.

    To disable security measures:

    .. code-block:: none

        # setenforce 0
        # sed -i.bak "s/SELINUX=enforcing/SELINUX=permissive/g" \
            /etc/selinux/config
        # systemctl mask firewalld.service
        # systemctl stop firewalld.service

Configure ``/etc/hosts``
________________________

You will need to add the remote node's hostname (we're using **remote1** in
this tutorial) to the cluster nodes' ``/etc/hosts`` files if you haven't already.
This is required unless you have DNS set up in a way where remote1's address can be
discovered.

For each remote node, execute the following on each cluster node and on the
remote nodes, replacing the IP address with the actual IP address of the remote
node.

.. code-block:: none

    # cat << END >> /etc/hosts
    192.168.122.10  remote1
    END

Also add entries for each cluster node to the ``/etc/hosts`` file on each
remote node. For example:

.. code-block:: none

   # cat << END >> /etc/hosts
   192.168.122.101  pcmk-1
   192.168.122.102  pcmk-2
   END

Configure pacemaker_remote on Remote Node
_________________________________________

Install the pacemaker_remote daemon on the remote node.

.. code-block:: none

    # yum install -y pacemaker-remote resource-agents pcs

Prepare ``pcsd``
________________

Now we need to prepare ``pcsd`` on the remote node so that we can use ``pcs``
commands to communicate with it.

Start and enable the ``pcsd`` daemon on the remote node.

.. code-block:: none

    [root@remote1 ~]# systemctl start pcsd
    [root@remote1 ~]# systemctl enable pcsd
    Created symlink /etc/systemd/system/multi-user.target.wants/pcsd.service → /usr/lib/systemd/system/pcsd.service.

Next, set a password for the ``hacluster`` user on the remote node

.. code-block:: none

    [root@remote ~]# echo MyPassword | passwd --stdin hacluster
    Changing password for user hacluster.
    passwd: all authentication tokens updated successfully.

Now authenticate the existing cluster nodes to ``pcsd`` on the remote node. The
below command only needs to be run from one cluster node.

.. code-block:: none

    [root@pcmk-1 ~]# pcs host auth remote1 -u hacluster
    Password: 
    remote1: Authorized

Integrate Remote Node into Cluster
__________________________________

Integrating a remote node into the cluster is achieved through the
creation of a remote node connection resource. The remote node connection
resource both establishes the connection to the remote node and defines that
the remote node exists. Note that this resource is actually internal to
Pacemaker's controller. The metadata for this resource can be found in
the ``/usr/lib/ocf/resource.d/pacemaker/remote`` file. The metadata in this file
describes what options are available, but there is no actual
**ocf:pacemaker:remote** resource agent script that performs any work.

Define the remote node connection resource to our remote node,
**remote1**, using the following command on any cluster node. This
command creates the ocf:pacemaker:remote resource; creates the authkey if it
does not exist already and distributes it to the remote node; and starts and
enables ``pacemaker-remoted`` on the remote node.

.. code-block:: none

    [root@pcmk-1 ~]# pcs cluster node add-remote remote1
    No addresses specified for host 'remote1', using 'remote1'
    Sending 'pacemaker authkey' to 'remote1'
    remote1: successful distribution of the file 'pacemaker authkey'
    Requesting 'pacemaker_remote enable', 'pacemaker_remote start' on 'remote1'
    remote1: successful run of 'pacemaker_remote enable'
    remote1: successful run of 'pacemaker_remote start'

That's it.  After a moment you should see the remote node come online. The final ``pcs status`` output should look something like this, and you can see that it
created the ocf:pacemaker:remote resource:

.. code-block:: none

    # pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-1 (version 2.0.5-8.el8-ba59be7122) - partition with quorum
      * Last updated: Wed Mar  3 11:02:03 2021
      * Last change:  Wed Mar  3 11:01:57 2021 by root via cibadmin on pcmk-1
      * 3 nodes configured
      * 1 resource instance configured
    
    Node List:
      * Online: [ pcmk-1 pcmk-2 ]
      * RemoteOnline: [ remote1 ]
    
    Full List of Resources:
      * remote1	(ocf::pacemaker:remote):	 Started pcmk-1

How pcs Configures the Remote
#############################

To see that it created the key and copied it to all cluster nodes and the
remote node, run:

.. code-block:: none

    # ls -l /etc/pacemaker

To see that it enables pacemaker_remote, run:

.. code-block:: none

    # systemctl status pacemaker_remote
    ● pacemaker_remote.service - Pacemaker Remote executor daemon
       Loaded: loaded (/usr/lib/systemd/system/pacemaker_remote.service; enabled; vendor preset: disabled)
       Active: active (running) since Tue 2021-03-02 10:42:40 EST; 1min 23s ago
         Docs: man:pacemaker-remoted
               https://clusterlabs.org/pacemaker/doc/
     Main PID: 1139 (pacemaker-remot)
        Tasks: 1
       Memory: 5.4M
       CGroup: /system.slice/pacemaker_remote.service
               └─1139 /usr/sbin/pacemaker-remoted
    
    Mar 02 10:42:40 remote1 systemd[1]: Started Pacemaker Remote executor daemon.
    Mar 02 10:42:40 remote1 pacemaker-remoted[1139]:  notice: Additional logging available in /var/log/pacemaker/pacemaker.log
    Mar 02 10:42:40 remote1 pacemaker-remoted[1139]:  notice: Starting Pacemaker remote executor
    Mar 02 10:42:41 remote1 pacemaker-remoted[1139]:  notice: Pacemaker remote executor successfully started and accepting connections

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
``crm_attribute``, etc.) to work on remote nodes natively.

Try it: Run ``crm_mon`` on the remote node after pacemaker has
integrated it into the cluster. These tools just work. These means resource
agents such as promotable resources (which need access to tools like
``crm_attribute``) work seamlessly on the remote nodes.

Higher-level command shells such as ``pcs`` may have partial support
on remote nodes, but it is recommended to run them from a cluster node.

Troubleshooting a Remote Connection
###################################

Note: This section should not be done when the remote is connected to the cluster.

Should connectivity issues occur, it can be worth verifying that the cluster nodes
can contact the remote node on port 3121. Here's a trick you can use.
Connect using ssh from each of the cluster nodes. The connection will get
destroyed, but how it is destroyed tells you whether it worked or not.

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
cluster nodes, you may move on to setting up Pacemaker on the
cluster nodes.
