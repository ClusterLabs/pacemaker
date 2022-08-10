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

    [root@remote1 ~]# dnf config-manager --set-enabled highavailability
    [root@remote1 ~]# dnf install -y pacemaker-remote resource-agents pcs

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

    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-1 (version 2.1.2-4.el9-ada5c3b36e2) - partition with quorum
      * Last updated: Wed Aug 10 05:17:28 2022
      * Last change:  Wed Aug 10 05:17:26 2022 by root via cibadmin on pcmk-1
      * 3 nodes configured
      * 2 resource instances configured

    Node List:
      * Online: [ pcmk-1 pcmk-2 ]
      * RemoteOnline: [ remote1 ]

    Full List of Resources:
      * xvm	(stonith:fence_xvm):	 Started pcmk-1
      * remote1	(ocf:pacemaker:remote):	 Started pcmk-1

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

How pcs Configures the Remote
#############################

Let's take a closer look at what the ``pcs cluster node add-remote`` command is
doing. There is no need to run any of the commands in this section.

First, ``pcs`` copies the Pacemaker authkey file to the VM that will become the
guest. If an authkey is not already present on the cluster nodes, this command
creates one and distributes it to the existing nodes and to the guest.

If you want to do this manually, you can run a command like the following to
generate an authkey in ``/etc/pacemaker/authkey``, and then distribute the key
to the rest of the nodes and to the new guest.

.. code-block:: none

    [root@pcmk-1 ~]# dd if=/dev/urandom of=/etc/pacemaker/authkey bs=4096 count=1

Then ``pcs`` starts and enables the ``pacemaker_remote`` service on the guest.
If you want to do this manually, run the following commands.

.. code-block:: none

    [root@guest1 ~]# systemctl start pacemaker_remote
    [root@guest1 ~]# systemctl enable pacemaker_remote

Starting Resources on Remote Node
#################################

Once the remote node is integrated into the cluster, starting and managing
resources on a remote node is the exact same as on cluster nodes. Refer to the
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

If connectivity issues occur, it's worth verifying that the cluster nodes can
communicate with the remote node on TCP port 3121. We can use the ``nc`` command
to test the connection.

On the cluster nodes, install the package that provides the ``nc`` command. The
package name may vary by distribution; on |REMOTE_DISTRO| |REMOTE_DISTRO_VER|
it's ``nmap-ncat``.

Now connect using ``nc`` from each of the cluster nodes to the remote node and
run a ``/bin/true`` command that does nothing except return success. No output
indicates that the cluster node is able to communicate with the remote node on
TCP port 3121. An error indicates that the connection failed. This could be due
to a network issue or because ``pacemaker-remoted`` is not currently running on
the remote node.

Example of success:

.. code-block:: none

    [root@pcmk-1 ~]# nc remote1 3121 --sh-exec /bin/true
    [root@pcmk-1 ~]#

Examples of failure:

.. code-block:: none

    [root@pcmk-1 ~]# nc remote1 3121 --sh-exec /bin/true
    Ncat: Connection refused.
    [root@pcmk-1 ~]# nc remote1 3121 --sh-exec /bin/true
    Ncat: No route to host.

