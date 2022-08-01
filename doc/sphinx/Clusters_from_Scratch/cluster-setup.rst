Set up a Cluster
----------------

Simplify Administration With a Cluster Shell
############################################

In the dark past, configuring Pacemaker required the administrator to
read and write XML.  In true UNIX style, there were also a number of
different commands that specialized in different aspects of querying
and updating the cluster.

In addition, the various components of the cluster stack (corosync, pacemaker,
etc.) had to be configured separately, with different configuration tools and
formats.

All of that has been greatly simplified with the creation of higher-level tools,
whether command-line or GUIs, that hide all the mess underneath.

Command-line cluster shells take all the individual aspects required for
managing and configuring a cluster, and pack them into one simple-to-use
command-line tool.

They even allow you to queue up several changes at once and commit
them all at once.

Two popular command-line shells are ``pcs`` and ``crmsh``. Clusters from Scratch is
based on ``pcs`` because it comes with |CFS_DISTRO|, but both have similar
functionality. Choosing a shell or GUI is a matter of personal preference and
what comes with (and perhaps is supported by) your choice of operating system.


Install the Cluster Software
############################

Fire up a shell on both nodes and run the following to activate the High
Availability repo.

.. code-block:: none

    # dnf config-manager --set-enabled highavailability

.. IMPORTANT::

    This document will show commands that need to be executed on both nodes
    with a simple ``#`` prompt. Be sure to run them on each node individually.

Now, we'll install pacemaker, pcs, and some other command-line tools that will
make our lives easier:

.. code-block:: none

    # dnf install -y pacemaker pcs psmisc policycoreutils-python3
    
.. NOTE::

    This document uses ``pcs`` for cluster management. Other alternatives,
    such as ``crmsh``, are available, but their syntax
    will differ from the examples used here.

Configure the Cluster Software
##############################

.. index::
   single: firewall

Allow cluster services through firewall
_______________________________________

On each node, allow cluster-related services through the local firewall:

.. code-block:: none

    # firewall-cmd --permanent --add-service=high-availability
    success
    # firewall-cmd --reload
    success

.. NOTE ::

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

        [root@pcmk-1 ~]# setenforce 0
        [root@pcmk-1 ~]# sed -i.bak "s/SELINUX=enforcing/SELINUX=permissive/g" /etc/selinux/config
        [root@pcmk-1 ~]# systemctl mask firewalld.service
        [root@pcmk-1 ~]# systemctl stop firewalld.service
        [root@pcmk-1 ~]# iptables --flush

Enable pcs Daemon
_________________

Before the cluster can be configured, the pcs daemon must be started and enabled
to start at boot time on each node. This daemon works with the pcs command-line interface
to manage synchronizing the corosync configuration across all nodes in the
cluster, among other functions.

Start and enable the daemon by issuing the following commands on each node:

.. code-block:: none

    # systemctl start pcsd.service
    # systemctl enable pcsd.service
    Created symlink from /etc/systemd/system/multi-user.target.wants/pcsd.service to /usr/lib/systemd/system/pcsd.service.

The installed packages will create an **hacluster** user with a disabled password.
While this is fine for running ``pcs`` commands locally,
the account needs a login password in order to perform such tasks as syncing
the corosync configuration, or starting and stopping the cluster on other nodes.

This tutorial will make use of such commands,
so now we will set a password for the **hacluster** user, using the same password
on both nodes:

.. code-block:: none

    # passwd hacluster
    Changing password for user hacluster.
    New password:
    Retype new password:
    passwd: all authentication tokens updated successfully.

.. NOTE::

    Alternatively, to script this process or set the password on a
    different machine from the one you're logged into, you can use
    the ``--stdin`` option for ``passwd``:

    .. code-block:: none

        [root@pcmk-1 ~]# ssh pcmk-2 -- 'echo mysupersecretpassword | passwd --stdin hacluster'

Configure Corosync
__________________

On either node, use ``pcs host auth`` to authenticate as the **hacluster** user:

.. code-block:: none

    [root@pcmk-1 ~]# pcs host auth pcmk-1 pcmk-2
    Username: hacluster
    Password:
    pcmk-2: Authorized
    pcmk-1: Authorized

Next, use ``pcs cluster setup`` on the same node to generate and synchronize the
corosync configuration:

.. code-block:: none

    [root@pcmk-1 ~]# pcs cluster setup mycluster pcmk-1 pcmk-2
    No addresses specified for host 'pcmk-1', using 'pcmk-1'
    No addresses specified for host 'pcmk-2', using 'pcmk-2'
    Destroying cluster on hosts: 'pcmk-1', 'pcmk-2'...
    pcmk-2: Successfully destroyed cluster
    pcmk-1: Successfully destroyed cluster
    Requesting remove 'pcsd settings' from 'pcmk-1', 'pcmk-2'
    pcmk-1: successful removal of the file 'pcsd settings'
    pcmk-2: successful removal of the file 'pcsd settings'
    Sending 'corosync authkey', 'pacemaker authkey' to 'pcmk-1', 'pcmk-2'
    pcmk-1: successful distribution of the file 'corosync authkey'
    pcmk-1: successful distribution of the file 'pacemaker authkey'
    pcmk-2: successful distribution of the file 'corosync authkey'
    pcmk-2: successful distribution of the file 'pacemaker authkey'
    Sending 'corosync.conf' to 'pcmk-1', 'pcmk-2'
    pcmk-1: successful distribution of the file 'corosync.conf'
    pcmk-2: successful distribution of the file 'corosync.conf'
    Cluster has been successfully set up.

.. NOTE::

    If you'd like, you can specify an **addr** option for each node in the 
    ``pcs cluster setup`` command. This will create an explicit name-to-address
    mapping for each node in ``/etc/corosync/corosync.conf``, eliminating the
    need for hostname resolution via DNS, ``/etc/hosts``, and the like.

    .. code-block:: none

        [root@pcmk-1 ~]# pcs cluster setup mycluster \
            pcmk-1 addr=192.168.122.101 pcmk-2 addr=192.168.122.102


If you received an authorization error for either of those commands, make
sure you configured the **hacluster** user account on each node
with the same password.

The final corosync.conf configuration on each node should look
something like the sample in :ref:`sample-corosync-configuration`.

Explore pcs
###########

Start by taking some time to familiarize yourself with what ``pcs`` can do.

.. code-block:: none

    [root@pcmk-1 ~]# pcs
    
    Usage: pcs [-f file] [-h] [commands]...
    Control and configure pacemaker and corosync.
    
    Options:
        -h, --help         Display usage and exit.
        -f file            Perform actions on file instead of active CIB.
                           Commands supporting the option use the initial state of
                           the specified file as their input and then overwrite the
                           file with the state reflecting the requested
                           operation(s).
                           A few commands only use the specified file in read-only
                           mode since their effect is not a CIB modification.
        --debug            Print all network traffic and external commands run.
        --version          Print pcs version information. List pcs capabilities if
                           --full is specified.
        --request-timeout  Timeout for each outgoing request to another node in
                           seconds. Default is 60s.
        --force            Override checks and errors, the exact behavior depends on
                           the command. WARNING: Using the --force option is
                           strongly discouraged unless you know what you are doing.

    Commands:
        cluster     Configure cluster options and nodes.
        resource    Manage cluster resources.
        stonith     Manage fence devices.
        constraint  Manage resource constraints.
        property    Manage pacemaker properties.
        acl         Manage pacemaker access control lists.
        qdevice     Manage quorum device provider on the local host.
        quorum      Manage cluster quorum settings.
        booth       Manage booth (cluster ticket manager).
        status      View cluster status.
        config      View and manage cluster configuration.
        pcsd        Manage pcs daemon.
        host        Manage hosts known to pcs/pcsd.
        node        Manage cluster nodes.
        alert       Manage pacemaker alerts.
        client      Manage pcsd client configuration.
        dr          Manage disaster recovery configuration.
        tag         Manage pacemaker tags.


As you can see, the different aspects of cluster management are separated
into categories. To discover the functionality available in each of these
categories, one can issue the command ``pcs <CATEGORY> help``.  Below is an
example of all the options available under the status category.

.. code-block:: none

    [root@pcmk-1 ~]# pcs status help

    Usage: pcs status [commands]...
    View current cluster and resource status
    Commands:
        [status] [--full] [--hide-inactive]
            View all information about the cluster and resources (--full provides
            more details, --hide-inactive hides inactive resources).

        resources [<resource id | tag id>] [node=<node>] [--hide-inactive]
            Show status of all currently configured resources. If --hide-inactive
            is specified, only show active resources.  If a resource or tag id is
            specified, only show status of the specified resource or resources in
            the specified tag. If node is specified, only show status of resources
            configured for the specified node.

        cluster
            View current cluster status.

        corosync
            View current membership information as seen by corosync.

        quorum
            View current quorum status.

        qdevice <device model> [--full] [<cluster name>]
            Show runtime status of specified model of quorum device provider.  Using
            --full will give more detailed output.  If <cluster name> is specified,
            only information about the specified cluster will be displayed.

        booth
            Print current status of booth on the local node.

        nodes [corosync | both | config]
            View current status of nodes from pacemaker. If 'corosync' is
            specified, view current status of nodes from corosync instead. If
            'both' is specified, view current status of nodes from both corosync &
            pacemaker. If 'config' is specified, print nodes from corosync &
            pacemaker configuration.

        pcsd [<node>]...
            Show current status of pcsd on nodes specified, or on all nodes
            configured in the local cluster if no nodes are specified.

        xml
            View xml version of status (output from crm_mon -r -1 -X).

Additionally, if you are interested in the version and supported cluster stack(s)
available with your Pacemaker installation, run:

.. code-block:: none

    [root@pcmk-1 ~]# pacemakerd --features
     Pacemaker 2.1.2-4.el9 (Build: ada5c3b36e2)
     Supporting v3.13.0: agent-manpages cibsecrets corosync-ge-2 default-concurrent-fencing default-resource-stickiness default-sbd-sync generated-manpages monotonic nagios ncurses remote systemd
