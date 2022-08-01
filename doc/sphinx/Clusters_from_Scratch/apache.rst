.. index::
    single: Apache HTTP Server

Add Apache HTTP Server as a Cluster Service
-------------------------------------------

Now that we have a basic but functional active/passive two-node cluster,
we're ready to add some real services. We're going to start with
Apache HTTP Server because it is a feature of many clusters and is relatively
simple to configure.

Install Apache
##############

Before continuing, we need to make sure Apache is installed on both
hosts. We will also allow the cluster to use the **wget** tool (this is the
default, but **curl** is also supported) to check the status of the Apache
server. We'll install **httpd** (Apache) and **wget** now.

.. code-block:: none

    # yum install -y httpd wget
    # firewall-cmd --permanent --add-service=http
    # firewall-cmd --reload

.. IMPORTANT::

    Do **not** enable the httpd service. Services that are intended to
    be managed via the cluster software should never be managed by the OS.
    It is often useful, however, to manually start the service, verify that
    it works, then stop it again, before adding it to the cluster. This
    allows you to resolve any non-cluster-related problems before continuing.
    Since this is a simple example, we'll skip that step here.

Create Website Documents
########################

We need to create a page for Apache to serve. On |CFS_DISTRO| |CFS_DISTRO_VER|, the
default Apache document root is ``/var/www/html``, so we'll create an index
file there. For the moment, we will simplify things by serving a static site
and manually synchronizing the data between the two nodes, so run this command
on both nodes:

.. code-block:: none

    # cat <<-END >/var/www/html/index.html
     <html>
     <body>My Test Site - $(hostname)</body>
     </html>
    END


.. index::
    single: Apache HTTP Server; status URL

Enable the Apache Status URL
############################

Pacemaker uses the **apache** resource agent to monitor the health of your
Apache instance via the ``server-status`` URL, and to recover the instance if
it fails. On both nodes, configure this URL as follows:

.. code-block:: none

    # cat <<-END >/etc/httpd/conf.d/status.conf
     <Location /server-status>
        SetHandler server-status
        Require local
     </Location>
    END

.. NOTE::

    If you are using a different operating system, server-status may already be
    enabled or may be configurable in a different location. If you are using
    a version of Apache HTTP Server less than 2.4, the syntax will be different.


.. index::
    pair: Apache HTTP Server; resource

Configure the Cluster
#####################

At this point, Apache is ready to go, and all that needs to be done is to
add it to the cluster. Let's call the resource WebSite. We need to use
an OCF resource agent called apache in the heartbeat namespace [#]_.
The script's only required parameter is the path to the main Apache
configuration file, and we'll tell the cluster to check once a
minute that Apache is still running.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource create WebSite ocf:heartbeat:apache  \
          configfile=/etc/httpd/conf/httpd.conf \
          statusurl="http://localhost/server-status" \
          op monitor interval=1min

By default, the operation timeout for all resources' start, stop, monitor, and
other operations is 20 seconds. In many cases, this timeout period is less than
a particular resource's advised timeout period. For the purposes of this
tutorial, we will adjust the global operation timeout default to 240 seconds.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource op defaults update timeout=240s
    Warning: Defaults do not apply to resources which override them with their own defined values
    [root@pcmk-1 ~]# pcs resource op defaults
    timeout: 240s

.. NOTE::

    In a production cluster, it is usually better to adjust each resource's
    start, stop, and monitor timeouts to values that are appropriate for
    the behavior observed in your environment, rather than adjusting
    the global default.

.. NOTE::

    If you use a tool like ``pcs`` to create a resource, its operations may be
    automatically configured with explicit timeout values that override the
    Pacemaker built-in default value of 20 seconds. If the resource agent's
    metadata contains suggested values for the operation timeouts in a
    particular format, ``pcs`` reads those values and adds them to the
    configuration at resource creation time.

After a short delay, we should see the cluster start Apache.

.. code-block:: none

    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-2 (version 2.0.5-4.el8-ba59be7122) - partition with quorum
      * Last updated: Tue Jan 26 19:38:22 2021
      * Last change:  Tue Jan 26 19:38:19 2021 by root via cibadmin on pcmk-1
      * 2 nodes configured
      * 2 resource instances configured
    
    Node List:
      * Online: [ pcmk-1 pcmk-2 ]
    
    Full List of Resources:
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-2
      * WebSite		(ocf::heartbeat:apache):	 Started pcmk-1

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

Wait a moment, the WebSite resource isn't running on the same host as our
IP address!

.. NOTE::

    If, in the ``pcs status`` output, you see the WebSite resource has
    failed to start, then you've likely not enabled the status URL correctly.
    You can check whether this is the problem by running:

    .. code-block:: none

        wget -O - http://localhost/server-status

    If you see **Not Found** or **Forbidden** in the output, then this is likely the
    problem.  Ensure that the **<Location /server-status>** block is correct.

.. index::
    single: constraint; colocation
    single: colocation constraint

Ensure Resources Run on the Same Host
#####################################

To reduce the load on any one machine, Pacemaker will generally try to
spread the configured resources across the cluster nodes. However, we
can tell the cluster that two resources are related and need to run on
the same host (or else one of them should not run at all, if they cannot run on
the same node). Here, we instruct the cluster that WebSite can only run on the
host where ClusterIP is active.

To achieve this, we use a *colocation constraint* that indicates it is
mandatory for WebSite to run on the same node as ClusterIP. The
"mandatory" part of the colocation constraint is indicated by using a
score of INFINITY. The INFINITY score also means that if ClusterIP is not
active anywhere, WebSite will not be permitted to run.

.. NOTE::

    If ClusterIP is not active anywhere, WebSite will not be permitted to run
    anywhere.

.. NOTE::

    INFINITY is the default score for a colocation constraint. If you don't
    specify a score, INFINITY will be used automatically.

.. IMPORTANT::

    Colocation constraints are "directional", in that they imply certain
    things about the order in which the two resources will have a location
    chosen. In this case, we're saying that **WebSite** needs to be placed on the
    same machine as **ClusterIP**, which implies that the cluster must know the
    location of **ClusterIP** before choosing a location for **WebSite**.

.. code-block:: none

    [root@pcmk-1 ~]# pcs constraint colocation add WebSite with ClusterIP INFINITY
    [root@pcmk-1 ~]# pcs constraint
    Location Constraints:
    Ordering Constraints:
    Colocation Constraints:
      WebSite with ClusterIP (score:INFINITY)
    Ticket Constraints:
    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-2 (version 2.0.5-4.el8-ba59be7122) - partition with quorum
      * Last updated: Tue Jan 26 19:45:11 2021
      * Last change:  Tue Jan 26 19:44:30 2021 by root via cibadmin on pcmk-1
      * 2 nodes configured
      * 2 resource instances configured
    
    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-2
      * WebSite		(ocf::heartbeat:apache):	 Started pcmk-2


    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled


.. index::
    single: constraint; ordering
    single: ordering constraint

Ensure Resources Start and Stop in Order
########################################

Like many services, Apache can be configured to bind to specific
IP addresses on a host or to the wildcard IP address. If Apache
binds to the wildcard, it doesn't matter whether an IP address
is added before or after Apache starts; Apache will respond on
that IP just the same. However, if Apache binds only to certain IP
address(es), the order matters: If the address is added after Apache
starts, Apache won't respond on that address.

To be sure our WebSite responds regardless of Apache's address configuration,
we need to make sure ClusterIP not only runs on the same node,
but also starts before WebSite. A colocation constraint ensures only that the
resources run together; it doesn't affect order in which the resources are
started or stopped.

We do this by adding an ordering constraint. By default, all order constraints
are mandatory. This means, for example, that if ClusterIP needs to stop, then
WebSite must stop first (or already be stopped); and if WebSite needs to start,
then ClusterIP must start first (or already be started). This also implies that
the recovery of ClusterIP will trigger the recovery of WebSite, causing it to
be restarted.

.. code-block:: none

    [root@pcmk-1 ~]# pcs constraint order ClusterIP then WebSite
    Adding ClusterIP WebSite (kind: Mandatory) (Options: first-action=start then-action=start)
    [root@pcmk-1 ~]# pcs constraint
    Location Constraints:
    Ordering Constraints:
      start ClusterIP then start WebSite (kind:Mandatory)
    Colocation Constraints:
      WebSite with ClusterIP (score:INFINITY)
    Ticket Constraints:

.. NOTE::

    The default action in an order constraint is **start**. If you don't
    specify an action, as in the example above, **pcs** automatically uses the
    **start** action.


.. index::
    single: constraint; location
    single: location constraint

Prefer One Node Over Another
############################

Pacemaker does not rely on any sort of hardware symmetry between nodes,
so it may well be that one machine is more powerful than the other.

In such cases, you may want to host the resources on the more powerful node
when it is available, to have the best performance -- or you may want to host
the resources on the **less** powerful node when it's available, so you don't
have to worry about whether you can handle the load after a failover.

To do this, we create a location constraint.

In the location constraint below, we are saying the WebSite resource
prefers the node pcmk-1 with a score of 50.  Here, the score indicates
how strongly we'd like the resource to run at this location.

.. code-block:: none

    [root@pcmk-1 ~]# pcs constraint location WebSite prefers pcmk-1=50
    [root@pcmk-1 ~]# pcs constraint
    Location Constraints:
      Resource: WebSite
        Enabled on: pcmk-1 (score:50)
    Ordering Constraints:
      start ClusterIP then start WebSite (kind:Mandatory)
    Colocation Constraints:
      WebSite with ClusterIP (score:INFINITY)
    Ticket Constraints:
    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-2 (version 2.0.5-4.el8-ba59be7122) - partition with quorum
      * Last updated: Tue Jan 26 19:46:52 2021
      * Last change:  Tue Jan 26 19:46:40 2021 by root via cibadmin on pcmk-1
      * 2 nodes configured
      * 2 resource instances configured
    
    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-2
      * WebSite		(ocf::heartbeat:apache):	 Started pcmk-2

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

Wait a minute, the resources are still on pcmk-2!

Even though WebSite now prefers to run on pcmk-1, that preference is
(intentionally) less than the resource stickiness (how much we
preferred not to have unnecessary downtime).

To see the current placement scores, you can use a tool called crm_simulate.

.. code-block:: none

    [root@pcmk-1 ~]# crm_simulate -sL

    Current cluster status:
    Online: [ pcmk-1 pcmk-2 ]

     ClusterIP	(ocf::heartbeat:IPaddr2):	Started pcmk-2
     WebSite	(ocf::heartbeat:apache):	Started pcmk-2

    Allocation scores:
    native_color: ClusterIP allocation score on pcmk-1: 50
    native_color: ClusterIP allocation score on pcmk-2: 200
    native_color: WebSite allocation score on pcmk-1: -INFINITY
    native_color: WebSite allocation score on pcmk-2: 100

    Transition Summary:


.. index::
   single: resource; moving manually

Move Resources Manually
#######################

There are always times when an administrator needs to override the
cluster and force resources to move to a specific location. In this example,
we will force the WebSite to move to pcmk-1.

We will use the **pcs resource move** command to create a temporary constraint
with a score of INFINITY. While we could update our existing constraint,
using **move** allows to easily get rid of the temporary constraint later.
If desired, we could even give a lifetime for the constraint, so it would
expire automatically -- but we don't do that in this example.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource move WebSite pcmk-1
    [root@pcmk-1 ~]# pcs constraint
    Location Constraints:
      Resource: WebSite
        Enabled on: pcmk-1 (score:50)
        Enabled on: pcmk-1 (score:INFINITY) (role: Started)
    Ordering Constraints:
      start ClusterIP then start WebSite (kind:Mandatory)
    Colocation Constraints:
      WebSite with ClusterIP (score:INFINITY)
    Ticket Constraints:
    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-2 (version 2.0.5-4.el8-ba59be7122) - partition with quorum
      * Last updated: Tue Jan 26 19:49:27 2021
      * Last change:  Tue Jan 26 19:49:10 2021 by root via crm_resource on pcmk-1
      * 2 nodes configured
      * 2 resource instances configured
    
    Node List:
      * Online: [ pcmk-1 pcmk-2 ]
    
    Full List of Resources:
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite		(ocf::heartbeat:apache):	 Started pcmk-1

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

Once we've finished whatever activity required us to move the
resources to pcmk-1 (in our case nothing), the new constraint is no longer
needed, and so we can remove it. Due to our first location constraint and our
default stickiness, the resources will remain on pcmk-1.

We will use the **pcs resource clear** command, which removes all temporary
constraints previously created by **pcs resource move** or **pcs resource ban**.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource clear WebSite
    Removing constraint: cli-prefer-WebSite
    [root@pcmk-1 ~]# pcs constraint
    Location Constraints:
      Resource: WebSite
        Enabled on: pcmk-1 (score:50)
    Ordering Constraints:
      start ClusterIP then start WebSite (kind:Mandatory)
    Colocation Constraints:
      WebSite with ClusterIP (score:INFINITY)
    Ticket Constraints:

Note that the INFINITY location constraint is now gone. If we check the cluster
status, we can also see that (as expected) the resources are still active
on pcmk-1.

.. code-block:: none

    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-2 (version 2.0.5-4.el8-ba59be7122) - partition with quorum
      * Last updated: Tue Jan 26 19:50:52 2021
      * Last change:  Tue Jan 26 19:50:24 2021 by root via crm_resource on pcmk-1
      * 2 nodes configured
      * 2 resource instances configured
    
    Node List:
      * Online: [ pcmk-1 pcmk-2 ]
    
    Full List of Resources:
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite		(ocf::heartbeat:apache):	 Started pcmk-1

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

To remove the constraint with the score of 50, we would first get the
constraint's ID using ``pcs constraint --full``, then remove it with
``pcs constraint remove`` and the ID. We won't show those steps here,
but feel free to try it on your own, with the help of the pcs man page
if necessary.

.. [#] Compare the key used here, **ocf:heartbeat:apache**, with the one we
       used earlier for the IP address, **ocf:heartbeat:IPaddr2**.
