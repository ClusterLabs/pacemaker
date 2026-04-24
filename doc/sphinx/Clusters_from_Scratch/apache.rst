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
hosts. We will also allow the cluster to use the ``wget`` tool (this is the
default, but ``curl`` is also supported) to check the status of the Apache
server. We'll install ``httpd`` (Apache) and ``wget`` now.

.. code-block:: console

    # dnf install -y httpd wget
    # firewall-cmd --permanent --add-service=http
    # firewall-cmd --reload

.. IMPORTANT::

    Do **not** enable the ``httpd`` service. Services that are intended to
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

.. code-block:: console

    # cat <<-END >/var/www/html/index.html
     <html>
     <body>My Test Site - $(hostname)</body>
     </html>
    END


.. index::
    single: Apache HTTP Server; status URL

Enable the Apache Status URL
############################

Pacemaker uses the ``apache`` resource agent to monitor the health of your
Apache instance via the ``server-status`` URL, and to recover the instance if
it fails. On both nodes, configure this URL as follows:

.. code-block:: console

    # cat <<-END >/etc/httpd/conf.d/status.conf
     <Location /server-status>
        SetHandler server-status
        Require all granted
     </Location>
    END

.. NOTE::

    If you are using a different operating system, ``server-status`` may
    already be enabled or may be configurable in a different location. If you
    are using a version of Apache HTTP Server less than 2.4, the syntax will be
    different.


.. index::
    pair: Apache HTTP Server; resource

Configure the Cluster
#####################

At this point, Apache is ready to go, and all that needs to be done is to
add it to the cluster. Let's call the resource ``WebSite``. We need to use
an OCF resource agent called ``apache`` in the ``heartbeat`` namespace [#]_.
The script's only required parameter is the path to the main Apache
configuration file, and we'll tell the cluster to check once a
minute that Apache is still running.

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource create WebSite ocf:heartbeat:apache  \
          configfile=/etc/httpd/conf/httpd.conf \
          statusurl="http://localhost/server-status" \
          op monitor interval=1min

By default, the operation timeout for all resources' start, stop, monitor, and
other operations is 20 seconds. In many cases, this timeout period is less than
a particular resource's advised timeout period. For the purposes of this
tutorial, we will adjust the global operation timeout default to 240 seconds.

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource op defaults
    [root@pcmk-1 ~]# pcs resource op defaults update timeout=240s
    Warning: Defaults do not apply to resources which override them with their own defined values
    [root@pcmk-1 ~]# pcs resource op defaults
    Meta Attrs: op_defaults-meta_attributes
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

.. code-block:: console

    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync (Pacemaker is running)
      * Current DC: pcmk-1 (version 3.0.1-3.el10-6a90427) - partition with quorum
      * Last updated: Tue Feb 24 16:34:07 2026 on pcmk-1
      * Last change:  Tue Feb 24 16:33:50 2026 by root via root on pcmk-1
      * 2 nodes configured
      * 3 resource instances configured

    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * fence_dev	(stonith:some_fence_agent):	 Started pcmk-1
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf:heartbeat:apache):	     Started pcmk-2

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

Wait a moment, the ``WebSite`` resource isn't running on the same host as our
IP address!

.. NOTE::

    If, in the ``pcs status`` output, you see the ``WebSite`` resource has
    failed to start, then you've likely not enabled the status URL correctly.
    You can check whether this is the problem by running:

    .. code-block:: console

        wget -O - http://localhost/server-status

    If you see ``Not Found`` or ``Forbidden`` in the output, then this is likely the
    problem. Ensure that the ``<Location /server-status>`` block is correct.

.. index::
    single: constraint; colocation
    single: colocation constraint

Ensure Resources Run on the Same Host
#####################################

To reduce the load on any one machine, Pacemaker will generally try to
spread the configured resources across the cluster nodes. However, we
can tell the cluster that two resources are related and need to run on
the same host (or else one of them should not run at all, if they cannot run on
the same node). Here, we instruct the cluster that ``WebSite`` can only run on
the host where ``ClusterIP`` is active.

To achieve this, we use a *colocation constraint* that indicates it is
mandatory for ``WebSite`` to run on the same node as ``ClusterIP``. The
"mandatory" part of the colocation constraint is indicated by using a
score of ``INFINITY``. The ``INFINITY`` score also means that if ``ClusterIP``
is not active anywhere, ``WebSite`` will not be permitted to run.

.. NOTE::

    If ``ClusterIP`` is not active anywhere, ``WebSite`` will not be permitted
    to run anywhere.

.. NOTE::

    ``INFINITY`` is the default score for a colocation constraint. If you don't
    specify a score, ``INFINITY`` will be used automatically.

.. IMPORTANT::

    Colocation constraints are "directional", in that they imply certain
    things about the order in which the two resources will have a location
    chosen. In this case, we're saying that ``WebSite`` needs to be placed on
    the same machine as ``ClusterIP``, which implies that the cluster must know
    the location of ``ClusterIP`` before choosing a location for ``WebSite``

.. code-block:: console

    [root@pcmk-1 ~]# pcs constraint colocation add WebSite with ClusterIP score=INFINITY
    [root@pcmk-1 ~]# pcs constraint
    Colocation Constraints:
      resource 'WebSite' with resource 'ClusterIP'
        score=INFINITY
    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync (Pacemaker is running)
      * Current DC: pcmk-1 (version 3.0.1-3.el10-6a90427) - partition with quorum
      * Last updated: Tue Feb 24 16:37:25 2026 on pcmk-1
      * Last change:  Tue Feb 24 16:36:36 2026 by root via root on pcmk-1
      * 2 nodes configured
      * 3 resource instances configured

    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * fence_dev	(stonith:some_fence_agent):	 Started pcmk-1
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf:heartbeat:apache):	     Started pcmk-1

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

To be sure our ``WebSite`` responds regardless of Apache's address
configuration, we need to make sure ``ClusterIP`` not only runs on the same
node, but also starts before ``WebSite``. A colocation constraint ensures
only that the resources run together; it doesn't affect order in which the
resources are started or stopped.

We do this by adding an ordering constraint. By default, all order constraints
are mandatory. This means, for example, that if ``ClusterIP`` needs to stop,
then ``WebSite`` must stop first (or already be stopped); and if WebSite needs
to start, then ``ClusterIP`` must start first (or already be started). This
also implies that the recovery of ``ClusterIP`` will trigger the recovery of
``WebSite``, causing it to be restarted.

.. code-block:: console

    [root@pcmk-1 ~]# pcs constraint order ClusterIP then WebSite
    Adding ClusterIP WebSite (kind: Mandatory) (Options: first-action=start then-action=start)
    [root@pcmk-1 ~]# pcs constraint
    Colocation Constraints:
      resource 'WebSite' with resource 'ClusterIP'
        score=INFINITY
    Order Constraints:
      start resource 'ClusterIP' then start 'WebSite'

.. NOTE::

    The default action in an order constraint is ``start`` If you don't
    specify an action, as in the example above, ``pcs`` automatically uses the
    ``start`` action.

.. NOTE::

    We could have placed the ``ClusterIP`` and ``WebSite`` resources into a
    **resource group** instead of configuring constraints. A resource group is
    a compact and intuitive way to organize a set of resources into a chain of
    colocation and ordering constraints. We will omit that in this guide; see
    the `Pacemaker Explained <https://www.clusterlabs.org/pacemaker/doc/>`_
    document for more details.


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

In the location constraint below, we are saying the ``WebSite`` resource
prefers the node ``pcmk-2`` with a score of ``50``.  Here, the score indicates
how strongly we'd like the resource to run at this location.

.. code-block:: console

    [root@pcmk-1 ~]# pcs constraint location WebSite prefers pcmk-2=50
    [root@pcmk-1 ~]# pcs constraint
    Location Constraints:
      resource 'WebSite' prefers node 'pcmk-2' with score 50
    Colocation Constraints:
      resource 'WebSite' with resource 'ClusterIP'
        score=INFINITY
    Order Constraints:
      start resource 'ClusterIP' then start 'WebSite'
    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync (Pacemaker is running)
      * Current DC: pcmk-1 (version 3.0.1-3.el10-6a90427) - partition with quorum
      * Last updated: Tue Feb 24 16:44:43 2026 on pcmk-1
      * Last change:  Tue Feb 24 16:43:35 2026 by root via root on pcmk-1
      * 2 nodes configured
      * 3 resource instances configured

    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * fence_dev	(stonith:some_fence_agent):	 Started pcmk-1
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf:heartbeat:apache):	     Started pcmk-1

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

Wait a minute, the resources are still on ``pcmk-1``!

Even though ``WebSite`` now prefers to run on ``pcmk-2``, that preference is
(intentionally) less than the resource stickiness (how much we
preferred not to have unnecessary downtime).

To see the current placement scores, you can use a tool called
``crm_simulate``.

.. code-block:: console

    [root@pcmk-1 ~]# crm_simulate -sL
    Current cluster status:
      * Node List:
        * Online: [ pcmk-1 pcmk-2 ]

      * Full List of Resources:
        * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1
        * fence_dev	(stonith:some_fence_agent):	 Started pcmk-1
        * WebSite	(ocf:heartbeat:apache):	 Started pcmk-1

    Assignment Scores:
      * pcmk__native_allocate: ClusterIP allocation score on pcmk-1: 200
      * pcmk__native_allocate: ClusterIP allocation score on pcmk-2: 50
      * pcmk__native_allocate: fence_dev allocation score on pcmk-1: 100
      * pcmk__native_allocate: fence_dev allocation score on pcmk-2: -INFINITY
      * pcmk__native_allocate: WebSite allocation score on pcmk-1: 100
      * pcmk__native_allocate: WebSite allocation score on pcmk-2: -INFINITY

.. index::
   single: resource; moving manually

Move Resources Manually
#######################

There are always times when an administrator needs to override the
cluster and force resources to move to a specific location. In this example,
we will force the WebSite to move to ``pcmk-2``.

We will use the ``pcs resource move`` command to create a temporary constraint
with a score of ``INFINITY``. While we could update our existing constraint,
using ``move`` allows ``pcs`` to get rid of the temporary constraint
automatically after the resource has moved to its destination. Note in the
below that the ``pcs constraint`` output after the ``move`` command is the same
as before.

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource move WebSite pcmk-2
    Location constraint to move resource 'WebSite' has been created
    Waiting for the cluster to apply configuration changes...
    Location constraint created to move resource 'WebSite' has been removed
    Waiting for the cluster to apply configuration changes...
    resource 'WebSite' is running on node 'pcmk-2'
    [root@pcmk-1 ~]# pcs constraint
    Location Constraints:
      resource 'WebSite' prefers node 'pcmk-2' with score 50
    Colocation Constraints:
      resource 'WebSite' with resource 'ClusterIP'
        score=INFINITY
    Order Constraints:
      start resource 'ClusterIP' then start 'WebSite'
    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync (Pacemaker is running)
      * Current DC: pcmk-1 (version 3.0.1-3.el10-6a90427) - partition with quorum
      * Last updated: Tue Feb 24 16:56:37 2026 on pcmk-1
      * Last change:  Tue Feb 24 16:54:28 2026 by root via root on pcmk-1
      * 2 nodes configured
      * 3 resource instances configured

    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * fence_dev	(stonith:some_fence_agent):	 Started pcmk-1
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-2
      * WebSite	(ocf:heartbeat:apache):	     Started pcmk-2

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

To remove the constraint with the score of ``50``, we would first get the
constraint's ID using ``pcs constraint --full``, then remove it with
``pcs constraint remove`` and the ID. We won't show those steps here,
but feel free to try it on your own, with the help of the ``pcs`` man page
if necessary.

.. [#] Compare the key used here, ``ocf:heartbeat:apache`` with the one we
       used earlier for the IP address, ``ocf:heartbeat:IPaddr2``.
