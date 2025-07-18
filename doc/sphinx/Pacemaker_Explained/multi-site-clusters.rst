Multi-Site Clusters and Tickets
-------------------------------

Apart from local clusters, Pacemaker also supports multi-site clusters.
That means you can have multiple, geographically dispersed sites, each with a
local cluster. Failover between these clusters can be coordinated
manually by the administrator, or automatically by a higher-level entity called
a *Cluster Ticket Registry (CTR)*.

Challenges for Multi-Site Clusters
##################################

Typically, multi-site environments are too far apart to support
synchronous communication and data replication between the sites.
That leads to significant challenges:

- How do we make sure that a cluster site is up and running?

- How do we make sure that resources are only started once?

- How do we make sure that quorum can be reached between the different
  sites and a split-brain scenario avoided?

- How do we manage failover between sites?

- How do we deal with high latency in case of resources that need to be
  stopped?

In the following sections, learn how to meet these challenges.

Conceptual Overview
###################

Multi-site clusters can be considered as “overlay” clusters where
each cluster site corresponds to a cluster node in a traditional cluster.
The overlay cluster can be managed by a CTR in order to
guarantee that any cluster resource will be active
on no more than one cluster site. This is achieved by using
*tickets* that are treated as failover domain between cluster
sites, in case a site should be down.

The following sections explain the individual components and mechanisms
that were introduced for multi-site clusters in more detail.

Ticket
______

Tickets are, essentially, cluster-wide attributes. A ticket grants the
right to run certain resources on a specific cluster site. Resources can
be bound to a certain ticket by ``rsc_ticket`` constraints. Only if the
ticket is available at a site can the respective resources be started there.
Vice versa, if the ticket is revoked, the resources depending on that
ticket must be stopped.

The ticket thus is similar to a *site quorum*, i.e. the permission to
manage/own resources associated with that site. (One can also think of the
current ``have-quorum`` flag as a special, cluster-wide ticket that is
granted in case of node majority.)

Tickets can be granted and revoked either manually by administrators
(which could be the default for classic enterprise clusters), or via
the automated CTR mechanism described below.

A ticket can only be owned by one site at a time. Initially, none
of the sites has a ticket. Each ticket must be granted once by the cluster
administrator.

The presence or absence of tickets for a site is stored in the CIB as a
cluster status. With regards to a certain ticket, there are only two states
for a site: ``true`` (the site has the ticket) or ``false`` (the site does
not have the ticket). The absence of a certain ticket (during the initial
state of the multi-site cluster) is the same as the value ``false``.

Dead Man Dependency
___________________

A site can only activate resources safely if it can be sure that the
other site has deactivated them. However after a ticket is revoked, it can
take a long time until all resources depending on that ticket are stopped
"cleanly", especially in case of cascaded resources. To cut that process
short, the concept of a *Dead Man Dependency* was introduced.

If a dead man dependency is in force, if a ticket is revoked from a site, the
nodes that are hosting dependent resources are fenced. This considerably speeds
up the recovery process of the cluster and makes sure that resources can be
migrated more quickly.

This can be configured by specifying a ``loss-policy="fence"`` in
``rsc_ticket`` constraints.

Cluster Ticket Registry
_______________________

A CTR is a coordinated group of network daemons that automatically handles
granting, revoking, and timing out tickets (instead of the administrator
revoking the ticket somewhere, waiting for everything to stop, and then
granting it on the desired site).

Pacemaker does not implement its own CTR, but interoperates with external
software designed for that purpose (similar to how resource and fencing agents
are not directly part of pacemaker).

Participating clusters run the CTR daemons, which connect to each other, exchange
information about their connectivity, and vote on which sites gets which
tickets.

A ticket is granted to a site only once the CTR is sure that the ticket
has been relinquished by the previous owner, implemented via a timer in most
scenarios. If a site loses connection to its peers, its tickets time out and
recovery occurs. After the connection timeout plus the recovery timeout has
passed, the other sites are allowed to re-acquire the ticket and start the
resources again.

This can also be thought of as a "quorum server", except that it is not
a single quorum ticket, but several.

Configuration Replication
_________________________

As usual, the CIB is synchronized within each cluster, but it is *not* synchronized
across cluster sites of a multi-site cluster. You have to configure the resources
that will be highly available across the multi-site cluster for every site
accordingly.

.. _ticket-constraints:

Configuring Ticket Dependencies
###############################

The **rsc_ticket** constraint lets you specify the resources depending on a certain
ticket. Together with the constraint, you can set a **loss-policy** that defines
what should happen to the respective resources if the ticket is revoked.

The attribute **loss-policy** can have the following values:

* ``fence:`` Fence the nodes that are running the relevant resources.

* ``stop:`` Stop the relevant resources.

* ``freeze:`` Do nothing to the relevant resources.

* ``demote:`` Demote relevant resources that are running in the promoted role.

.. topic:: Constraint that fences node if ``ticketA`` is revoked

   .. code-block:: xml

      <rsc_ticket id="rsc1-req-ticketA" rsc="rsc1" ticket="ticketA" loss-policy="fence"/>

The example above creates a constraint with the ID ``rsc1-req-ticketA``. It
defines that the resource ``rsc1`` depends on ``ticketA`` and that the node running
the resource should be fenced if ``ticketA`` is revoked.

If resource ``rsc1`` were a promotable resource, you might want to configure
that only being in the promoted role depends on ``ticketA``. With the following
configuration, ``rsc1`` will be demoted if ``ticketA`` is revoked:

.. topic:: Constraint that demotes ``rsc1`` if ``ticketA`` is revoked

   .. code-block:: xml

      <rsc_ticket id="rsc1-req-ticketA" rsc="rsc1" rsc-role="Promoted" ticket="ticketA" loss-policy="demote"/>

You can create multiple **rsc_ticket** constraints to let multiple resources
depend on the same ticket. However, **rsc_ticket** also supports resource sets
(see :ref:`s-resource-sets`), so one can easily list all the resources in one
**rsc_ticket** constraint instead.

.. topic:: Ticket constraint for multiple resources

   .. code-block:: xml

      <rsc_ticket id="resources-dep-ticketA" ticket="ticketA" loss-policy="fence">
        <resource_set id="resources-dep-ticketA-0" role="Started">
          <resource_ref id="rsc1"/>
          <resource_ref id="group1"/>
          <resource_ref id="clone1"/>
        </resource_set>
        <resource_set id="resources-dep-ticketA-1" role="Promoted">
          <resource_ref id="ms1"/>
        </resource_set>
      </rsc_ticket>

In the example above, there are two resource sets, so we can list resources
with different roles in a single ``rsc_ticket`` constraint. There's no dependency
between the two resource sets, and there's no dependency among the
resources within a resource set. Each of the resources just depends on
``ticketA``.

Referencing resource templates in ``rsc_ticket`` constraints, and even
referencing them within resource sets, is also supported.

If you want other resources to depend on further tickets, create as many
constraints as necessary with ``rsc_ticket``.

Managing Multi-Site Clusters
############################

Granting and Revoking Tickets Manually
______________________________________

You can grant tickets to sites or revoke them from sites manually.
If you want to re-distribute a ticket, you should wait for
the dependent resources to stop cleanly at the previous site before you
grant the ticket to the new site.

Use the **crm_ticket** command line tool to grant and revoke tickets.

To grant a ticket to this site:

   .. code-block:: none

      # crm_ticket --ticket ticketA --grant

To revoke a ticket from this site:

   .. code-block:: none

      # crm_ticket --ticket ticketA --revoke

.. important::

   If you are managing tickets manually, use the **crm_ticket** command with
   great care, because it cannot check whether the same ticket is already
   granted elsewhere.

Granting and Revoking Tickets via a Cluster Ticket Registry
___________________________________________________________

We will use `Booth <https://github.com/ClusterLabs/booth>`_ here as an example of
software that can be used with pacemaker as a Cluster Ticket Registry.  Booth
implements the `Raft <http://en.wikipedia.org/wiki/Raft_%28computer_science%29>`_
algorithm to guarantee the distributed consensus among different
cluster sites, and manages the ticket distribution (and thus the failover
process between sites).

Each of the participating clusters and *arbitrators* runs the Booth daemon
**boothd**.

An *arbitrator* is the multi-site equivalent of a quorum-only node in a local
cluster. If you have a setup with an even number of sites,
you need an additional instance to reach consensus about decisions such
as failover of resources across sites. In this case, add one or more
arbitrators running at additional sites. Arbitrators are single machines
that run a booth instance in a special mode. An arbitrator is especially
important for a two-site scenario, otherwise there is no way for one site
to distinguish between a network failure between it and the other site, and
a failure of the other site.

The most common multi-site scenario is probably a multi-site cluster with two
sites and a single arbitrator on a third site. However, technically, there are
no limitations with regards to the number of sites and the number of
arbitrators involved.

**Boothd** at each site connects to its peers running at the other sites and
exchanges connectivity details. Once a ticket is granted to a site, the
booth mechanism will manage the ticket automatically: If the site which
holds the ticket is out of service, the booth daemons will vote which
of the other sites will get the ticket. To protect against brief
connection failures, sites that lose the vote (either explicitly or
implicitly by being disconnected from the voting body) need to
relinquish the ticket after a time-out. Thus, it is made sure that a
ticket will only be re-distributed after it has been relinquished by the
previous site.  The resources that depend on that ticket will fail over
to the new site holding the ticket. The nodes that have run the
resources before will be treated according to the **loss-policy** you set
within the **rsc_ticket** constraint.

Before the booth can manage a certain ticket within the multi-site cluster,
you initially need to grant it to a site manually via the **booth** command-line
tool. After you have initially granted a ticket to a site, **boothd**
will take over and manage the ticket automatically.

.. important::

   The **booth** command-line tool can be used to grant, list, or
   revoke tickets and can be run on any machine where **boothd** is running.
   If you are managing tickets via Booth, use only **booth** for manual
   intervention, not **crm_ticket**. That ensures the same ticket
   will only be owned by one cluster site at a time.

Booth Requirements
~~~~~~~~~~~~~~~~~~

* All clusters that will be part of the multi-site cluster must be based on
  Pacemaker.

* Booth must be installed on all cluster nodes and on all arbitrators that will
  be part of the multi-site cluster.

* Nodes belonging to the same cluster site should be synchronized via NTP. However,
  time synchronization is not required between the individual cluster sites.

General Management of Tickets
_____________________________

Display the information of tickets:

   .. code-block:: none

      # crm_ticket --info

Or you can monitor them with:

   .. code-block:: none

      # crm_mon --tickets

Display the ``rsc_ticket`` constraints that apply to a ticket:

   .. code-block:: none

      # crm_ticket --ticket ticketA --constraints

When you want to do maintenance or manual switch-over of a ticket,
revoking the ticket would trigger the loss policies. If
``loss-policy="fence"``, the dependent resources could not be gracefully
stopped/demoted, and other unrelated resources could even be affected. 

The proper way is making the ticket *standby* first with:

   .. code-block:: none

      # crm_ticket --ticket ticketA --standby

Then the dependent resources will be stopped or demoted gracefully without
triggering the loss policies.

If you have finished the maintenance and want to activate the ticket again,
you can run:

   .. code-block:: none

      # crm_ticket --ticket ticketA --activate

For more information
####################

* `SUSE's Geo Clustering quick start <https://www.suse.com/documentation/sle-ha-geo-12/art_ha_geo_quick/data/art_ha_geo_quick.html>`_

* `Booth <https://github.com/ClusterLabs/booth>`_
