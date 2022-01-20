.. index:: upgrade

Upgrading a Pacemaker Cluster
-----------------------------

.. index:: version

Pacemaker Versioning
####################

Pacemaker has an overall release version, plus separate version numbers for
certain internal components.

.. index::
   single: version; release

* **Pacemaker release version:** This version consists of three numbers
  (*x.y.z*).

  The major version number (the *x* in *x.y.z*) increases when at least some
  rolling upgrades are not possible from the previous major version. For example,
  a rolling upgrade from 1.0.8 to 1.1.15 should always be supported, but a
  rolling upgrade from 1.0.8 to 2.0.0 may not be possible.

  The minor version (the *y* in *x.y.z*) increases when there are significant
  changes in cluster default behavior, tool behavior, and/or the API interface
  (for software that utilizes Pacemaker libraries). The main benefit is to alert
  you to pay closer attention to the release notes, to see if you might be
  affected.

  The release counter (the *z* in *x.y.z*) is increased with all public releases
  of Pacemaker, which typically include both bug fixes and new features.

.. index::
   single: feature set
   single: version; feature set

* **CRM feature set:** This version number applies to the communication between
  full cluster nodes, and is used to avoid problems in mixed-version clusters.

  The major version number increases when nodes with different versions would not
  work (rolling upgrades are not allowed). The minor version number increases
  when mixed-version clusters are allowed only during rolling upgrades. The
  minor-minor version number is ignored, but allows resource agents to detect
  cluster support for various features. [#]_

  Pacemaker ensures that the longest-running node is the cluster's DC. This
  ensures new features are not enabled until all nodes are upgraded to support
  them.

.. index::
   single: version; Pacemaker Remote protocol

* **Pacemaker Remote protocol version:** This version applies to communication
  between a Pacemaker Remote node and the cluster. It increases when an older
  cluster node would have problems hosting the connection to a newer
  Pacemaker Remote node. To avoid these problems, Pacemaker Remote nodes will
  accept connections only from cluster nodes with the same or newer
  Pacemaker Remote protocol version.

  Unlike with CRM feature set differences between full cluster nodes,
  mixed Pacemaker Remote protocol versions between Pacemaker Remote nodes and
  full cluster nodes are fine, as long as the Pacemaker Remote nodes have the
  older version. This can be useful, for example, to host a legacy application
  in an older operating system version used as a Pacemaker Remote node.

.. index::
   single: version; XML schema

* **XML schema version:** Pacemaker’s configuration syntax — what's allowed in
  the Configuration Information Base (CIB) — has its own version. This allows
  the configuration syntax to evolve over time while still allowing clusters
  with older configurations to work without change.


.. index::
   single: upgrade; methods

Upgrading Cluster Software
##########################

There are three approaches to upgrading a cluster, each with advantages and
disadvantages.

.. table:: **Upgrade Methods**

   +---------------------------------------------------+----------+----------+--------+---------+----------+----------+
   | Method                                            | Available| Can be   | Service| Service | Exercises| Allows   |
   |                                                   | between  | used with| outage | recovery| failover | change of|
   |                                                   | all      | Pacemaker| during | during  | logic    | messaging|
   |                                                   | versions | Remote   | upgrade| upgrade |          | layer    |
   |                                                   |          | nodes    |        |         |          | [#]_     |
   +===================================================+==========+==========+========+=========+==========+==========+
   | Complete cluster shutdown                         | yes      | yes      | always | N/A     | no       | yes      |
   +---------------------------------------------------+----------+----------+--------+---------+----------+----------+
   | Rolling (node by node)                            | no       | yes      | always | yes     | yes      | no       |
   |                                                   |          |          | [#]_   |         |          |          |
   +---------------------------------------------------+----------+----------+--------+---------+----------+----------+
   | Detach and reattach                               | yes      | no       | only   | no      | no       | yes      |
   |                                                   |          |          | due to |         |          |          |
   |                                                   |          |          | failure|         |          |          |
   +---------------------------------------------------+----------+----------+--------+---------+----------+----------+


.. index::
   single: upgrade; shutdown

Complete Cluster Shutdown
_________________________

In this scenario, one shuts down all cluster nodes and resources,
then upgrades all the nodes before restarting the cluster.

#. On each node:

   a. Shutdown the cluster software (pacemaker and the messaging layer).
   #. Upgrade the Pacemaker software. This may also include upgrading the
      messaging layer and/or the underlying operating system.
   #. Check the configuration with the ``crm_verify`` tool.

#. On each node:

   a. Start the cluster software.

Currently, only Corosync version 2 and greater is supported as the cluster
layer, but if another stack is supported in the future, the stack does not
need to be the same one before the upgrade.

One variation of this approach is to build a new cluster on new hosts.
This allows the new version to be tested beforehand, and minimizes downtime by
having the new nodes ready to be placed in production as soon as the old nodes
are shut down.


.. index::
   single: upgrade; rolling upgrade

Rolling (node by node)
______________________

In this scenario, each node is removed from the cluster, upgraded, and then
brought back online, until all nodes are running the newest version.

Special considerations when planning a rolling upgrade:

* If you plan to upgrade other cluster software -- such as the messaging layer --
  at the same time, consult that software's documentation for its compatibility
  with a rolling upgrade.

* If the major version number is changing in the Pacemaker version you are
  upgrading to, a rolling upgrade may not be possible. Read the new version's
  release notes (as well the information here) for what limitations may exist.

* If the CRM feature set is changing in the Pacemaker version you are upgrading
  to, you should run a mixed-version cluster only during a small rolling
  upgrade window. If one of the older nodes drops out of the cluster for any
  reason, it will not be able to rejoin until it is upgraded.

* If the Pacemaker Remote protocol version is changing, all cluster nodes
  should be upgraded before upgrading any Pacemaker Remote nodes.

See the ClusterLabs wiki's
`release calendar <https://wiki.clusterlabs.org/wiki/ReleaseCalendar>`_
to figure out whether the CRM feature set and/or Pacemaker Remote protocol
version changed between the the Pacemaker release versions in your rolling
upgrade.

To perform a rolling upgrade, on each node in turn:

#. Put the node into standby mode, and wait for any active resources
   to be moved cleanly to another node. (This step is optional, but
   allows you to deal with any resource issues before the upgrade.)
#. Shutdown the cluster software (pacemaker and the messaging layer) on the node.
#. Upgrade the Pacemaker software. This may also include upgrading the
   messaging layer and/or the underlying operating system.
#. If this is the first node to be upgraded, check the configuration
   with the ``crm_verify`` tool.
#. Start the messaging layer.
   This must be the same messaging layer (currently only Corosync version 2 and
   greater is supported) that the rest of the cluster is using.

.. note::

   Even if a rolling upgrade from the current version of the cluster to the
   newest version is not directly possible, it may be possible to perform a
   rolling upgrade in multiple steps, by upgrading to an intermediate version
   first.

.. table:: **Version Compatibility Table**

   +-------------------------+---------------------------+
   | Version being Installed | Oldest Compatible Version |
   +=========================+===========================+
   | Pacemaker 2.y.z         | Pacemaker 1.1.11 [#]_     |
   +-------------------------+---------------------------+
   | Pacemaker 1.y.z         | Pacemaker 1.0.0           |
   +-------------------------+---------------------------+
   | Pacemaker 0.7.z         | Pacemaker 0.6.z           |
   +-------------------------+---------------------------+

.. index::
   single: upgrade; detach and reattach

Detach and Reattach
___________________

The reattach method is a variant of a complete cluster shutdown, where the
resources are left active and get re-detected when the cluster is restarted.

This method may not be used if the cluster contains any Pacemaker Remote nodes.

#. Tell the cluster to stop managing services. This is required to allow the
   services to remain active after the cluster shuts down.

   .. code-block:: none

      # crm_attribute --name maintenance-mode --update true

#. On each node, shutdown the cluster software (pacemaker and the messaging
   layer), and upgrade the Pacemaker software. This may also include upgrading
   the messaging layer. While the underlying operating system may be upgraded
   at the same time, that will be more likely to cause outages in the detached
   services (certainly, if a reboot is required).
#. Check the configuration with the ``crm_verify`` tool.
#. On each node, start the cluster software.
   Currently, only Corosync version 2 and greater is supported as the cluster
   layer, but if another stack is supported in the future, the stack does not
   need to be the same one before the upgrade.
#. Verify that the cluster re-detected all resources correctly.
#. Allow the cluster to resume managing resources again:

   .. code-block:: none

      # crm_attribute --name maintenance-mode --delete

.. note::

   While the goal of the detach-and-reattach method is to avoid disturbing
   running services, resources may still move after the upgrade if any
   resource's location is governed by a rule based on transient node
   attributes. Transient node attributes are erased when the node leaves the
   cluster. A common example is using the ``ocf:pacemaker:ping`` resource to
   set a node attribute used to locate other resources.

.. index::
   pair: upgrade; CIB

Upgrading the Configuration
###########################

The CIB schema version can change from one Pacemaker version to another.

After cluster software is upgraded, the cluster will continue to use the older
schema version that it was previously using. This can be useful, for example,
when administrators have written tools that modify the configuration, and are
based on the older syntax. [#]_

However, when using an older syntax, new features may be unavailable, and there
is a performance impact, since the cluster must do a non-persistent
configuration upgrade before each transition. So while using the old syntax is
possible, it is not advisable to continue using it indefinitely.

Even if you wish to continue using the old syntax, it is a good idea to
follow the upgrade procedure outlined below, except for the last step, to ensure
that the new software has no problems with your existing configuration (since it
will perform much the same task internally).

If you are brave, it is sufficient simply to run ``cibadmin --upgrade``.

A more cautious approach would proceed like this:

#. Create a shadow copy of the configuration. The later commands will
   automatically operate on this copy, rather than the live configuration.

   .. code-block:: none

      # crm_shadow --create shadow

.. index::
   single: configuration; verify

#. Verify the configuration is valid with the new software (which may be
   stricter about syntax mistakes, or may have dropped support for deprecated
   features):

   .. code-block:: none

      # crm_verify --live-check

#. Fix any errors or warnings.
#. Perform the upgrade:

   .. code-block:: none

      # cibadmin --upgrade

#. If this step fails, there are three main possibilities:

   a. The configuration was not valid to start with (did you do steps 2 and
      3?).
   #. The transformation failed; `report a bug <https://bugs.clusterlabs.org/>`_.
   #. The transformation was successful but produced an invalid result.

   If the result of the transformation is invalid, you may see a number of
   errors from the validation library. If these are not helpful, visit the
   `Validation FAQ wiki page <https://wiki.clusterlabs.org/wiki/Validation_FAQ>`_
   and/or try the manual upgrade procedure described below.

#. Check the changes:

   .. code-block:: none

      # crm_shadow --diff

   If at this point there is anything about the upgrade that you wish to
   fine-tune (for example, to change some of the automatic IDs), now is the
   time to do so:

   .. code-block:: none

      # crm_shadow --edit

   This will open the configuration in your favorite editor (whichever is
   specified by the standard ``$EDITOR`` environment variable).

#. Preview how the cluster will react:

   .. code-block:: none

      # crm_simulate --live-check --save-dotfile shadow.dot -S
      # dot -Tsvg shadow.dot -o shadow.svg

   You can then view shadow.svg with any compatible image viewer or web
   browser. Verify that either no resource actions will occur or that you are
   happy with any that are scheduled.  If the output contains actions you do
   not expect (possibly due to changes to the score calculations), you may need
   to make further manual changes. See :ref:`crm_simulate` for further details
   on how to interpret the output of ``crm_simulate`` and ``dot``.

#. Upload the changes:

   .. code-block:: none

      # crm_shadow --commit shadow --force

   In the unlikely event this step fails, please report a bug.

.. note::

   It is also possible to perform the configuration upgrade steps manually:

   #. Locate the ``upgrade*.xsl`` conversion scripts provided with the source
      code. These will often be installed in a location such as
      ``/usr/share/pacemaker``, or may be obtained from the
      `source repository <https://github.com/ClusterLabs/pacemaker/tree/main/xml>`_.
          
   #. Run the conversion scripts that apply to your older version, for example:

      .. code-block:: none

         # xsltproc /path/to/upgrade06.xsl config06.xml > config10.xml

   #. Locate the ``pacemaker.rng`` script (from the same location as the xsl
      files).
   #. Check the XML validity:

      .. code-block:: none

         # xmllint --relaxng /path/to/pacemaker.rng config10.xml

   The advantage of this method is that it can be performed without the cluster
   running, and any validation errors are often more informative.


What Changed in 2.1
###################

The Pacemaker 2.1 release is fully backward-compatible in both the CIB XML and
the C API. Highlights:

* Pacemaker now supports the **OCF Resource Agent API version 1.1**.
  Most notably, the ``Master`` and ``Slave`` role names have been renamed to
  ``Promoted`` and ``Unpromoted``.

* Pacemaker now supports colocations where the dependent resource does not
  affect the primary resource's placement (via a new ``influence`` colocation
  constraint option and ``critical`` resource meta-attribute). This is intended
  for cases where a less-important resource must be colocated with an essential
  resource, but it is preferred to leave the less-important resource stopped if
  it fails, rather than move both resources.

* If Pacemaker is built with libqb 2.0 or later, the detail log will use
  **millisecond-resolution timestamps**.

* In addition to crm_mon and stonith_admin, the crmadmin, crm_resource,
  crm_simulate, and crm_verify commands now support the ``--output-as`` and
  ``--output-to`` options, including **XML output** (which scripts and
  higher-level tools are strongly recommended to use instead of trying to parse
  the text output, which may change from release to release).

For a detailed list of changes, see the release notes and the
`Pacemaker 2.1 Changes <https://wiki.clusterlabs.org/wiki/Pacemaker_2.1_Changes>`_
page on the ClusterLabs wiki.


What Changed in 2.0
###################

The main goal of the 2.0 release was to remove support for deprecated syntax,
along with some small changes in default configuration behavior and tool
behavior. Highlights:

* Only Corosync version 2 and greater is now supported as the underlying
  cluster layer. Support for Heartbeat and Corosync 1 (including CMAN) is
  removed.

* The Pacemaker detail log file is now stored in
  ``/var/log/pacemaker/pacemaker.log`` by default.

* The record-pending cluster property now defaults to true, which
  allows status tools such as crm_mon to show operations that are in
  progress.

* Support for a number of deprecated build options, environment variables,
  and configuration settings has been removed.

* The ``master`` tag has been deprecated in favor of using the ``clone`` tag
  with the new ``promotable`` meta-attribute set to ``true``. "Master/slave"
  clone resources are now referred to as "promotable" clone resources.

* The public API for Pacemaker libraries that software applications can use
  has changed significantly.

For a detailed list of changes, see the release notes and the
`Pacemaker 2.0 Changes <https://wiki.clusterlabs.org/wiki/Pacemaker_2.0_Changes>`_
page on the ClusterLabs wiki.


What Changed in 1.0
###################

New
___

* Failure timeouts.
* New section for resource and operation defaults.
* Tool for making offline configuration changes.
* ``Rules``, ``instance_attributes``, ``meta_attributes`` and sets of
  operations can be defined once and referenced in multiple places.
* The CIB now accepts XPath-based create/modify/delete operations. See
  ``cibadmin --help``.
* Multi-dimensional colocation and ordering constraints.
* The ability to connect to the CIB from non-cluster machines.
* Allow recurring actions to be triggered at known times.


Changed
_______

* Syntax

  * All resource and cluster options now use dashes (-) instead of underscores
    (_)
  * ``master_slave`` was renamed to ``master``
  * The ``attributes`` container tag was removed
  * The operation field ``pre-req`` has been renamed ``requires``
  * All operations must have an ``interval``, ``start``/``stop`` must have it
    set to zero

* The ``stonith-enabled`` option now defaults to true.
* The cluster will refuse to start resources if ``stonith-enabled`` is true (or
  unset) and no STONITH resources have been defined
* The attributes of colocation and ordering constraints were renamed for
  clarity.
* ``resource-failure-stickiness`` has been replaced by ``migration-threshold``.
* The parameters for command-line tools have been made consistent
* Switched to 'RelaxNG' schema validation and 'libxml2' parser

  * id fields are now XML IDs which have the following limitations:

    * id's cannot contain colons (:)
    * id's cannot begin with a number
    * id's must be globally unique (not just unique for that tag)

  * Some fields (such as those in constraints that refer to resources) are
    IDREFs.

    This means that they must reference existing resources or objects in
    order for the configuration to be valid.  Removing an object which is
    referenced elsewhere will therefore fail.

  * The CIB representation, from which a MD5 digest is calculated to verify
    CIBs on the nodes, has changed.

    This means that every CIB update will require a full refresh on any
    upgraded nodes until the cluster is fully upgraded to 1.0. This will result
    in significant performance degradation and it is therefore highly
    inadvisable to run a mixed 1.0/0.6 cluster for any longer than absolutely
    necessary.

* Ping node information no longer needs to be added to ``ha.cf``. Simply
  include the lists of hosts in your ping resource(s).


Removed
_______


* Syntax

  * It is no longer possible to set resource meta options as top-level
    attributes. Use meta-attributes instead.
  * Resource and operation defaults are no longer read from ``crm_config``.

.. rubric:: Footnotes

.. [#] Before CRM feature set 3.1.0 (Pacemaker 2.0.0), the minor-minor version
       number was treated the same as the minor version.

.. [#] Currently, Corosync version 2 and greater is the only supported cluster
       stack, but other stacks have been supported by past versions, and may be
       supported by future versions.

.. [#] Any active resources will be moved off the node being upgraded, so there
       will be at least a brief outage unless all resources can be migrated
       "live".

.. [#] Rolling upgrades from Pacemaker 1.1.z to 2.y.z are possible only if the
       cluster uses corosync version 2 or greater as its messaging layer, and
       the Cluster Information Base (CIB) uses schema 1.0 or higher in its
       ``validate-with`` property.

.. [#] As of Pacemaker 2.0.0, only schema versions pacemaker-1.0 and higher
       are supported (excluding pacemaker-1.1, which was an experimental schema
       now known as pacemaker-next).
