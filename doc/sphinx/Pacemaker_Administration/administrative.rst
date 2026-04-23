.. index::
   single: administrative mode

Administrative Modes
--------------------

Intrusive administration can be performed on a Pacemaker cluster without
causing resource failures, recovery, and fencing, by putting the cluster or a
subset of it into an administrative mode.

Pacemaker supports several administrative modes:

* Maintenance mode for the entire cluster, specific nodes, or specific
  resources
* Unmanaged resources
* Disabled configuration items
* Standby mode for specific nodes

Rules may be used to automatically set any of these modes for specific times or
other conditions.


.. index::
   pair: administrative mode; maintenance mode

.. _maintenance_mode:

Maintenance Mode
################

In maintenance mode, the cluster will not start or stop resources. Recurring
monitors for affected resources will be paused, except those specifying
``role`` as ``Stopped``.

To put a specific resource into maintenance mode, set the resource's
``maintenance`` meta-attribute to ``true``.

To put all active resources on a specific node into maintenance mode, set the
node's ``maintenance`` node attribute to ``true``. When enabled, this overrides
resource-specific maintenance mode.

.. warning::

   Restarting Pacemaker on a node that is in single-node maintenance mode will
   likely lead to undesirable effects. If ``maintenance`` is set as a transient
   attribute, it will be erased when Pacemaker is stopped, which will
   immediately take the node out of maintenance mode and likely get it fenced.
   If set as a permanent attribute, any resources active on the node will have
   their local history erased when Pacemaker is restarted, so the cluster will
   no longer consider them running on the node and thus will consider them
   managed again, allowing them to be started elsewhere.

To put all resources in the cluster into maintenance mode, set the
``maintenance-mode`` cluster option to ``true``. When enabled, this overrides
node- or resource- specific maintenance mode.

Maintenance mode, at any level, overrides other administrative modes.


.. index::
   pair: administrative mode; unmanaged resources

.. _unmanaged_resources:

Unmanaged Resources
###################

An unmanaged resource will not be started or stopped by the cluster. A resource
may become unmanaged in several ways:

* The administrator may set the ``is-managed`` resource meta-attribute to
  ``false`` (whether for a specific resource, or all resources without an
  explicit setting via ``rsc_defaults``)
* :ref:`Maintenance mode <maintenance_mode>` causes affected resources to
  become unmanaged (and overrides any ``is-managed`` setting)
* Certain types of failure cause affected resources to become unmanaged. These
  include:

  * Failed stop operations when the ``fencing-enabled`` cluster property is set
    to ``false``
  * Failure of an operation that has ``on-fail`` set to ``block``
  * A resource detected as incorrectly active on more than one node when its
    ``multiple-active`` meta-attribute is set to ``block``
  * A resource constrained by a revoked ``rsc_ticket`` with ``loss-policy`` set
    to ``freeze``
  * Resources with ``requires`` set (or defaulting) to anything other than
    ``nothing`` in a partition that loses quorum when the ``no-quorum-policy``
    cluster option is set to ``freeze``

Recurring actions are not affected by unmanaging a resource.

.. warning::

   Manually starting an unmanaged resource on a different node is strongly
   discouraged. It will at least cause the cluster to consider the resource
   failed, and may require the resource's ``target-role`` to be set to
   ``Stopped`` then ``Started`` in order for recovery to succeed.


.. index::
   pair: administrative mode; disabled configuration

.. _disabled_configuration:

Disabled Configuration
######################

Some configuration elements disable particular behaviors:

* The ``fencing-enabled`` cluster option, when set to ``false``, disables node
  fencing. This is highly discouraged, as it can lead to data unavailability,
  loss, or corruption.

* The ``stop-all-resources`` cluster option, when set to ``true``, causes all
  resources to be stopped.

* Certain elements support an ``enabled`` meta-attribute, which if set to
  ``false``, causes the cluster to act as if the specific element is not
  configured. These include ``op``, ``alert`` *(since 2.1.6)*, and
  ``recipient`` *(since 2.1.6)*. ``enabled`` may be set for specific ``op``
  elements, or all operations without an explicit setting via ``op_defaults``.


.. index::
   pair: administrative mode; standby

.. _standby:

Standby Mode
############

When a node is put into standby, all resources will be moved away from the
node, and all recurring operations will be stopped on the node, except those
specifying ``role`` as ``Stopped`` (which will be newly initiated if
appropriate).

A node may be put into standby mode by setting its ``standby`` node attribute
to ``true``. The attribute may be queried and set using the ``crm_standby``
tool.


.. index::
   pair: administrative mode; rules

Rules
#####

Rules may be used to set administrative mode options automatically according to
various criteria such as date and time. See the "Rules" chapter of the
*Pacemaker Explained* document for details.
