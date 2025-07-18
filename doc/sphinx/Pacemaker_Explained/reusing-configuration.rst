Reusing Parts of the Configuration
----------------------------------

Pacemaker provides multiple ways to simplify the configuration XML by reusing
parts of it in multiple places.

Besides simplifying the XML, this also allows you to manipulate multiple
configuration elements with a single reference.

Reusing Resource Definitions
############################

If you want to create lots of resources with similar configurations, defining a
*resource template* simplifies the task. Once defined, it can be referenced in
primitives or in certain types of constraints.

Configuring Resources with Templates
____________________________________

The primitives referencing the template will inherit all meta-attributes,
instance attributes, utilization attributes and operations defined
in the template. And you can define specific attributes and operations for any
of the primitives. If any of these are defined in both the template and the
primitive, the values defined in the primitive will take precedence over the
ones defined in the template.

Hence, resource templates help to reduce the amount of configuration work.
If any changes are needed, they can be done to the template definition and
will take effect globally in all resource definitions referencing that
template.

Resource templates have a syntax similar to that of primitives.

.. topic:: Resource template for a migratable Xen virtual machine

   .. code-block:: xml

      <template id="vm-template" class="ocf" provider="heartbeat" type="Xen">
        <meta_attributes id="vm-template-meta_attributes">
          <nvpair id="vm-template-meta_attributes-allow-migrate" name="allow-migrate" value="true"/>
        </meta_attributes>
        <utilization id="vm-template-utilization">
          <nvpair id="vm-template-utilization-memory" name="memory" value="512"/>
        </utilization>
        <operations>
          <op id="vm-template-monitor-15s" interval="15s" name="monitor" timeout="60s"/>
          <op id="vm-template-start-0" interval="0" name="start" timeout="60s"/>
        </operations>
      </template>

Once you define a resource template, you can use it in primitives by specifying the
``template`` property.

.. topic:: Xen primitive resource using a resource template

   .. code-block:: xml

      <primitive id="vm1" template="vm-template">
        <instance_attributes id="vm1-instance_attributes">
          <nvpair id="vm1-instance_attributes-name" name="name" value="vm1"/>
          <nvpair id="vm1-instance_attributes-xmfile" name="xmfile" value="/etc/xen/shared-vm/vm1"/>
        </instance_attributes>
      </primitive>

In the example above, the new primitive ``vm1`` will inherit everything from ``vm-template``. For
example, the equivalent of the above two examples would be:

.. topic:: Equivalent Xen primitive resource not using a resource template

   .. code-block:: xml

      <primitive id="vm1" class="ocf" provider="heartbeat" type="Xen">
        <meta_attributes id="vm-template-meta_attributes">
          <nvpair id="vm-template-meta_attributes-allow-migrate" name="allow-migrate" value="true"/>
        </meta_attributes>
        <utilization id="vm-template-utilization">
          <nvpair id="vm-template-utilization-memory" name="memory" value="512"/>
        </utilization>
        <operations>
          <op id="vm-template-monitor-15s" interval="15s" name="monitor" timeout="60s"/>
          <op id="vm-template-start-0" interval="0" name="start" timeout="60s"/>
        </operations>
        <instance_attributes id="vm1-instance_attributes">
          <nvpair id="vm1-instance_attributes-name" name="name" value="vm1"/>
          <nvpair id="vm1-instance_attributes-xmfile" name="xmfile" value="/etc/xen/shared-vm/vm1"/>
        </instance_attributes>
      </primitive>

If you want to overwrite some attributes or operations, add them to the
particular primitive's definition.

.. topic:: Xen resource overriding template values

   .. code-block:: xml

      <primitive id="vm2" template="vm-template">
        <meta_attributes id="vm2-meta_attributes">
          <nvpair id="vm2-meta_attributes-allow-migrate" name="allow-migrate" value="false"/>
        </meta_attributes>
        <utilization id="vm2-utilization">
          <nvpair id="vm2-utilization-memory" name="memory" value="1024"/>
        </utilization>
        <instance_attributes id="vm2-instance_attributes">
          <nvpair id="vm2-instance_attributes-name" name="name" value="vm2"/>
          <nvpair id="vm2-instance_attributes-xmfile" name="xmfile" value="/etc/xen/shared-vm/vm2"/>
        </instance_attributes>
        <operations>
          <op id="vm2-monitor-30s" interval="30s" name="monitor" timeout="120s"/>
          <op id="vm2-stop-0" interval="0" name="stop" timeout="60s"/>
        </operations>
      </primitive>

In the example above, the new primitive ``vm2`` has special attribute values.
Its ``monitor`` operation has a longer ``timeout`` and ``interval``, and
the primitive has an additional ``stop`` operation.

To see the resulting definition of a resource, run:

.. code-block:: none

   # crm_resource --query-xml --resource vm2

To see the raw definition of a resource in the CIB, run:

.. code-block:: none

   # crm_resource --query-xml-raw --resource vm2

Using Templates in Constraints
______________________________

A resource template can be referenced in the following types of constraints:

- ``order`` constraints (see :ref:`s-resource-ordering`)
- ``colocation`` constraints (see :ref:`s-resource-colocation`)
- ``rsc_ticket`` constraints (for multi-site clusters as described in :ref:`ticket-constraints`)

Resource templates referenced in constraints stand for all primitives which are
derived from that template. This means, the constraint applies to all primitive
resources referencing the resource template. Referencing resource templates in
constraints is an alternative to resource sets and can simplify the cluster
configuration considerably.

For example, given the example templates earlier in this chapter:

.. code-block:: xml

   <rsc_colocation id="vm-template-colo-base-rsc" rsc="vm-template" rsc-role="Started" with-rsc="base-rsc" score="INFINITY"/>

would colocate all VMs with ``base-rsc`` and is the equivalent of the following constraint configuration:

.. code-block:: xml

   <rsc_colocation id="vm-colo-base-rsc" score="INFINITY">
     <resource_set id="vm-colo-base-rsc-0" sequential="false" role="Started">
       <resource_ref id="vm1"/>
       <resource_ref id="vm2"/>
     </resource_set>
     <resource_set id="vm-colo-base-rsc-1">
       <resource_ref id="base-rsc"/>
     </resource_set>
   </rsc_colocation>

.. note::

   In a colocation constraint, only one template may be referenced from either
   ``rsc`` or ``with-rsc``; the other reference must be a regular resource.

Using Templates in Resource Sets
________________________________

Resource templates can also be referenced in resource sets.

For example, given the example templates earlier in this section, then:

.. code-block:: xml

   <rsc_order id="order1" score="INFINITY">
     <resource_set id="order1-0">
       <resource_ref id="base-rsc"/>
       <resource_ref id="vm-template"/>
       <resource_ref id="top-rsc"/>
     </resource_set>
   </rsc_order>

is the equivalent of the following constraint using a sequential resource set:

.. code-block:: xml

   <rsc_order id="order1" score="INFINITY">
     <resource_set id="order1-0">
       <resource_ref id="base-rsc"/>
       <resource_ref id="vm1"/>
       <resource_ref id="vm2"/>
       <resource_ref id="top-rsc"/>
     </resource_set>
   </rsc_order>

Or, if the resources referencing the template can run in parallel, then:

.. code-block:: xml

   <rsc_order id="order2" score="INFINITY">
     <resource_set id="order2-0">
       <resource_ref id="base-rsc"/>
     </resource_set>
     <resource_set id="order2-1" sequential="false">
       <resource_ref id="vm-template"/>
     </resource_set>
     <resource_set id="order2-2">
       <resource_ref id="top-rsc"/>
     </resource_set>
   </rsc_order>

is the equivalent of the following constraint configuration:

.. code-block:: xml

   <rsc_order id="order2" score="INFINITY">
     <resource_set id="order2-0">
       <resource_ref id="base-rsc"/>
     </resource_set>
     <resource_set id="order2-1" sequential="false">
       <resource_ref id="vm1"/>
       <resource_ref id="vm2"/>
     </resource_set>
     <resource_set id="order2-2">
       <resource_ref id="top-rsc"/>
     </resource_set>
   </rsc_order>

.. _s-reusing-config-elements:

Reusing Rules, Options and Sets of Operations
#############################################

Sometimes a number of constraints need to use the same set of rules,
and resources need to set the same options and parameters.  To
simplify this situation, you can refer to an existing object using an
``id-ref`` instead of an ``id``.

So if for one resource you have

.. code-block:: xml

   <rsc_location id="WebServer-connectivity" rsc="Webserver">
      <rule id="ping-prefer-rule" score-attribute="pingd" >
       <expression id="ping-prefer" attribute="pingd" operation="defined"/>
      </rule>
   </rsc_location>

Then instead of duplicating the rule for all your other resources, you can instead specify:

.. topic:: **Referencing rules from other constraints**

   .. code-block:: xml

      <rsc_location id="WebDB-connectivity" rsc="WebDB">
         <rule id-ref="ping-prefer-rule"/>
      </rsc_location>

.. important::

   The cluster will insist that the ``rule`` exists somewhere.  Attempting
   to add a reference to a nonexistent ``id`` will cause a validation failure,
   as will attempting to remove a ``rule`` with an ``id`` that is referenced
   elsewhere.

   Some rule syntax is allowed only in
   :ref:`certain contexts <rule_conditions>`. Validation cannot ensure that the
   referenced rule is allowed in the context of the rule containing ``id-ref``,
   so such errors will be caught (and logged) only after the new configuration
   is accepted. It is the administrator's reponsibility to check for these.

The same principle applies for ``meta_attributes`` and
``instance_attributes`` as illustrated in the example below:

.. topic:: Referencing attributes, options, and operations from other resources

    .. code-block:: xml

      <primitive id="mySpecialRsc" class="ocf" type="Special" provider="me">
         <instance_attributes id="mySpecialRsc-attrs" score="1" >
           <nvpair id="default-interface" name="interface" value="eth0"/>
           <nvpair id="default-port" name="port" value="9999"/>
         </instance_attributes>
         <meta_attributes id="mySpecialRsc-options">
           <nvpair id="failure-timeout" name="failure-timeout" value="5m"/>
           <nvpair id="migration-threshold" name="migration-threshold" value="1"/>
           <nvpair id="stickiness" name="resource-stickiness" value="0"/>
         </meta_attributes>
         <operations id="health-checks">
           <op id="health-check" name="monitor" interval="60s"/>
           <op id="health-check" name="monitor" interval="30min"/>
         </operations>
      </primitive>
      <primitive id="myOtherRsc" class="ocf" type="Other" provider="me">
         <instance_attributes id-ref="mySpecialRsc-attrs"/>
         <meta_attributes id-ref="mySpecialRsc-options"/>
         <operations id-ref="health-checks"/>
      </primitive>

``id-ref`` can similarly be used with ``resource_set`` (in any constraint type),
``nvpair``, and ``operations``.

Tagging Configuration Elements
##############################

Pacemaker allows you to *tag* any configuration element that has an XML ID.

The main purpose of tagging is to support higher-level user interface tools;
Pacemaker itself only uses tags within constraints. Therefore, what you can
do with tags mostly depends on the tools you use.

Configuring Tags
________________

A tag is simply a named list of XML IDs.

.. topic:: Tag referencing three resources

   .. code-block:: xml

      <tags>
        <tag id="all-vms">
          <obj_ref id="vm1"/>
          <obj_ref id="vm2"/>
          <obj_ref id="vm3"/>
        </tag>
      </tags>

What you can do with this new tag depends on what your higher-level tools
support. For example, a tool might allow you to enable or disable all of
the tagged resources at once, or show the status of just the tagged
resources.

A single configuration element can be listed in any number of tags.

.. important::

   If listing nodes in a tag, you must list the node's ``id``, not name.


Using Tags in Constraints and Resource Sets
___________________________________________

Pacemaker itself only uses tags in constraints. If you supply a tag name
instead of a resource name in any constraint, the constraint will apply to
all resources listed in that tag.

.. topic:: Constraint using a tag

   .. code-block:: xml

      <rsc_order id="order1" first="storage" then="all-vms" kind="Mandatory" />

In the example above, assuming the ``all-vms`` tag is defined as in the previous
example, the constraint will behave the same as:

.. topic:: Equivalent constraints without tags

   .. code-block:: xml

      <rsc_order id="order1-1" first="storage" then="vm1" kind="Mandatory" />
      <rsc_order id="order1-2" first="storage" then="vm2" kind="Mandatory" />
      <rsc_order id="order1-3" first="storage" then="vm3" kind="Mandatory" />

A tag may be used directly in the constraint, or indirectly by being
listed in a :ref:`resource set <s-resource-sets>` used in the constraint.
When used in a resource set, an expanded tag will honor the set's
``sequential`` property.

Filtering With Tags
___________________

The ``crm_mon`` tool can be used to display lots of information about the
state of the cluster.  On large or complicated clusters, this can include
a lot of information, which makes it difficult to find the one thing you
are interested in.  The ``--resource=`` and ``--node=`` command line
options can be used to filter results.  In their most basic usage, these
options take a single resource or node name.  However, they can also
be supplied with a tag name to display several objects at once.

For instance, given the following CIB section:

.. code-block:: xml

   <resources>
     <primitive class="stonith" id="Fencing" type="fence_xvm"/>
     <primitive class="ocf" id="dummy" provider="pacemaker" type="Dummy"/>
     <group id="inactive-group">
       <primitive class="ocf" id="inactive-dummy-1" provider="pacemaker" type="Dummy"/>
       <primitive class="ocf" id="inactive-dummy-2" provider="pacemaker" type="Dummy"/>
     </group>
     <clone id="inactive-clone">
       <primitive id="inactive-dhcpd" class="systemd" type="dhcpd"/>
     </clone>
   </resources>
   <tags>
     <tag id="inactive-rscs">
       <obj_ref id="inactive-group"/>
       <obj_ref id="inactive-clone"/>
     </tag>
   </tags>

The following would be output for ``crm_mon --resource=inactive-rscs -r``:

.. code-block:: none

   Cluster Summary:
     * Stack: corosync
     * Current DC: cluster02 (version 2.0.4-1.e97f9675f.git.el7-e97f9675f) - partition with quorum
     * Last updated: Tue Oct 20 16:09:01 2020
     * Last change:  Tue May  5 12:04:36 2020 by hacluster via crmd on cluster01
     * 5 nodes configured
     * 27 resource instances configured (4 DISABLED)

   Node List:
     * Online: [ cluster01 cluster02 ]

   Full List of Resources:
     * Clone Set: inactive-clone [inactive-dhcpd] (disabled):
       * Stopped (disabled): [ cluster01 cluster02 ]
     * Resource Group: inactive-group (disabled):
       * inactive-dummy-1  (ocf::pacemaker:Dummy):  Stopped (disabled)
       * inactive-dummy-2  (ocf::pacemaker:Dummy):  Stopped (disabled)
