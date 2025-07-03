Moving Resources
----------------

.. index::
   single: resource; move

Moving Resources Manually
#########################

There are primarily two occasions when you would want to move a resource from
its current location: when the whole node is under maintenance, and when a
single resource needs to be moved.

.. index::
   single: standby mode
   single: node; standby mode

Standby Mode
____________

Since everything eventually comes down to a score, you could create constraints
for every resource to prevent them from running on one node. While Pacemaker
configuration can seem convoluted at times, not even we would require this of
administrators.

Instead, you can set a special node attribute which tells the cluster "don't
let anything run here". There is even a helpful tool to help query and set it,
called ``crm_standby``. To check the standby status of the current machine,
run:

.. code-block:: none

   # crm_standby -G

A value of ``on`` indicates that the node is *not* able to host any resources,
while a value of ``off`` says that it *can*.

You can also check the status of other nodes in the cluster by specifying the
`--node` option:

.. code-block:: none

   # crm_standby -G --node sles-2

To change the current node's standby status, use ``-v`` instead of ``-G``:

.. code-block:: none

   # crm_standby -v on

Again, you can change another host's value by supplying a hostname with
``--node``.

A cluster node in standby mode will not run resources, but still contributes to
quorum, and may fence or be fenced by nodes.

Moving One Resource
___________________

When only one resource is required to move, we could do this by creating
location constraints.  However, once again we provide a user-friendly shortcut
as part of the ``crm_resource`` command, which creates and modifies the extra
constraints for you.  If ``Email`` were running on ``sles-1`` and you wanted it
moved to a specific location, the command would look something like:

.. code-block:: none

   # crm_resource -M -r Email -H sles-2

Behind the scenes, the tool will create the following location constraint:

.. code-block:: xml

   <rsc_location id="cli-prefer-Email" rsc="Email" node="sles-2" score="INFINITY"/>

It is important to note that subsequent invocations of ``crm_resource -M`` are
not cumulative. So, if you ran these commands:

.. code-block:: none

   # crm_resource -M -r Email -H sles-2
   # crm_resource -M -r Email -H sles-3

then it is as if you had never performed the first command.

To allow the resource to move back again, use:

.. code-block:: none

   # crm_resource -U -r Email

Note the use of the word *allow*.  The resource *can* move back to its original
location, but depending on ``resource-stickiness``, location constraints, and
so forth, it might stay where it is.

To be absolutely certain that it moves back to ``sles-1``, move it there before
issuing the call to ``crm_resource -U``:

.. code-block:: none

   # crm_resource -M -r Email -H sles-1
   # crm_resource -U -r Email

Alternatively, if you only care that the resource should be moved from its
current location, try:

.. code-block:: none

   # crm_resource -B -r Email

which will instead create a negative constraint, like:

.. code-block:: xml

   <rsc_location id="cli-ban-Email-on-sles-1" rsc="Email" node="sles-1" score="-INFINITY"/>

This will achieve the desired effect, but will also have long-term
consequences. As the tool will warn you, the creation of a ``-INFINITY``
constraint will prevent the resource from running on that node until
``crm_resource -U`` is used. This includes the situation where every other
cluster node is no longer available!

In some cases, such as when ``resource-stickiness`` is set to ``INFINITY``, it
is possible that you will end up with nodes with the same score, forcing the
cluster to choose one (which may not be the one you want). The tool can detect
some of these cases and deals with them by creating both positive and negative
constraints. For example:

.. code-block:: xml

   <rsc_location id="cli-ban-Email-on-sles-1" rsc="Email" node="sles-1" score="-INFINITY"/>
   <rsc_location id="cli-prefer-Email" rsc="Email" node="sles-2" score="INFINITY"/>

which has the same long-term consequences as discussed earlier.

Moving Resources Due to Connectivity Changes
############################################

You can configure the cluster to move resources when external connectivity is
lost in two steps.

.. index::
   single: ocf:pacemaker:ping resource
   single: ping resource

Tell Pacemaker to Monitor Connectivity
______________________________________

First, add an ``ocf:pacemaker:ping`` resource to the cluster. The ``ping``
resource uses the system utility of the same name to a test whether a list of
machines (specified by DNS hostname or IP address) are reachable, and uses the
results to maintain a node attribute.

The node attribute is called ``pingd`` by default, but is customizable in order
to allow multiple ping groups to be defined.

Normally, the ping resource should run on all cluster nodes, which means that
you'll need to create a clone. A template for this can be found below, along
with a description of the most interesting parameters.

.. list-table:: **Commonly Used ocf:pacemaker:ping Resource Parameters**
   :widths: 20 80
   :header-rows: 1

   * - Resource Parameter
     - Description
   * - dampen
     - .. index::
          single: ocf:pacemaker:ping resource; dampen parameter
          single: dampen; ocf:pacemaker:ping resource parameter

       The time to wait (dampening) for further changes to occur.  Use this to
       prevent a resource from bouncing around the cluster when cluster nodes
       notice the loss of connectivity at slightly different times.
   * - multiplier
     - .. index::
          single: ocf:pacemaker:ping resource; multiplier parameter
          single: multiplier; ocf:pacemaker:ping resource parameter

       The number of connected ping nodes gets multiplied by this value to get
       a score. Useful when there are multiple ping nodes configured.
   * - host_list
     - .. index::
          single: ocf:pacemaker:ping resource; host_list parameter
          single: host_list; ocf:pacemaker:ping resource parameter

       The machines to contact in order to determine the current connectivity
       status. Allowed values include resolvable DNS connectivity host names,
       IPv4 addresses, and IPv6 addresses.

.. topic:: Example ping resource that checks node connectivity once every minute

   .. code-block:: xml

      <clone id="Connected">
         <primitive id="ping" class="ocf" provider="pacemaker" type="ping">
          <instance_attributes id="ping-attrs">
            <nvpair id="ping-dampen"     name="dampen" value="5s"/>
            <nvpair id="ping-multiplier" name="multiplier" value="1000"/>
            <nvpair id="ping-hosts"      name="host_list" value="my.gateway.com www.bigcorp.com"/>
          </instance_attributes>
          <operations>
            <op id="ping-monitor-60s" interval="60s" name="monitor"/>
          </operations>
         </primitive>
      </clone>

.. important::

   You're only half done. The next section deals with telling Pacemaker how to
   deal with the connectivity status that ``ocf:pacemaker:ping`` is recording.

Tell Pacemaker How to Interpret the Connectivity Data
_____________________________________________________

.. important::

   Before attempting the following, make sure you understand rules. See the
   "Rules" chapter of the *Pacemaker Explained* document for details.

There are a number of ways to use the connectivity data.

The most common setup is for people to have a single ping target (for example,
the service network's default gateway), to prevent the cluster from running a
resource on any unconnected node.

.. topic:: Don't run a resource on unconnected nodes

   .. code-block:: xml

      <rsc_location id="WebServer-no-connectivity" rsc="Webserver">
         <rule id="ping-exclude-rule" score="-INFINITY" >
            <expression id="ping-exclude" attribute="pingd" operation="not_defined"/>
         </rule>
      </rsc_location>

A more complex setup is to have a number of ping targets configured. You can
require the cluster to only run resources on nodes that can connect to all (or
a minimum subset) of them.

.. topic:: Run only on nodes connected to three or more ping targets

   .. code-block:: xml

      <primitive id="ping" provider="pacemaker" class="ocf" type="ping">
      ... <!-- omitting some configuration to highlight important parts -->
         <nvpair id="ping-multiplier" name="multiplier" value="1000"/>
      ...
      </primitive>
      ...
      <rsc_location id="WebServer-connectivity" rsc="Webserver">
         <rule id="ping-prefer-rule" score="-INFINITY" >
            <expression id="ping-prefer" attribute="pingd" operation="lt" value="3000"/>
         </rule>
      </rsc_location>

Alternatively, you can tell the cluster only to *prefer* nodes with the best
connectivity, by using ``score-attribute`` in the rule. Just be sure to set
``multiplier`` to a value higher than that of ``resource-stickiness`` (and
don't set either of them to ``INFINITY``).

.. topic:: Prefer node with most connected ping nodes

   .. code-block:: xml

      <rsc_location id="WebServer-connectivity" rsc="Webserver">
         <rule id="ping-prefer-rule" score-attribute="pingd" >
            <expression id="ping-prefer" attribute="pingd" operation="defined"/>
         </rule>
      </rsc_location>

It is perhaps easier to think of this in terms of the simple constraints that
the cluster translates it into. For example, if ``sles-1`` is connected to all
five ping nodes but ``sles-2`` is only connected to two, then it would be as if
you instead had the following constraints in your configuration:

.. topic:: How the cluster translates the above location constraint

   .. code-block:: xml

      <rsc_location id="ping-1" rsc="Webserver" node="sles-1" score="5000"/>
      <rsc_location id="ping-2" rsc="Webserver" node="sles-2" score="2000"/>

The advantage is that you don't have to manually update any constraints
whenever your network connectivity changes.

You can also combine the concepts above into something even more complex. The
example below shows how you can prefer the node with the most connected ping
nodes provided they have connectivity to at least three (again assuming that
``multiplier`` is set to 1000).

.. topic:: More complex example of choosing location based on connectivity

   .. code-block:: xml

      <rsc_location id="WebServer-connectivity" rsc="Webserver">
         <rule id="ping-exclude-rule" score="-INFINITY" >
            <expression id="ping-exclude" attribute="pingd" operation="lt" value="3000"/>
         </rule>
         <rule id="ping-prefer-rule" score-attribute="pingd" >
            <expression id="ping-prefer" attribute="pingd" operation="defined"/>
         </rule>
      </rsc_location>
