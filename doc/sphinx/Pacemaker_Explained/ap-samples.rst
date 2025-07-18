Sample Configurations
---------------------

Empty
#####

.. topic:: An Empty Configuration

   .. code-block:: xml

      <cib crm_feature_set="3.0.7" validate-with="pacemaker-1.2" admin_epoch="1" epoch="0" num_updates="0">
        <configuration>
          <crm_config/>
          <nodes/>
          <resources/>
          <constraints/>
        </configuration>
        <status/>
      </cib>

Simple
######

.. topic:: A simple configuration with two nodes, some cluster options and a resource

   .. code-block:: xml

      <cib crm_feature_set="3.0.7" validate-with="pacemaker-1.2" admin_epoch="1" epoch="0" num_updates="0">
        <configuration>
          <crm_config>
            <cluster_property_set id="cib-bootstrap-options">
              <nvpair id="option-1" name="symmetric-cluster" value="true"/>
              <nvpair id="option-2" name="no-quorum-policy" value="stop"/>
              <nvpair id="option-3" name="stonith-enabled" value="0"/>
            </cluster_property_set>
          </crm_config>
          <nodes>
            <node id="xxx" uname="c001n01" type="normal"/>
            <node id="yyy" uname="c001n02" type="normal"/>
          </nodes>
          <resources>
            <primitive id="myAddr" class="ocf" provider="heartbeat" type="IPaddr">
              <operations>
                <op id="myAddr-monitor" name="monitor" interval="300s"/>
              </operations>
              <instance_attributes id="myAddr-params">
                <nvpair id="myAddr-ip" name="ip" value="192.0.2.10"/>
              </instance_attributes>
            </primitive>
          </resources>
          <constraints>
            <rsc_location id="myAddr-prefer" rsc="myAddr" node="c001n01" score="INFINITY"/>
          </constraints>
          <rsc_defaults>
            <meta_attributes id="rsc_defaults-options">
              <nvpair id="rsc-default-1" name="resource-stickiness" value="100"/>
              <nvpair id="rsc-default-2" name="migration-threshold" value="10"/>
            </meta_attributes>
          </rsc_defaults>
          <op_defaults>
            <meta_attributes id="op_defaults-options">
              <nvpair id="op-default-1" name="timeout" value="30s"/>
            </meta_attributes>
          </op_defaults>
        </configuration>
        <status/>
      </cib>

In the above example, we have one resource (an IP address) that we check
every five minutes and will run on host ``c001n01`` until either the
resource fails 10 times or the host shuts down.

Advanced Configuration
######################

.. topic:: An advanced configuration with groups, clones and STONITH

   .. code-block:: xml

      <cib crm_feature_set="3.0.7" validate-with="pacemaker-1.2" admin_epoch="1" epoch="0" num_updates="0">
        <configuration>
          <crm_config>
            <cluster_property_set id="cib-bootstrap-options">
              <nvpair id="option-1" name="symmetric-cluster" value="true"/>
              <nvpair id="option-2" name="no-quorum-policy" value="stop"/>
              <nvpair id="option-3" name="stonith-enabled" value="true"/>
            </cluster_property_set>
          </crm_config>
          <nodes>
            <node id="xxx" uname="c001n01" type="normal"/>
            <node id="yyy" uname="c001n02" type="normal"/>
            <node id="zzz" uname="c001n03" type="normal"/>
          </nodes>
          <resources>
            <primitive id="myAddr" class="ocf" provider="heartbeat" type="IPaddr">
              <operations>
                <op id="myAddr-monitor" name="monitor" interval="300s"/>
              </operations>
              <instance_attributes id="myAddr-attrs">
                <nvpair id="myAddr-attr-1" name="ip" value="192.0.2.10"/>
              </instance_attributes>
            </primitive>
            <group id="myGroup">
              <primitive id="database" class="systemd" type="mariadb">
                <operations>
                  <op id="database-monitor" name="monitor" interval="300s"/>
                </operations>
              </primitive>
              <primitive id="webserver" class="systemd" type="httpd">
                <operations>
                  <op id="webserver-monitor" name="monitor" interval="300s"/>
                </operations>
              </primitive>
            </group>
            <clone id="STONITH">
              <meta_attributes id="stonith-options">
                <nvpair id="stonith-option-1" name="globally-unique" value="false"/>
              </meta_attributes>
              <primitive id="stonithclone" class="stonith" type="external/ssh">
                <operations>
                  <op id="stonith-op-mon" name="monitor" interval="5s"/>
                </operations>
                <instance_attributes id="stonith-attrs">
                  <nvpair id="stonith-attr-1" name="hostlist" value="c001n01,c001n02"/>
                </instance_attributes>
              </primitive>
            </clone>
          </resources>
          <constraints>
            <rsc_location id="myAddr-prefer" rsc="myAddr" node="c001n01"
              score="INFINITY"/>
            <rsc_colocation id="group-with-ip" rsc="myGroup" with-rsc="myAddr"
              score="INFINITY"/>
          </constraints>
          <op_defaults>
            <meta_attributes id="op_defaults-options">
              <nvpair id="op-default-1" name="timeout" value="30s"/>
            </meta_attributes>
          </op_defaults>
          <rsc_defaults>
            <meta_attributes id="rsc_defaults-options">
              <nvpair id="rsc-default-1" name="resource-stickiness" value="100"/>
              <nvpair id="rsc-default-2" name="migration-threshold" value="10"/>
            </meta_attributes>
          </rsc_defaults>
        </configuration>
        <status/>
      </cib>
