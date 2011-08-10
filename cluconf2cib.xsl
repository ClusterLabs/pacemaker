<?xml version="1.0" ?>

<!-- Convert a flattened cluster.conf into a cib.xml -->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
		xmlns:cluster="http://dev/null"
		version="2.0">

<xsl:output method="xml" indent="yes"/>

<xsl:function name="cluster:normalize">
	<xsl:param name="val"/>
	<xsl:value-of select="translate($val, ': .=', '____')"/>
</xsl:function>


<!-- transpose failover domain score -->
<xsl:function name="cluster:domscore">
	<xsl:param name="val"/>
	<xsl:param name="prioritized"/>
	<xsl:choose>
		<xsl:when test="($prioritized = 1)">
			<xsl:choose>
				<xsl:when test="($val >= 1)">
					<xsl:value-of select="(101-$val)*10000"/>
				</xsl:when>
				<xsl:otherwise>
					500000
				</xsl:otherwise>
			</xsl:choose>
		</xsl:when>
		<xsl:otherwise>
			1000000
		</xsl:otherwise>
	</xsl:choose>
</xsl:function>

<xsl:function name="cluster:textify-score">
	<xsl:param name="val"/>
	<xsl:choose>
		<xsl:when test="(number($val) = 1000000)">INFINITY</xsl:when>
		<xsl:when test="(number($val) = -1000000)">-INFINITY</xsl:when>
		<xsl:otherwise>
			<xsl:value-of select="$val"/>
		</xsl:otherwise>
	</xsl:choose>
</xsl:function>


<xsl:function name="cluster:getname">
	<xsl:param name="ele" as="element()" />
	<xsl:value-of select="$ele" />
</xsl:function>


<xsl:function name="cluster:makeresname">
	<xsl:param name="ele" as="element()" />
        <xsl:choose>
		<xsl:when test="name($ele) = 'ip'">
			<xsl:sequence select="concat(name($ele),'_',cluster:normalize($ele/@address))"/>
		</xsl:when>
		<xsl:otherwise>
			<xsl:sequence select="concat(name($ele),'_',cluster:normalize($ele/@name))"/>
		</xsl:otherwise>
	</xsl:choose>
</xsl:function>

<!-- STONITH host map generator -->
<xsl:function name="cluster:stonith-map-int" >
	<xsl:param name="device" />
	<xsl:param name="pos" as="element()" />
	<xsl:for-each select="$pos/../../clusternodes/clusternode">
		<xsl:variable name="node" select="@name"/>
		<xsl:for-each select="fence/method/device[@name=$device]">
			<xsl:if test="$node != @port" >
				<xsl:sequence select="concat($node,':',@port)"/>
			</xsl:if>
		</xsl:for-each>
	</xsl:for-each>
</xsl:function>

<xsl:function name="cluster:stonith-host-map" >
	<xsl:param name="device" />
	<xsl:param name="pos" as="element()" />
	<xsl:variable name="ret" select="cluster:stonith-map-int($device,$pos)" />
	<xsl:sequence select="string-join($ret,',')" />
</xsl:function>

<!-- STONITH host list generator -->
<xsl:function name="cluster:stonith-host-list" >
	<xsl:param name="device" />
	<xsl:param name="pos" as="element()" />
	<xsl:for-each select="$pos/../../clusternodes/clusternode">
		<xsl:variable name="node" select="@name"/>
		<xsl:for-each select="fence/method/device[@name=$device]">
			<xsl:sequence select="$node"/>
		</xsl:for-each>
	</xsl:for-each>
</xsl:function>

<xsl:template match="service" mode="#default">
	<!-- Pacemaker doesn't like empty groups -->
	<xsl:if test="child::*">
	  <group id="{concat('service_', @name)}">
	  <xsl:for-each select="child::*">
	  <xsl:variable name="resname" select="cluster:makeresname(self::node())"/>
	  <primitive class="ocf" id="{$resname}" provider="redhat" type="{name()}" >
	    <instance_attributes id="{$resname}_inst_attrs" >
	      <xsl:for-each select="@*">
	        <nvpair id="{$resname}_{name()}" name="{name()}" value="{.}" />
	      </xsl:for-each>
	    </instance_attributes>
	  </primitive>
	  </xsl:for-each>
	  </group>
	</xsl:if>
</xsl:template>

<xsl:template match="vm" mode="#default">
	<xsl:variable name="resname" select="cluster:makeresname(self::node())"/>
	<primitive class="ocf" id="{$resname}" provider="redhat" type="{.}" >
	  <instance_attributes id="{$resname}_inst_attrs" >
	    <xsl:for-each select="@*">
	      <nvpair id="{$resname}_{name()}" name="{name()}" value="{.}" />
	    </xsl:for-each>
	  </instance_attributes>
	</primitive>
</xsl:template>


<!-- Failover Domains -->
<!-- Node definition:
     failoverdomainnode -> node
     priority (1..100) -> value, 1000000 .. 1000;
       (101-priority)*10000
 -->
<xsl:template match="failoverdomainnode">
      <node name="{@name}" score="{cluster:textify-score(format-number(cluster:domscore(@priority,../@ordered),'#'))}"/>
</xsl:template>

<!-- failoverdomain definition:
     failoverdomain -> domain
       name       -> id
       ordered    -> N/A
       restricted -> N/A
 -->
<xsl:template match="failoverdomain" mode="#default">
    <domain id="{@name}">
      <xsl:apply-templates select="failoverdomainnode"/>
    </domain>
</xsl:template>

<xsl:template match="failoverdomains" mode="#default">
  <domains><xsl:apply-templates select="failoverdomain"/>
  </domains>
</xsl:template>

<!-- Service / VMs - link with domain constraint -->
<xsl:template match="service|vm" mode="domlink">
  <xsl:variable name="resname" select="cluster:makeresname(self::node())"/>
  <xsl:if test="@domain">
    <rsc_location id="{$resname}_{@domain}" rsc="{$resname}" domain="{@domain}"/>
  </xsl:if>
</xsl:template>

<!-- rgmanager tag handling -->
<xsl:template match="rm" mode="#default">
    <xsl:apply-templates select="failoverdomains"/>
    <resources>
      <xsl:apply-templates select="service|vm" />
      <!-- todo: STONITH resources here -->
      <xsl:apply-templates select="../fencedevices" />
    </resources>
    <constraints>
      <xsl:apply-templates select="service|vm" mode="domlink"/>
    </constraints>
</xsl:template>

<xsl:template match="clusternode" mode="#default">
	<node id="{concat('node_', @nodeid)}" uname="{@name}" type="normal"/>
</xsl:template>

<xsl:template match="clusternodes" mode="#default">
    <nodes><xsl:apply-templates select="clusternode"/>
    </nodes>
</xsl:template>

<!-- STONITH configuration -->
<xsl:template match="fencedevice" mode="#default">
      <xsl:variable name="name" select="concat('st_',@name)"/>
      <primitive class="stonith" id="{$name}" type="{@agent}">
      	<operations>
      	  <op id="{$name}_mon" name="monitor" interval="120s"/>
      	</operations>
      	<instance_attributes id="{$name}_attrs">
	  <xsl:for-each select="@*">
	    <xsl:choose>
	      <xsl:when test="name() = 'name'" />
	      <xsl:when test="name() = 'agent'" />
	      <xsl:otherwise>
	        <nvpair id="{$name}_{name()}" name="{name()}" value="{.}" />
	      </xsl:otherwise>
	    </xsl:choose>
	  </xsl:for-each>

	  <xsl:variable name="hostlist" select="cluster:stonith-host-list(@name,self::node())" />
	  <xsl:variable name="hostmap" select="cluster:stonith-host-map(@name,self::node())" />

	  <xsl:if test="$hostlist != ''" >
	    <nvpair id="{$name}_hosts" name="pcmk_host_list" value="{$hostlist}"/>
	  </xsl:if>
	  <xsl:if test="$hostmap != ''" >
	    <nvpair id="{$name}_map" name="pcmk_host_map" value="{$hostmap}"/>
	  </xsl:if>
      	</instance_attributes>
      </primitive>
</xsl:template>

<xsl:template match="fencedevices" mode="#default">
	<xsl:apply-templates select="fencedevice" />
</xsl:template>


<xsl:template match="/cluster">
<cib validate-with="pacemaker-1.1" admin_epoch="1" epoch="1" num_updates="0" >
  <configuration>
    <crm_config>
      <cluster_property_set id="cib-bootstrap-options">
        <nvpair id="startup-fencing" name="startup-fencing" value="true"/>
        <nvpair id="stonith-enabled" name="stonith-enabled" value="true"/>
        <nvpair id="default-resource-stickiness" name="default-resource-stickiness" value="INFINITY"/>
      </cluster_property_set>
    </crm_config>
    <xsl:apply-templates select="clusternodes"/>
    <xsl:apply-templates select="rm"/>
  </configuration>
  <status/>
</cib>
</xsl:template>
</xsl:stylesheet>
