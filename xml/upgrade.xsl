<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
		xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
		xmlns:fn="http://www.w3.org/2005/02/xpath-functions">
<xsl:output method='xml' version='1.0' encoding='UTF-8' indent='yes'/>

<!-- Utility templates -->
<xsl:template name="auto-id">
  <xsl:attribute name="id">
    <xsl:value-of select="name()"/>
    <xsl:text>.</xsl:text>
    <xsl:value-of select="generate-id()"/>
  </xsl:attribute>
</xsl:template>

<xsl:template name="lower-case-value">
  <xsl:param name="value"/> 
  <xsl:value-of select="translate($value, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
</xsl:template>

<xsl:template name="upper-case-value">
  <xsl:param name="value"/> 
  <xsl:value-of select="translate($value, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
</xsl:template>

<xsl:template name="camel-case-value">
  <xsl:param name="value"/> 
    <xsl:call-template name="upper-case-value">
      <xsl:with-param name="value"><xsl:value-of select="substring($value,1,1)"/></xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="lower-case-value">
      <xsl:with-param name="value"><xsl:value-of select="substring($value,2)"/></xsl:with-param>
    </xsl:call-template>
</xsl:template>

<xsl:template name="create-as-attr"> 
  <xsl:param name="name"/> 
  <xsl:param name="value"/> 
  <xsl:element name="nvpair">
    <xsl:attribute name="id">
      <xsl:value-of select="name()"/>
      <xsl:text>.meta.auto-</xsl:text>
      <xsl:number level="any" from="cib" count="node()"/>
    </xsl:attribute>
    <xsl:attribute name="name">
      <xsl:value-of select="translate($name,'_','-')"/>
    </xsl:attribute>
    <xsl:attribute name="value">
      <xsl:value-of select="$value"/>
    </xsl:attribute>
  </xsl:element>
</xsl:template> 

<xsl:template name="convert-instance-to-meta">
  <xsl:for-each select="instance_attributes//nvpair[@name='resource_stickiness']"> 
    <xsl:call-template name="create-as-attr">
      <xsl:with-param name="name"><xsl:value-of select="translate(@name, '_', '-')"/></xsl:with-param>
      <xsl:with-param name="value"><xsl:value-of select="@value"/></xsl:with-param>
    </xsl:call-template>
  </xsl:for-each>
  <xsl:for-each select="instance_attributes//nvpair[@name='allow_migrate']"> 
    <xsl:call-template name="create-as-attr">
      <xsl:with-param name="name"><xsl:value-of select="translate(@name, '_', '-')"/></xsl:with-param>
      <xsl:with-param name="value"><xsl:value-of select="@value"/></xsl:with-param>
    </xsl:call-template>
  </xsl:for-each>
  <xsl:for-each select="instance_attributes//nvpair[@name='globally_unique']"> 
    <xsl:call-template name="create-as-attr">
      <xsl:with-param name="name"><xsl:value-of select="translate(@name, '_', '-')"/></xsl:with-param>
      <xsl:with-param name="value"><xsl:value-of select="@value"/></xsl:with-param>
    </xsl:call-template>
  </xsl:for-each>
  <xsl:for-each select="instance_attributes//nvpair[@name='target_role']"> 
    <xsl:call-template name="create-as-attr">
      <xsl:with-param name="name"><xsl:value-of select="translate(@name, '_', '-')"/></xsl:with-param>
      <xsl:with-param name="value"><xsl:value-of select="@value"/></xsl:with-param>
    </xsl:call-template>
  </xsl:for-each>
  <xsl:for-each select="instance_attributes//nvpair[@name='clone_max']"> 
    <xsl:call-template name="create-as-attr">
      <xsl:with-param name="name"><xsl:value-of select="translate(@name, '_', '-')"/></xsl:with-param>
      <xsl:with-param name="value"><xsl:value-of select="@value"/></xsl:with-param>
    </xsl:call-template>
  </xsl:for-each>
  <xsl:for-each select="instance_attributes//nvpair[@name='clone_node_max']"> 
    <xsl:call-template name="create-as-attr">
      <xsl:with-param name="name"><xsl:value-of select="translate(@name, '_', '-')"/></xsl:with-param>
      <xsl:with-param name="value"><xsl:value-of select="@value"/></xsl:with-param>
    </xsl:call-template>
  </xsl:for-each>
  <xsl:for-each select="instance_attributes//nvpair[@name='master_max']"> 
    <xsl:call-template name="create-as-attr">
      <xsl:with-param name="name"><xsl:value-of select="translate(@name, '_', '-')"/></xsl:with-param>
      <xsl:with-param name="value"><xsl:value-of select="@value"/></xsl:with-param>
    </xsl:call-template>
  </xsl:for-each>
  <xsl:for-each select="instance_attributes//nvpair[@name='master_node_max']"> 
    <xsl:call-template name="create-as-attr">
      <xsl:with-param name="name"><xsl:value-of select="translate(@name, '_', '-')"/></xsl:with-param>
      <xsl:with-param name="value"><xsl:value-of select="@value"/></xsl:with-param>
    </xsl:call-template>
  </xsl:for-each>
</xsl:template>

<xsl:template match="instance_attributes">
  <xsl:element name="instance_attributes">
    <xsl:call-template name="auto-id"/>
    <xsl:element name="attributes">
      <xsl:for-each select="attributes//nvpair"> 
	<xsl:element name="nvpair">
	  <xsl:apply-templates select="@*"/>
	  <xsl:call-template name="auto-id"/>
	</xsl:element>
      </xsl:for-each>
    </xsl:element>
  </xsl:element>
</xsl:template>

<xsl:template match="meta_attributes">
  <xsl:element name="meta_attributes">
    <xsl:call-template name="auto-id"/>
    <xsl:element name="attributes">
      <xsl:for-each select="attributes//nvpair">
	<xsl:element name="nvpair">
	  <xsl:call-template name="auto-id"/>
	  <xsl:attribute name="name"><xsl:value-of select="translate(@name, '_', '-')"/></xsl:attribute>
	  <xsl:attribute name="value"><xsl:value-of select="@value"/></xsl:attribute>
	</xsl:element>
	</xsl:for-each>
    </xsl:element>
  </xsl:element>
</xsl:template>

<!-- Sanitizing templates -->

<xsl:template match="@generated|@ccm_transition|@num_peers|@cib_last_written|@ignore_dtd|@crm-debug-origin">
  <!-- swallow -->
</xsl:template>

<xsl:template match="@disabled">
  <xsl:attribute name="enabled">true</xsl:attribute>
  <xsl:if test="contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'true')">
    <xsl:attribute name="enabled">false</xsl:attribute>
  </xsl:if>
</xsl:template>

<xsl:template match="@action">
  <xsl:attribute name="rsc-action">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="@to_action">
  <xsl:attribute name="before-rsc-action">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="@score">
  <xsl:attribute name="{name()}">
    <xsl:if test="contains(., '.')">
      <xsl:value-of select="substring-before(.,'.')"/>
    </xsl:if>
    <xsl:if test="not(contains(., '.'))">
      <xsl:call-template name="upper-case-value">
	<xsl:with-param name="value"><xsl:value-of select="."/></xsl:with-param>
      </xsl:call-template>
    </xsl:if>
  </xsl:attribute>
</xsl:template>

<xsl:template match="@provider">
  <!-- only set provider for OCF resources -->
  <xsl:if test="contains(../@class, 'ocf')">
    <xsl:attribute name="{name()}">
      <xsl:value-of select="."/>
    </xsl:attribute>
  </xsl:if>
</xsl:template>

<xsl:template match="@id">
  <xsl:attribute name="{name()}">
    <xsl:choose>
      <!-- IDs cant start with a digit -->
      <xsl:when test='not(string(number(substring(.,1,1))) = "NaN")'>
	<!-- set an automatic id -->
	<xsl:for-each select=".."> 
	  <xsl:value-of select="name()"/>
	  <xsl:text>.auto-</xsl:text>
	  <xsl:number level="any"/>
	</xsl:for-each>
      </xsl:when>
      <xsl:otherwise>
	<xsl:value-of select="translate(., ':', '-')"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:attribute>
</xsl:template>


<!-- Rename templates -->
<xsl:template match="@admin_epoch|@num_updates|@boolean_op|@cib_feature_revision|@crm_feature_set|@on_fail|@have_quorum|@dc_uuid|@op_status|@transition_magic|@call_id|@rc_code|@op_digest|@transition_key|@op_restart_digest|@op_force_restart|@score_attribute|@score_attribute_mangled|@start_delay">
  <xsl:attribute name="{translate(name(),'_','-')}">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="@prereq">
  <xsl:attribute name="requires">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="@name">
  <xsl:attribute name="{name()}">
    <xsl:choose>

      <xsl:when test="contains(., 'default_resource_stickiness')">
	<xsl:value-of select="translate(., '_', '-')"/>
      </xsl:when>
      <xsl:when test="contains(., 'no_quorum_policy')">
	<xsl:value-of select="translate(., '_', '-')"/>
      </xsl:when>
      <xsl:when test="contains(., 'transition_idle_timeout')">
	<xsl:text>cluster-delay</xsl:text>
      </xsl:when>
      <xsl:when test="contains(., 'symmetric_cluster')">
	<xsl:value-of select="translate(., '_', '-')"/>
      </xsl:when>
      <xsl:when test="contains(., 'stonith_enabled')">
	<xsl:value-of select="translate(., '_', '-')"/>
      </xsl:when>
      <xsl:when test="contains(., 'stonith_action')">
	<xsl:value-of select="translate(., '_', '-')"/>
      </xsl:when>
      <xsl:when test="contains(., 'is_managed_default')">
	<xsl:value-of select="translate(., '_', '-')"/>
      </xsl:when>
      <xsl:when test="contains(., 'stop_orphan_resources')">
	<xsl:value-of select="translate(., '_', '-')"/>
      </xsl:when>
      <xsl:when test="contains(., 'stop_orphan_actions')">
	<xsl:value-of select="translate(., '_', '-')"/>
      </xsl:when>
      <xsl:when test="contains(., 'remove_after_stop')">
	<xsl:value-of select="translate(., '_', '-')"/>
      </xsl:when>
<!--
      <xsl:when test="contains(., '')">
	<xsl:value-of select="translate(., '_', '-')"/>
      </xsl:when>
-->
      <xsl:otherwise>
	<xsl:value-of select="."/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:attribute>
</xsl:template>

<!-- regular transformations -->
<xsl:template name="resource-common">
    <xsl:if test="contains(name(), 'primitive')">
      <xsl:for-each select="@*"> 
	<xsl:choose>
	  <xsl:when test="starts-with(name(), 'type')">
	    <xsl:apply-templates select="."/>
	  </xsl:when>
	  <xsl:when test="starts-with(name(), 'class')">
	    <xsl:apply-templates select="."/>
	  </xsl:when>
	  <xsl:when test="starts-with(name(), 'provider')">
	    <xsl:apply-templates select="."/>
	  </xsl:when>
	</xsl:choose>
      </xsl:for-each>
    </xsl:if>

    <xsl:if test="@description">
      <xsl:apply-templates select="@description"/>
    </xsl:if>

    <xsl:apply-templates select="node()"/>

    <xsl:element name="meta_attributes">
      <xsl:attribute name="id">
	<xsl:value-of select="name()"/>
	<xsl:text>-</xsl:text>
	<xsl:value-of select="@id"/>
	<xsl:text>.meta</xsl:text>
      </xsl:attribute>
      <xsl:element name="attributes">
	<xsl:for-each select="@*"> 
	  <xsl:choose>
	    <xsl:when test="starts-with(name(), 'id')"/>
	    <xsl:when test="starts-with(name(), 'type')"/>
	    <xsl:when test="starts-with(name(), 'class')"/>
	    <xsl:when test="starts-with(name(), 'provider')"/>
	    <xsl:when test="starts-with(name(), 'description')"/>
	    <xsl:otherwise>
	      <xsl:call-template name="create-as-attr">
		<xsl:with-param name="name"><xsl:value-of select="name()"/></xsl:with-param>
		<xsl:with-param name="value"><xsl:value-of select="."/></xsl:with-param>
	      </xsl:call-template>
	    </xsl:otherwise>
	  </xsl:choose>
	</xsl:for-each>
	<xsl:call-template name="convert-instance-to-meta"/>
      </xsl:element>
    </xsl:element>

</xsl:template>

<xsl:template match="primitive">
  <xsl:element name="{name()}">
    <xsl:attribute name="id">
      <xsl:value-of select="@id"/>
    </xsl:attribute>
    <xsl:call-template name="resource-common"/>
  </xsl:element>
</xsl:template>

<xsl:template match="group|clone">
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@id"/>
    <xsl:call-template name="resource-common"/>
  </xsl:element>
</xsl:template>

<xsl:template match="master_slave">
  <xsl:element name="master">
    <xsl:apply-templates select="@id"/>
    <xsl:call-template name="resource-common"/>
  </xsl:element>
</xsl:template>

<xsl:template name="rename-default"> 
  <xsl:param name="newvalue"/> 
  <xsl:param name="oldvalue"/> 
  <xsl:param name="default"/> 
  <xsl:choose>
    <xsl:when test="string-length($newvalue) > 0">
      <xsl:value-of select="$newvalue"/>
    </xsl:when>
    <xsl:when test="string-length($oldvalue) > 0">
      <xsl:value-of select="$oldvalue"/>
    </xsl:when>
    <xsl:when test="string-length($default) > 0">
      <xsl:value-of select="$default"/>
    </xsl:when>
  </xsl:choose>
</xsl:template> 

<xsl:template match="cib">
  <xsl:element name="{name()}">

    <xsl:attribute name="admin-epoch">
      <xsl:call-template name="rename-default">
	<xsl:with-param name="newvalue"><xsl:value-of select="@admin-epoch"/></xsl:with-param>
	<xsl:with-param name="oldvalue"><xsl:value-of select="@admin_epoch"/></xsl:with-param>
	<xsl:with-param name="default">0</xsl:with-param>
      </xsl:call-template>
    </xsl:attribute>

    <xsl:attribute name="epoch">
      <xsl:call-template name="rename-default">
	<xsl:with-param name="newvalue"><xsl:value-of select="@epoch"/></xsl:with-param>
	<xsl:with-param name="default">0</xsl:with-param>
      </xsl:call-template>
    </xsl:attribute>

    <xsl:attribute name="num-updates">
      <xsl:call-template name="rename-default">
	<xsl:with-param name="newvalue"><xsl:value-of select="@num-updates"/></xsl:with-param>
	<xsl:with-param name="oldvalue"><xsl:value-of select="@num_updates"/></xsl:with-param>
	<xsl:with-param name="default">0</xsl:with-param>
      </xsl:call-template>
    </xsl:attribute>

    <xsl:attribute name="dc-uuid">
      <xsl:call-template name="rename-default">
	<xsl:with-param name="newvalue"><xsl:value-of select="@dc-uuid"/></xsl:with-param>
	<xsl:with-param name="oldvalue"><xsl:value-of select="@dc_uuid"/></xsl:with-param>
	<xsl:with-param name="default">0</xsl:with-param>
      </xsl:call-template>
    </xsl:attribute>

    <xsl:attribute name="have-quorum">
      <xsl:call-template name="rename-default">
	<xsl:with-param name="newvalue"><xsl:value-of select="@have-quorum"/></xsl:with-param>
	<xsl:with-param name="oldvalue"><xsl:value-of select="@have_quorum"/></xsl:with-param>
	<xsl:with-param name="default">false</xsl:with-param>
      </xsl:call-template>
    </xsl:attribute>

    <xsl:attribute name="crm-feature-set">
      <xsl:call-template name="rename-default">
	<xsl:with-param name="newvalue"><xsl:value-of select="@crm-feature-set"/></xsl:with-param>
	<xsl:with-param name="oldvalue"><xsl:value-of select="@crm_feature_set"/></xsl:with-param>
	<xsl:with-param name="default">0</xsl:with-param>
      </xsl:call-template>
    </xsl:attribute>

    <xsl:attribute name="cib-feature-revision">
      <xsl:call-template name="rename-default">
	<xsl:with-param name="newvalue"><xsl:value-of select="@cib-feature-revision"/></xsl:with-param>
	<xsl:with-param name="oldvalue"><xsl:value-of select="@cib_feature_revision"/></xsl:with-param>
	<xsl:with-param name="default">0</xsl:with-param>
      </xsl:call-template>
    </xsl:attribute>

    <xsl:attribute name="remote-tls-port">
      <xsl:call-template name="rename-default">
	<xsl:with-param name="newvalue"><xsl:value-of select="@remote-tls-port"/></xsl:with-param>
	<xsl:with-param name="oldvalue"><xsl:value-of select="@remote_access_port"/></xsl:with-param>
	<xsl:with-param name="default">-1</xsl:with-param>
      </xsl:call-template>
    </xsl:attribute>

    <xsl:attribute name="validate-with">pacemaker-0.7</xsl:attribute>
    <xsl:apply-templates select="node()" />
  </xsl:element>
</xsl:template>

<xsl:template match="configuration|nodes|crm_config|resources|constraints|operations|attributes|status">
  <!-- no ID required -->
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@*"/>
    <xsl:apply-templates select="node()" />
  </xsl:element>
</xsl:template>

<!-- override the ID field for these objects -->
<xsl:template match="nvpair|expression">
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@*" />

    <!-- use an automatic ID -->
    <xsl:call-template name="auto-id"/>

    <xsl:apply-templates select="node()" />

  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="rule">
  <xsl:element name="{name()}">

    <!-- make sure some sort of score is always set -->
    <xsl:if test="not(@score)">
      <xsl:if test="not(@score_attribute)">
	<xsl:attribute name="score">0</xsl:attribute>
      </xsl:if>
    </xsl:if>

    <!-- use an automatic ID -->
    <xsl:call-template name="auto-id"/>

    <xsl:apply-templates select="@*" />
    <xsl:apply-templates select="node()" />

  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="date_expression">
  <xsl:element name="{name()}">

    <!-- make sure operation is always set -->
    <xsl:attribute name="operation">in_range</xsl:attribute>

    <!-- use an automatic ID -->
    <xsl:call-template name="auto-id"/>

    <xsl:apply-templates select="@*" />
    <xsl:apply-templates select="node()" />

  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="op">
  <xsl:element name="{name()}">

    <!-- arrange for the name to be before interval -->
    <xsl:attribute name="name"/>

    <!-- make sure interval is always set -->
    <xsl:attribute name="interval">0</xsl:attribute>

    <!-- use an automatic ID -->
    <xsl:call-template name="auto-id"/>

    <xsl:apply-templates select="@*" />
    <xsl:apply-templates select="node()" />

  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="date_expression">
  <xsl:element name="{name()}">

    <!-- make sure operation is always set -->
    <xsl:attribute name="operation">in_range</xsl:attribute>

    <!-- use an automatic ID -->
    <xsl:call-template name="auto-id"/>

    <xsl:apply-templates select="@*" />
    <xsl:apply-templates select="node()" />

  </xsl:element>
</xsl:template>

<xsl:template match="rsc_colocation">
  <xsl:element name="{name()}">

    <!-- set a automatic ID -->
    <xsl:call-template name="auto-id"/>
    
    <xsl:attribute name="rsc">
      <xsl:value-of select="@from"/>
    </xsl:attribute>
    <xsl:attribute name="with-rsc">
      <xsl:value-of select="@to"/>
    </xsl:attribute>

    <xsl:if test="@from_role">
      <xsl:attribute name="rsc-role">
	<xsl:call-template name="camel-case-value">
	  <xsl:with-param name="value"><xsl:value-of select="@from_role"/></xsl:with-param>
	</xsl:call-template>
      </xsl:attribute>
    </xsl:if>
    <xsl:if test="@to_role">
      <xsl:attribute name="with-rsc-role">
	<xsl:call-template name="camel-case-value">
	  <xsl:with-param name="value"><xsl:value-of select="@to_role"/></xsl:with-param>
	</xsl:call-template>
      </xsl:attribute>
    </xsl:if>
    
    <xsl:for-each select="@*"> 
      <xsl:choose>
	<xsl:when test="starts-with(name(), 'to')"/>
	<xsl:when test="starts-with(name(), 'from')"/>
	<xsl:otherwise>
	  <xsl:apply-templates select="."/>
	</xsl:otherwise>
      </xsl:choose>
    </xsl:for-each>
    <xsl:apply-templates select="node()" />

  </xsl:element>
</xsl:template>

<xsl:template match="rsc_order">
  <xsl:element name="{name()}">

    <!-- set a automatic ID -->
    <xsl:call-template name="auto-id"/>

    <!-- normalize ordering  -->
    <xsl:choose>
      <xsl:when test="not(contains(@type, 'before'))">

	<xsl:attribute name="first-rsc">
	  <xsl:value-of select="@to"/>
	</xsl:attribute>
	<xsl:attribute name="then-rsc">
	  <xsl:value-of select="@from"/>
	</xsl:attribute>

	<xsl:choose>
	  <xsl:when test="@action">
	    <xsl:attribute name="then-action">
	      <xsl:value-of select="@action"/>
	    </xsl:attribute>
	  </xsl:when>
	  <xsl:otherwise>
	    <xsl:attribute name="then-action">start</xsl:attribute>
	  </xsl:otherwise>
	</xsl:choose>

	<xsl:choose>
	  <xsl:when test="@to_action">
	    <xsl:attribute name="first-action">
	      <xsl:value-of select="@to_action"/>
	    </xsl:attribute>
	  </xsl:when>
	  <xsl:when test="@action">
	    <xsl:attribute name="first-action">
	      <xsl:value-of select="@action"/>
	    </xsl:attribute>
	  </xsl:when>
	  <xsl:otherwise>
	    <xsl:attribute name="first-action">start</xsl:attribute>
	  </xsl:otherwise>
	</xsl:choose>

      </xsl:when>
      <xsl:otherwise>
	<xsl:if test="@action">
	  <xsl:attribute name="first-action">
	  <xsl:value-of select="@action"/>
	  </xsl:attribute>
	</xsl:if>
	<xsl:attribute name="first-rsc">
	  <xsl:value-of select="@from"/>
	</xsl:attribute>
	<xsl:attribute name="then-rsc">
	  <xsl:value-of select="@to"/>
	</xsl:attribute>
	<xsl:if test="@to_action">
	  <xsl:attribute name="then-action">
	    <xsl:value-of select="@to_action"/>
	  </xsl:attribute>
	</xsl:if>
      </xsl:otherwise>

    </xsl:choose>

    <xsl:for-each select="@*"> 
      <xsl:choose>
	<xsl:when test="starts-with(name(), 'to')"/>
	<xsl:when test="starts-with(name(), 'from')"/>
	<xsl:when test="contains(name(), 'action')"/>
	<xsl:when test="starts-with(name(), 'type')"/>
	<xsl:otherwise>
	  <xsl:apply-templates select="."/>
	</xsl:otherwise>
      </xsl:choose>
    </xsl:for-each>
    <xsl:apply-templates select="node()" />

  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="lrm_resource|node|node_state">
  <xsl:element name="{name()}">
    <xsl:call-template name="auto-id"/>
    <xsl:for-each select="@*"> 
      <xsl:choose>
	<xsl:when test="starts-with(name(), 'id')">
	  <!--
	      Do not s/:/-/ for lrm_resource IDs 
	      Leave node IDs unmodified
	    -->
	  <xsl:attribute name="id">
	    <xsl:value-of select="."/>
	  </xsl:attribute>  
	</xsl:when>
	<xsl:otherwise>
	  <xsl:apply-templates select="."/>
	</xsl:otherwise>
      </xsl:choose>
    </xsl:for-each>
    <xsl:apply-templates select="node()" />
  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="@*">
  <xsl:attribute name="{name()}">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="/">
  <xsl:apply-templates select="@*"/>
  <xsl:apply-templates select="node()"/>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="*">
  <xsl:element name="{name()}">
    <xsl:call-template name="auto-id"/>
    <xsl:apply-templates select="@*"/>
    <xsl:apply-templates select="node()" />
  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

</xsl:stylesheet>
