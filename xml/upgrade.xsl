<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
		xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method='xml' version='1.0' encoding='UTF-8' indent='yes'/>

<!-- Utility templates -->
<xsl:template name="auto-id">
  <xsl:attribute name="id">
    <xsl:value-of select="name()"/>
    <xsl:text>.auto-</xsl:text>
    <xsl:number level="any"/>
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
      <xsl:text>.auto-</xsl:text>
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

<!-- Sanitizing templates -->
<xsl:template match="status"/>

<xsl:template match="@generated|@ccm_transition|@num_peers|@cib_last_written|@have_quorum|@dc_uuid|@start_delay">
  <!-- swallow -->
</xsl:template>

<xsl:template match="@disabled">
  <xsl:attribute name="enabled">true</xsl:attribute>
  <xsl:if test="contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'true')">
    <xsl:attribute name="enabled">false</xsl:attribute>
  </xsl:if>
</xsl:template>

<xsl:template match="@to_role|@role|@from_role">
  <xsl:attribute name="{name()}">
    <xsl:call-template name="camel-case-value">
      <xsl:with-param name="value"><xsl:value-of select="."/></xsl:with-param>
    </xsl:call-template>
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
  <xsl:choose>
    <!-- IDs cant start with a digit -->
    <xsl:when test='not(string(number(substring(.,1,1))) = "NaN")'>
      <!-- set an automatic id -->
      <xsl:for-each select=".."> 
	<xsl:attribute name="id">
	  <xsl:value-of select="name()"/>
	  <xsl:text>.auto-</xsl:text>
	  <xsl:number level="any"/>
	</xsl:attribute>
      </xsl:for-each>
    </xsl:when>
    <xsl:otherwise>
      <xsl:attribute name="{name()}">
	<xsl:value-of select="translate(., ':', '-')"/>
      </xsl:attribute>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!-- Rename templates -->
<xsl:template match="@admin_epoch|@num_updates|@boolean_op|@cib_feature_revision|@crm_feature_set|@on_fail">
  <xsl:attribute name="{translate(name(),'_','-')}">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="@prereq">
  <xsl:attribute name="requires">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>


<!-- regular transformations -->

<xsl:template match="primitive|group|clone">
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@id"/>

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

    <xsl:apply-templates select="node()" />

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
      </xsl:element>
    </xsl:element>
  </xsl:element>
</xsl:template>

<xsl:template match="master_slave">
  <xsl:element name="master">
    <xsl:apply-templates select="@id"/>

    <xsl:if test="@description">
      <xsl:apply-templates select="@description"/>
    </xsl:if>

    <xsl:apply-templates select="node()" />

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
	    <xsl:otherwise>
	      <xsl:call-template name="create-as-attr">
		<xsl:with-param name="name"><xsl:value-of select="name()"/></xsl:with-param>
		<xsl:with-param name="value"><xsl:value-of select="."/></xsl:with-param>
	      </xsl:call-template>
	    </xsl:otherwise>
	  </xsl:choose>
	</xsl:for-each>
      </xsl:element>
    </xsl:element>
  </xsl:element>
</xsl:template>



<xsl:template match="cib">
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@*"/>
    <xsl:attribute name="validate-with">relax-ng</xsl:attribute>
    <xsl:apply-templates select="node()" />
  </xsl:element>
</xsl:template>

<xsl:template match="configuration|nodes|node|crm_config|resources|constraints|operations|attributes">
  <!-- no ID required -->
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@*"/>
    <xsl:apply-templates select="node()" />
  </xsl:element>
</xsl:template>

<!-- override the ID field for these objects -->
<xsl:template match="nvpair|instance_attributes|expression|meta_attributes">
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

<xsl:template match="rsc_order">
  <xsl:element name="{name()}">

    <!-- set a automatic ID -->
    <xsl:call-template name="auto-id"/>

    <xsl:for-each select="@*"> 
      <xsl:choose>
	<xsl:when test="not(contains(name(), 'type'))">
	  <xsl:apply-templates select="."/>
	</xsl:when>
      </xsl:choose>
    </xsl:for-each>
    <xsl:apply-templates select="node()" />

    <!-- normalize ordering  -->
    <xsl:if test="contains(@type, 'before')">
      <xsl:attribute name="from">
	<xsl:value-of select="@to"/>
      </xsl:attribute>
      <xsl:attribute name="to">
	<xsl:value-of select="@from"/>
      </xsl:attribute>
      <xsl:if test="@to_role">
	  <xsl:attribute name="from_role">
	    <xsl:value-of select="@to_role"/>
	  </xsl:attribute>
      </xsl:if>
      <xsl:if test="@from_role">
	<xsl:attribute name="to_role">
	  <xsl:value-of select="@from_role"/>
	</xsl:attribute>
      </xsl:if>
    </xsl:if>

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
    <xsl:attribute name="id">
      <xsl:value-of select="name()"/>
      <xsl:text>.auto-</xsl:text>
      <xsl:number level="any" from="cib"/>
    </xsl:attribute>
    <xsl:apply-templates select="@*"/>
    <xsl:apply-templates select="node()" />
  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

</xsl:stylesheet>
