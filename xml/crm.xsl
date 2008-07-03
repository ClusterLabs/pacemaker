<?xml version="1.0" encoding="ISO-8859-1"?>
<!-- Edited with XML Spy v2007 (http://www.altova.com) -->
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method='html' version='1.0' encoding='UTF-8' indent='yes'/>

<xsl:template match="cib">
  <h2>Cluster Configuration: <xsl:value-of select="@admin_epoch"/>.<xsl:value-of select="@epoch"/>.<xsl:value-of select="@num_updates"/></h2>
  <xsl:apply-templates/>
</xsl:template>

<xsl:template match="cluster_property_set">
    <li>
      Property Set: <xsl:value-of select="@id"/>
      <xsl:apply-templates/>
    </li>
</xsl:template>

<xsl:template match="node">
  <li>
    <b>Node <xsl:value-of select="@uname"/></b> (<xsl:value-of select="@id"/>)
    <xsl:apply-templates select="node()"/>
  </li>
</xsl:template>

<xsl:template match="primitive">
  <li>
    <b>Resource
      <xsl:value-of select="@class"/>::<xsl:value-of select="@type"/>:<xsl:value-of select="@id"/>
    </b>
    <ul>
    <xsl:apply-templates select="node()"/>
    Preferred Locations:
    <xsl:call-template name="location_prefs">
      <xsl:with-param name="resource" select="@id"/>
    </xsl:call-template>
    </ul>
  </li>
</xsl:template>

<xsl:template name="location_prefs">
    <xsl:parameter name="resource"/>
    <xsl:for-each select="/cib/configuration/constraints/rsc_location">
	<xsl:if test="@rsc = $resource">
	  <xsl:apply-templates/>
	</xsl:if>
	<xsl:text> </xsl:text>
    </xsl:for-each>
</xsl:template>

<xsl:template match="group">
  <li>
    <h4>Resource Group <xsl:value-of select="@id"/></h4>
    <ul><xsl:apply-templates/></ul>
  </li>
</xsl:template>

<xsl:template match="clone">
  <li>
    <h4>Cloned Resource <xsl:value-of select="@id"/></h4>
    <ul><xsl:apply-templates/></ul>
  </li>
</xsl:template>

<xsl:template match="op">
  <li>
    <xsl:value-of select="@name"/>: 
    interval=<xsl:value-of select="@interval"/>
    timeout=<xsl:value-of select="@timeout"/>
  </li>
</xsl:template>

<xsl:template match="instance_attributes">
  Options: <xsl:value-of select="@id"/>
  <xsl:apply-templates/>
</xsl:template>

<xsl:template match="rsc_location">
  Location: <xsl:value-of select="@rsc"/>
  <ul><xsl:apply-templates/></ul>
</xsl:template>

<xsl:template match="rule">
  <ul><xsl:apply-templates/></ul>
</xsl:template>

<xsl:template match="expression">
  <li>
    <xsl:value-of select="@attribute"/>
    <xsl:text> </xsl:text>
    <xsl:value-of select="@operation"/>
    <xsl:text> </xsl:text>
    <xsl:value-of select="@value"/>
    <xsl:text> </xsl:text>
    (score=<xsl:value-of select="../@score"/>)
    <xsl:apply-templates/>
  </li>
</xsl:template>

<xsl:template match="attributes/nvpair">
      <li>
        <xsl:value-of select="@name"/>="<xsl:value-of select="@value"/>"
      </li>
</xsl:template>

<xsl:template match="crm_config">
  <h3>Cluster Options</h3>
  <ul><xsl:apply-templates/></ul>
</xsl:template>

<xsl:template match="nodes">
  <h3>Available Nodes</h3>
  <ul>
    <xsl:apply-templates/>
  </ul>
</xsl:template>

<xsl:template match="resources">
  <h3>Configured Resources</h3>
  <ul>
    <xsl:apply-templates/>
  </ul>
</xsl:template>

<xsl:template match="constraints">
  <h3>Inter-Resource Relationships</h3>
  <xsl:apply-templates select="rsc_colocation"/>
  <xsl:apply-templates select="rsc_order"/>
</xsl:template>

<xsl:template match="configuration">
  <xsl:apply-templates/>
</xsl:template>

<xsl:template match="attributes">
  <ul>
    <xsl:apply-templates/>
  </ul>
</xsl:template>

<xsl:template match="operations">
  Operations:
  <ul>
    <xsl:apply-templates/>
  </ul>
</xsl:template>

<xsl:template match="status"/>

<xsl:template match="/">
  <html>
  <body>
  <xsl:apply-templates/>
  </body>
  </html>
</xsl:template>

<xsl:template match="*">
  <div>
    <ul>
      <font color="#777777">Unknown Object: </font>
      <xsl:value-of select="name()"/>
      <p><xsl:apply-templates select="@*"/></p>
      <xsl:apply-templates select="node()" />
    </ul>
  </div>
</xsl:template>

<xsl:template match="@*">
  <xsl:value-of select="name()"/>
  <xsl:text>=</xsl:text>
  <xsl:value-of select="."/>
  <xsl:text> </xsl:text>
</xsl:template>

</xsl:stylesheet>
