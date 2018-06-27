<!--
 Copyright 2018 Red Hat, Inc.
 Author: Jan Pokorny <jpokorny@redhat.com>
 Part of pacemaker project
 SPDX-License-Identifier: GPL-2.0-or-later
 -->
<!--
 For experimenting and maintenance purposes only, pacemaker shall
 split the transformation pipeline on its own.
-->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:cibtr="http://clusterlabs.org/ns/pacemaker/cibtr-2"
                xmlns:exsl="http://exslt.org/common">
<!-- NOTE: this is an exception from rule forbidding EXSLT's usage -->

<xsl:import href="upgrade-2.10.xsl"/>
<xsl:import href="upgrade-2.10-enter.xsl"/>
<xsl:import href="upgrade-2.10-leave.xsl"/>

<xsl:output method="xml" encoding="UTF-8" indent="yes" omit-xml-declaration="yes"/>


<!--

 ACTUAL TRANSFORMATION

 Extra modes: cibtr:roundtrip

 -->
<xsl:template match="/"
              mode="cibtr:roundtrip">
  <xsl:variable name="pre-upgrade">
    <xsl:apply-templates mode="cibtr:enter"/>
  </xsl:variable>
  <xsl:variable name="upgrade">
    <xsl:apply-templates select="exsl:node-set($pre-upgrade)/node()" mode="cibtr:main"/>
  </xsl:variable>

  <xsl:apply-templates select="exsl:node-set($upgrade)/node()" mode="cibtr:leave"/>
</xsl:template>

<!-- mode-less, easy to override kick-off -->
<xsl:template match="/">
  <xsl:apply-templates select="." mode="cibtr:roundtrip"/>
</xsl:template>

</xsl:stylesheet>
