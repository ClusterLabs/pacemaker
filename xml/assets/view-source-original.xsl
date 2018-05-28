<?xml version="1.0" ?>
<!--
 This file was obtained from https://github.com/Boldewyn/view-source project:
 https://raw.githubusercontent.com/Boldewyn/view-source/f425605366b9f5a52e6a71632785d6e4543c705e/original.xsl

 Licensing governed with:
 https://github.com/Boldewyn/view-source/blob/f425605366b9f5a52e6a71632785d6e4543c705e/README

 > The stylesheet is published under an MIT-style license and the GPL v2.
 > Choose at your liking.

 -->
<t:stylesheet version="1.0"
  xmlns:t="http://www.w3.org/1999/XSL/Transform"
  xmlns="http://www.w3.org/1999/xhtml">

  <!-- Elements (original) -->
  <t:template match="*" mode="original">
    <t:variable name="lang">
      <t:call-template name="detect-lang" />
    </t:variable>
    <t:choose>
      <t:when test="node()">
        <span class="{$lang} element">
          <span class="tag start">
            <t:text>&lt;</t:text>
            <t:call-template name="print-name" />
            <t:for-each select="@*">
              <t:apply-templates select="." mode="original" />
            </t:for-each>
            <t:text>&gt;</t:text>
          </span>
          <t:apply-templates mode="original" />
          <span class="tag end">
            <t:text>&lt;/</t:text>
            <t:value-of select="name(.)"/>
            <t:text>&gt;</t:text>
          </span>
        </span>
      </t:when>
      <t:otherwise>
        <span class="{$lang} element empty">
          <span class="tag empty">
            <t:text>&lt;</t:text>
            <t:call-template name="print-name" />
            <t:for-each select="@*">
              <t:apply-templates select="." mode="original" />
            </t:for-each>
            <t:text> /&gt;</t:text>
          </span>
        </span>
      </t:otherwise>
    </t:choose>
  </t:template>

  <!-- Attributes (original) -->
  <t:template match="@*" mode="original">
    <t:variable name="lang">
      <t:call-template name="detect-lang" />
    </t:variable>
    <t:text> </t:text>
    <span class="{$lang} attribute">
      <t:call-template name="print-name" />
      <t:text>="</t:text>
      <span class="attribute-value">
        <t:call-template name="parse-attval" />
      </span>
      <t:text>"</t:text>
    </span>
  </t:template>

  <!-- Processing Instructions (original) -->
  <t:template match="processing-instruction()" mode="original">
    <span class="processing-instruction">
      <t:text>&lt;?</t:text>
      <t:value-of select="name(.)" />
      <t:text> </t:text>
      <t:value-of select="." />
      <t:text>?&gt;</t:text>
    </span>
  </t:template>

  <!-- Comments (original) -->
  <t:template match="comment()" mode="original">
    <span class="comment">
      <t:text>&lt;!--</t:text>
      <t:call-template name="quote">
        <t:with-param name="text" select="." />
      </t:call-template>
      <t:text>--></t:text>
    </span>
  </t:template>

  <!-- Text (original) -->
  <t:template match="text()" mode="original">
    <span class="text">
      <t:call-template name="quote">
        <t:with-param name="text" select="." />
      </t:call-template>
    </span>
  </t:template>

</t:stylesheet>
