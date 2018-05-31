<?xml version="1.0" ?>
<!--
 This file was obtained from https://github.com/Boldewyn/view-source project:
 https://raw.githubusercontent.com/Boldewyn/view-source/f425605366b9f5a52e6a71632785d6e4543c705e/library.xsl

 Licensing governed with:
 https://github.com/Boldewyn/view-source/blob/f425605366b9f5a52e6a71632785d6e4543c705e/README

 > The stylesheet is published under an MIT-style license and the GPL v2.
 > Choose at your liking.

 -->
<t:stylesheet version="1.0"
  xmlns:t="http://www.w3.org/1999/XSL/Transform"
  xmlns="http://www.w3.org/1999/xhtml">

  <t:variable name="ns" xmlns="">
    <empty></empty>
    <xml>http://www.w3.org/XML/1998/namespace</xml>
    <xmlns>http://www.w3.org/2000/xmlns/</xmlns>
    <xhtml>http://www.w3.org/1999/xhtml</xhtml>
    <svg>http://www.w3.org/2000/svg</svg>
    <mathml>http://www.w3.org/1998/Math/MathML</mathml>
    <xslt>http://www.w3.org/1999/XSL/Transform</xslt>
    <fo>http://www.w3.org/1999/XSL/Format</fo>
    <smil>http://www.w3.org/2005/SMIL21/Language</smil>
    <xlink>http://www.w3.org/1999/xlink</xlink>
    <xsd>http://www.w3.org/2001/XMLSchema</xsd>
    <xsd-inst>http://www.w3.org/2001/XMLSchema-instance</xsd-inst>
    <xforms>http://www.w3.org/2001/xforms</xforms>
    <xinclude>http://www.w3.org/2001/XInclude</xinclude>
    <xul>http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul</xul>
    <rdf>http://www.w3.org/1999/02/22-rdf-syntax-ns#</rdf>
  </t:variable>

  <!--
    format text, so that newlines get indented correctly
  -->
  <t:template name="format-text">
    <t:param name="text" select="." />
    <t:param name="indent" />
    <t:choose>
      <t:when test="contains($text, '&#xA;')">
        <t:value-of select="normalize-space(substring-before($text, '&#xA;'))" />
        <t:text>&#xA;</t:text>
        <t:value-of select="$indent" />
        <t:call-template name="format-text">
          <t:with-param name="text" select="substring-after($text, '&#xA;')" />
          <t:with-param name="indent" select="$indent " />
        </t:call-template>
      </t:when>
      <t:otherwise>
        <t:value-of select="normalize-space($text)" />
      </t:otherwise>
    </t:choose>
  </t:template>

  <!--
    HTML entity quote stuff
  -->
  <t:template name="quote">
    <t:param name="text" />
    <t:call-template name="replace">
      <t:with-param name="text">
        <t:call-template name="replace">
          <t:with-param name="text">
            <t:call-template name="replace">
              <t:with-param name="text">
                <t:call-template name="replace">
                  <t:with-param name="text">
                    <t:call-template name="replace">
                      <t:with-param name="text">
                        <t:value-of select="$text" />
                      </t:with-param>
                      <t:with-param name="from" select="'&amp;'" />
                      <t:with-param name="to" select="'&amp;amp;'" />
                    </t:call-template>
                  </t:with-param>
                  <t:with-param name="from" select='"&apos;"' />
                  <t:with-param name="to" select="'&amp;apos;'" />
                </t:call-template>
              </t:with-param>
              <t:with-param name="from" select="'&quot;'" />
              <t:with-param name="to" select="'&amp;quot;'" />
            </t:call-template>
          </t:with-param>
          <t:with-param name="from" select="'&gt;'" />
          <t:with-param name="to" select="'&amp;gt;'" />
        </t:call-template>
      </t:with-param>
      <t:with-param name="from" select="'&lt;'" />
      <t:with-param name="to" select="'&amp;lt;'" />
    </t:call-template>
  </t:template>

  <!--
    replace a string with another
  -->
  <t:template name="replace">
    <t:param name="text" />
    <t:param name="from" />
    <t:param name="to" />
    <t:choose>
      <t:when test="not($from)">
        <t:value-of select="$text" />
      </t:when>
      <t:when test="contains($text, $from)">
        <t:value-of select="substring-before($text, $from)" />
        <t:value-of select="$to" />
        <t:call-template name="replace">
          <t:with-param name="text" select="substring-after($text, $from)" />
          <t:with-param name="from" select="$from" />
          <t:with-param name="to" select="$to" />
        </t:call-template>
      </t:when>
      <t:otherwise>
        <t:value-of select="$text" />
      </t:otherwise>
    </t:choose>
  </t:template>

  <!--
    parse the value of an attribute (find links and make them clickable)
  -->
  <t:template name="parse-attval">
    <t:param name="att" select="." />
    <t:choose>
      <!-- FIXME: element{xhtml} / @attr{obscure-ns} 'href' gets linkified -->
      <t:when test="(namespace-uri($att/..) = document('')//t:variable[@name = 'ns']/xml/text()   and ( local-name($att) = 'base' )) or
                    (namespace-uri($att/..) = document('')//t:variable[@name = 'ns']/xhtml/text() and ( local-name($att) = 'src' or local-name($att) = 'href' )) or
                    (namespace-uri($att/..) = document('')//t:variable[@name = 'ns']/svg/text()   and ( local-name($att) = 'src' )) or
                    (namespace-uri($att/..) = document('')//t:variable[@name = 'ns']/xslt/text()  and ( local-name($att) = 'href' )) or
                    (namespace-uri($att/..) = document('')//t:variable[@name = 'ns']/smil/text()  and ( local-name($att) = 'src' or local-name($att) = 'href' )) or
                    (namespace-uri($att)    = document('')//t:variable[@name = 'ns']/xlink/text() and ( local-name($att) = 'href' or local-name($att) = 'role' )) or
                    contains(substring($att, 1, 7), 'http://') or
                    contains(substring($att, 1, 8), 'https://') or
                    contains(substring($att, 1, 7), 'file://') or
                    contains(substring($att, 1, 7), 'mailto:') or
                    contains(substring($att, 1, 6), 'ftp://') or
                    contains(substring($att, 1, 7), 'ftps://') or
                    contains(substring($att, 1, 5), 'news:') or
                    contains(substring($att, 1, 4), 'urn:') or
                    contains(substring($att, 1, 5), 'ldap:') or
                    contains(substring($att, 1, 5), 'data:')">
        <a>
          <t:attribute name="href">
            <t:value-of select="$att" />
          </t:attribute>
          <t:call-template name="quote">
            <t:with-param name="text" select="$att" />
          </t:call-template>
        </a>
      </t:when>
      <t:otherwise>
        <t:call-template name="quote">
          <t:with-param name="text" select="$att" />
        </t:call-template>
      </t:otherwise>
    </t:choose>
  </t:template>

  <!--
    print the name of a node plus the namespace URI in a title attribute
  -->
  <t:template name="print-name">
    <t:param name="node" select="." />
    <span class="label">
      <t:if test="namespace-uri($node)">
        <t:attribute name="title">
          <t:value-of select="namespace-uri($node)" />
        </t:attribute>
      </t:if>
      <t:choose>
        <t:when test="name($node) != local-name($node)">
          <span class="nsprefix">
            <t:value-of select="substring-before(name($node), ':')" />
          </span>
          <span class="nscolon syntax">
            <t:text>:</t:text>
          </span>
          <span class="local-name">
            <t:value-of select="local-name($node)" />
          </span>
        </t:when>
        <t:otherwise>
          <t:value-of select="name($node)" />
        </t:otherwise>
      </t:choose>
    </span>
  </t:template>

  <!--
    check the used language against a list of known ones
  -->
  <t:template name="detect-lang">
    <t:param name="node" select="." />
    <t:if test="namespace-uri($node) = $highlight-namespace">
      <t:text>highlight </t:text>
    </t:if>
    <t:value-of select="local-name(document('')//t:variable[@name = 'ns']/*[text() = namespace-uri($node)])" />
  </t:template>

  <t:key name="kElemByNSURI"
       match="*[namespace::*[not(. = ../../namespace::*)]]"
       use="namespace::*[not(. = ../../namespace::*)]" />

  <!--
    get a list of all namespaces used in the document
  -->
  <t:template name="get-namespace-nodes">
    <script type="text/javascript">
      var namespaces = [
      <t:for-each select="//namespace::*[not(. = ../../namespace::*)]
                        [count(..|key('kElemByNSURI',.)[1])=1]">
        <t:value-of select="concat('&quot;',.,'&quot;,')"/>
      </t:for-each>
      'DUMMY'
      ];
    </script>
  </t:template>

</t:stylesheet>
