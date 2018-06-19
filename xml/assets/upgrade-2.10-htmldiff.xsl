<!--
 Copyright 2018 Red Hat, Inc.
 Author: Jan Pokorny <jpokorny@redhat.com>
 Part of pacemaker project
 SPDX-License-Identifier: GPL-2.0-or-later
 -->
<xsl:stylesheet version="1.0"
                xmlns="http://www.w3.org/1999/xhtml"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:cibtr="http://clusterlabs.org/ns/pacemaker/cibtr-2"
                xmlns:exsl="http://exslt.org/common">
<!-- NOTE: this is an exception from rule forbidding EXSLT's usage -->

<xsl:include href="../upgrade-2.10-roundtrip.xsl"/>

<!--
 we are embedding files from 3rd party project so as to reproduce the content
 of XML into HTML-formatted presentation form; alternatively:
 * from mozilla/firefox:
   - view-source.xsl by Keith Visco (example transformation for transformiix)
     https://dxr.mozilla.org/mozilla/source/extensions/transformiix/source/examples
   - XMLPrettyPrint.xsl by Jonas Sicking
     https://dxr.mozilla.org/mozilla-central/source/dom/xml/resources
     https://hg.mozilla.org/mozilla-central/file/9b2a99adc05e/content/xml/document/resources/XMLPrettyPrint.xsl
     or possibly its readily sanitized version from rdf-viewer project
     https://github.com/marianafranco/rdf-viewer
 * custom stylesheet to be written
 -->
<xsl:param name="highlight-namespace" select="''"/>
<!--
<xsl:include href="https://raw.githubusercontent.com/Boldewyn/view-source/master/library.xsl"/>
<xsl:include href="https://raw.githubusercontent.com/Boldewyn/view-source/master/original.xsl"/>
 -->
<xsl:include href="view-source-library.xsl"/>
<xsl:include href="view-source-original.xsl"/>

<xsl:output method="xml" encoding="UTF-8"
            omit-xml-declaration="yes"
            doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN"
            doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"/>

<!-- B: identity mode -->
<xsl:template match="@*|node()" mode="identity">
  <xsl:copy>
    <xsl:apply-templates select="@*|node()" mode="identity"/>
  </xsl:copy>
</xsl:template>

<!-- used in test files to allow in-browser on-the-fly checking -->
<xsl:template match="processing-instruction()[
                       name() = 'xml-stylesheet'
                       and
                       count(..|/) = 1
                     ]"
              mode="identity"/>
<!-- E: identity mode -->

<xsl:template match="/">
  <xsl:variable name="before-upgrade">
    <xsl:apply-templates select="." mode="identity"/>
  </xsl:variable>
  <xsl:variable name="after-upgrade">
    <xsl:apply-templates select="." mode="cibtr:roundtrip"/>
  </xsl:variable>

  <html>
    <head>
      <title>
        <xsl:text>upgrade-2.10 on-the-fly in-browser transformation</xsl:text>
      </title>
      <style>
        ol.count,.possibly-revealed { display: none; }
        li.delete { color: red; }
        li.delete em { background-color: #FFE4E1; }
        li.insert { color: green; }
        li.insert em { background-color: #FAFAD2; }
        .count,.data { font-family: monospace;
                       background-color: #F8F8FF;
                       border: 1px solid #DCDCDC; }
      </style>
      <script type="text/javascript">
        var global = { prettydiff: {} },  /* for diffview.js */
            diffview_source = new String("../assets/diffview.js");

        /* add location-based file detail to the title */
        var split_url = document.URL.split('/'),
            basename = new String(split_url[split_url.length - 1]),
            /* see whether there's 'test-\d+' in URL as a discriminator */
            is_test = split_url.some(function(item, index, array) {
              if (index &lt; array.length - 1 &amp;&amp; item.match(/test-\d+/))
                return true;
              return false;
            });

        window.addEventListener("DOMContentLoaded", function(event) {
          /* update title + headline */
          var basename_title = new String(basename + " upgrade");
          document.getElementById("headline").innerText = basename_title;
          document.title = basename_title + " [" + document.title + "]";

          /* add location-based file detail to the acknowledgement's text */
          document.getElementById("acknowledgement")
            .innerHTML = document.getElementById("acknowledgement").innerHTML
                         .replace("@basename@", basename);

          /* make expand/collapse buttons udner debugging section work */
          document.querySelectorAll("#original, #transformed").forEach(
            function(item) {
              item.querySelector(".expand").addEventListener("click",
                                                             function(event) {
                item.querySelectorAll(".possibly-revealed").forEach(
                  function(item) {
                    item.classList.replace("possibly-revealed", "revealed");
                  }
                );
                this.classList.add("possibly-revealed");
                event.preventDefault();
              });
              item.querySelector(".collapse").addEventListener("click",
                                                               function(event) {
                item.querySelectorAll(".revealed").forEach(
                  function(item) {
                    item.classList.replace("revealed", "possibly-revealed");
                  }
                );
                item.querySelector(".expand").classList.remove("possibly-revealed");
                event.preventDefault();
              });
            }
          );

          if (is_test) {
            var xhr1 = new XMLHttpRequest(),
                xhr2 = new XMLHttpRequest(),
                basename_split = basename.split('.');

            /* fetch expected out-of-band messages */
            xhr1.onload = function() {
              document.getElementById("expected-messages").innerText = this.responseText;
              document.querySelectorAll(["#expected-messages",
                                         "#expected-messages-ext",
                                         "#navigation"]).forEach(
                function(item) {
                  item.classList.remove("possibly-revealed");
                }
              );
            };
            xhr1.open("GET", basename_split.splice(0, basename_split.length - 1)
                                           .join('.') + ".ref.err");
            xhr1.responseType = "text";
            xhr1.send();

            /* fetch previous/next pointers */
            xhr2.onload = function() {
              var prev_link, next_link,
                  found = false;
              Array.prototype.every.call(
                this.responseXML.getElementsByTagName("a"),
                function(item) {
                  if (item.href.endsWith(basename_split[basename_split.length - 1])) {
                    if (item.href.endsWith(basename))
                      found = true;
                    else if (!found)
                      prev_link = item;
                    else if (next_link !== undefined)
                      return false;
                    else
                      next_link = item;
                  }
                  return true;
                }
              );
              if (prev_link !== undefined)
                document.getElementById("navigation-prev").href = prev_link.href;
              if (next_link !== undefined)
              document.getElementById("navigation-next").href = next_link.href;
            };
            xhr2.open("GET", ".");
            xhr2.responseType = "document";
            xhr2.send();
          }
        });

        window.addEventListener("load", function(event) {
          /* trigger diff'ing */
          document
            .getElementById("output")
            .innerHTML = global.prettydiff.diffview({
              source: document.getElementById("original-placeholder").innerText,
              sourcelabel: "Differences: original",
              diff: document.getElementById("transformed-placeholder").innerText,
              difflabel: "transformed (some whitespace stripped)",
              diffview: "inline",
              lang: "text"
            })[0];

          /* add proper location of diffview.js */
          var diffview_link = document.getElementById("diffview-link");
          if (diffview_link.host != document.location.host) {
            diffview_link.href = diffview_source;
            diffview_link.parentElement.querySelector(".possibly-revealed")
              .classList.remove("possibly-revealed");
            diffview_link.parentElement.querySelector(".revealed")
              .classList.replace("revealed", "possibly-revealed");
          }
        });

        /* bind left/right arrows */
        window.addEventListener("keydown", function(event) {
          switch (event.keyCode) {
          case 37:
            document.location = document.getElementById("navigation-prev").href;
            break;
          case 39:
            document.location = document.getElementById("navigation-next").href;
            break;
          }
        });
      </script>
      <script type="text/javascript" src="../assets/diffview.js"/>
      <!-- fallback to externally fetched js, without any guarantees,
           safety ones or otherwise -->
      <script type="text/javascript">
        if (typeof global.prettydiff.diffview == "undefined") {
          diffview_source = new String("https://raw.githubusercontent.com/prettydiff/prettydiff/2.2.8/lib/diffview.js");
          document.write(unescape('%3Cscript type="text/javascript" src=' + diffview_source + '/%3E'));
        }
      </script>
    </head>
    <body>
      <h1 id="headline">test</h1>
      <p>
        <strong>Using <a href="../upgrade-2.10.xsl">upgrade-2.10</a> on-the-fly in-browser transformation</strong>
        <span id="navigation" class="possibly-revealed">
          [
          <a id="navigation-prev" href="#">previous</a>
          and
          <a id="navigation-next" href="#">next</a>, or use arrows
          ]
        </span>
      </p>
      <p id="output">
        Differences highlight view to be loaded here.
      </p>
      <h3>Diagnostics</h3>
      <p>
        Open <a href="https://webmasters.stackexchange.com/a/77337">JS console</a>
        (e.g. <kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>J</kbd>, focusing JS + log combo)
        <span id="expected-messages-ext" class="possibly-revealed">
          to check the actual messages from the in-browser transformation match the baseline:
        </span>
      </p>
      <pre id="expected-messages" class="data possibly-revealed">
        Expected diagnostic messages to be loaded here.
      </pre>
      <h3>Debugging</h3>
      <p>
        These are raw data (beware, already chewed with the
        <a href="../assets/view-source-original.xsl">view-source</a>
        transformation, hence not very suitable for copying) entering
        the differential generating processs:
      </p>
      <p id="original">
        <span>
          <a class="expand" href="">original+</a>
          <a class="collapse possibly-revealed" href="">original-</a>
        </span>
        <br/>
        <pre id="original-placeholder" class="data possibly-revealed">
          <xsl:apply-templates select="exsl:node-set($before-upgrade)/node()" mode="original"/>
        </pre>
      </p>
      <p id="transformed">
        <span>
          <a class="expand" href="">transformed+</a>
          <a class="collapse possibly-revealed" href="">transformed-</a>
        </span>
        <br/>
        <pre id="transformed-placeholder" class="data possibly-revealed">
          <xsl:apply-templates select="exsl:node-set($after-upgrade)/node()" mode="original"/>
        </pre>
      </p>
      <hr/>
      <p id="acknowledgement">
        This generated page is based on the externally provided pacemaker XML
        configuration file (CIB), <span class="data">@basename@</span>, which is
        the primary object of interest here.
        But the rendered page wouldn't be possible without the actual
        transformations and other auxiliary files that come with these notices:
        <br/>
        <ul>
          <li id="ack-diffview">
            <a href="../assets/diffview.js" id="diffview-link">diffview.js</a>
            <p class="data revealed">
              This file was obtained from <a href="https://github.com/prettydiff/prettydiff">prettydiff/prettydiff</a> project:<br/>
              <a href="https://raw.githubusercontent.com/prettydiff/prettydiff/2.2.8/lib/diffview.js">diffview.js</a><br/>
              <br/>
              Licensing governed with:<br/>
              <a href="https://github.com/prettydiff/prettydiff/blob/2.2.8/license.txt">license.txt</a><br/>
              <br/>
              > Rights holder Austin Cheney and Pretty Diff<br/>
              > <br/>
              > Pretty Diff project, as of version 2.1.17 and all following versions<br/>
              > unless otherwise changed, is licensed with a Creative Commons 1.0<br/>
              > Universal license (CC0).
            </p>
            <p class="data possibly-revealed">
              This file is being served directly from <a href="https://raw.githubusercontent.com/prettydiff/prettydiff/2.2.8/lib/diffview.js">
              GitHub hosted location</a>, hence refer to <a href="https://raw.githubusercontent.com/prettydiff/prettydiff/2.2.8">
              respective repo tree</a>
            </p>
          </li>
          <li id="ack-view-source">
            <a href="../assets/view-source-library.xsl">library.xsl</a>
            and
            <a href="../assets/view-source-original.xsl">original.xsl</a>
            <p class="data">
              This file was obtained from <a href="https://github.com/Boldewyn/view-source">Boldewyn/view-source</a> project:<br/>
              <a href="https://raw.githubusercontent.com/Boldewyn/view-source/f425605366b9f5a52e6a71632785d6e4543c705e/library.xsl">library.xsl</a><br/>
              <a href="https://raw.githubusercontent.com/Boldewyn/view-source/f425605366b9f5a52e6a71632785d6e4543c705e/original.xsl">original.xsl</a><br/>
              <br/>
              Licensing governed with:<br/>
              <a href="https://github.com/Boldewyn/view-source/blob/f425605366b9f5a52e6a71632785d6e4543c705e/README">README</a><br/>
              <br/>
              > The stylesheet is published under an MIT-style license and the GPL v2.<br/>
              > Choose at your liking.
            </p>
          </li>
          <li id="ack-upgrade">
            <a href="../assets/upgrade-2.10-htmldiff.xsl">upgrade-2.10-htmldiff.xsl</a>
            (master template for this report) and
            <a href="../upgrade-2.10.xsl">upgrade-2.10.xsl</a>
            (actual upgrade engine)
            <p class="data">
              Copyright 2018 <a href="https://redhat.com">Red Hat, Inc.</a><br/>
              Author: <a href="https://wiki.clusterlabs.org/wiki/User:Jpokorny">Jan Pokorny</a>
              &lt;<a href="mailto:jpokorny@redhat.com">jpokorny@redhat.com</a>&gt;<br/>
              <a href="https://github.com/ClusterLabs/pacemaker/tree/master/xml">Part</a> of
              <a href="https://wiki.clusterlabs.org/wiki/Pacemaker">pacemaker</a> project<br/>
              <a href="https://spdx.org/sites/cpstandard/files/pages/files/using_spdx_license_list_short_identifiers.pdf#page=5">SPDX-License-Identifier</a>:
              <a href="https://spdx.org/licenses/GPL-2.0-or-later.html">GPL-2.0-or-later</a>
            </p>
          </li>
        </ul>
      </p>
    </body>
  </html>
</xsl:template>

</xsl:stylesheet>
