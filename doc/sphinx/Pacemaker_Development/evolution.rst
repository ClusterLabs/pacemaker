Evolution of the project
------------------------

This section will not generally be of interest, but may occasionally
shed light on why the current code is structured the way it is when
investigating some thorny issue.

Origin in Heartbeat project
###########################

Pacemaker can be considered as a spin-off from Heartbeat, the original
comprehensive high availability suite started by Alan Robertson. Some
portions of code are shared, at least on the conceptual level if not verbatim,
till today, even if the effective percentage continually declines.

Before Pacemaker 2.0, Pacemaker supported Heartbeat as a cluster layer
alternative to Corosync. That support was dropped for the 2.0.0 release (see
`commit 55ab749bf
<https://github.com/ClusterLabs/pacemaker/commit/55ab749bf0f0143bd1cd050c1bbe302aecb3898e>`_).

An archive of a 2016 checkout of the Heartbeat code base is shared as a
`read-only repository <https://gitlab.com/poki/archived-heartbeat>`_. Notable
commits include:

* `creation of Heartbeat's "new cluster resource manager," which evolved into
  Pacemaker
  <https://gitlab.com/poki/archived-heartbeat/commit/bb48551be418291c46980511aa31c7c2df3a85e4>`_

* `deletion of the new CRM from Heartbeat after Pacemaker had been split off
  <https://gitlab.com/poki/archived-heartbeat/commit/74573ac6182785820d765ec76c5d70086381931a>`_

Regarding Pacemaker's split from heartbeat, it evolved stepwise (as opposed to
one-off cut), and the last step of full dependency is depicted in
`The Corosync Cluster Engine
<https://www.kernel.org/doc/ols/2008/ols2008v1-pages-85-100.pdf#page=14>`_
paper, fig. 10. This article also provides a good reference regarding wider
historical context of the tangentially (and deeper in some cases) meeting
components around that time.


Influence of Heartbeat on Pacemaker
___________________________________

On a closer look, we can identify these things in common:

* extensive use of data types and functions of
  `GLib <https://wiki.gnome.org/Projects/GLib>`_

* Cluster Testing System (CTS), inherited from initial implementation
  by Alan Robertson

* ...


Notable Restructuring Steps in the Codebase
###########################################

File renames may not appear as notable ... unless one runs into complicated
``git blame`` and ``git log`` scenarios, so some more massive ones may be
stated as well.

* watchdog/'sbd' functionality spin-off:

  * `start separating, eb7cce2a1
    <https://github.com/ClusterLabs/pacemaker/commit/eb7cce2a172a026336f4ba6c441dedce42f41092>`_
  * `finish separating, 5884db780
    <https://github.com/ClusterLabs/pacemaker/commit/5884db78080941cdc4e77499bc76677676729484>`_

* daemons' rename for 2.0 (in chronological order)

  * `start of moving daemon sources from their top-level directories under new
    /daemons hierarchy, 318a2e003
    <https://github.com/ClusterLabs/pacemaker/commit/318a2e003d2369caf10a450fe7a7616eb7ffb264>`_
  * `attrd -> pacemaker-attrd, 01563cf26
    <https://github.com/ClusterLabs/pacemaker/commit/01563cf2637040e9d725b777f0c42efa8ab075c7>`_
  * `lrmd -> pacemaker-execd, 36a00e237
    <https://github.com/ClusterLabs/pacemaker/commit/36a00e2376fd50d52c2ccc49483e235a974b161c>`_
  * `pacemaker_remoted -> pacemaker-remoted, e4f4a0d64
    <https://github.com/ClusterLabs/pacemaker/commit/e4f4a0d64c8b6bbc4961810f2a41383f52eaa116>`_
  * `crmd -> pacemaker-controld, db5536e40
    <https://github.com/ClusterLabs/pacemaker/commit/db5536e40c77cdfdf1011b837f18e4ad9df45442>`_
  * `pengine -> pacemaker-schedulerd, e2fdc2bac
    <https://github.com/ClusterLabs/pacemaker/commit/e2fdc2baccc3ae07652aac622a83f317597608cd>`_
  * `stonithd -> pacemaker-fenced, 038c465e2
    <https://github.com/ClusterLabs/pacemaker/commit/038c465e2380c5349fb30ea96c8a7eb6184452e0>`_
  * `cib daemon -> pacemaker-based, 50584c234
    <https://github.com/ClusterLabs/pacemaker/commit/50584c234e48cd8b99d355ca9349b0dfb9503987>`_

.. TBD:
   - standalone tengine -> part of crmd/pacemaker-controld
