# Ideas About Future Extensions

These are half-baked ideas of the aspects that could be synchronized with
the currently known and compatible practices, technology and state-of-art
in general.

## Compatible Extensions

These do not require any concerns regarding multi-node/multi-version
compatibility.

### Efficiency & Parallelism

* replace `fork` + `exec`:
   + casual variant: `posix_spawn`:
      - https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=9ff72da471a509a8c19791efe469f47fa6977410
      - of limited applicability for reliability (glibc version? FreeBSD?):
        https://bugs.python.org/msg333123
   + hardcore variant: `vfork` instead of `fork`
      - https://bugs.python.org/issue35823
      - https://github.com/python/cpython/pull/11671/files
   * see also:
      - https://github.com/famzah/popen-noshell

* replace original `bzip2` with one of the parallel ones
  (as long as threading issue can be mitigated, e.g.,
  `pacemaker-based` doesn't start any children, so it
  fulfills some preconditions):
   - http://lbzip2.org/
   - https://code.launchpad.net/~pbzip2/pbzip2/1.1

### Node-local Core System Integration

* respond to the situations the local `hostname` is changed for whatever
  reason, accidental or intentional, since it may cause some undesired
  disparities (see `uname(2)`)
   + Linux: `poll(3)` on `/proc/sys/kernel/hostname`
      - https://lists.freedesktop.org/archives/systemd-devel/2019-August/043306.html

### Node-local Wider System Integration

* systemd:
   + systemic distinction of pacemaker-native (fixed set) and pacemaker-managed
     (open-ended set varying in time) processes from systemd/cgroup perspective
     - https://lists.clusterlabs.org/pipermail/users/2019-August/026270.html
