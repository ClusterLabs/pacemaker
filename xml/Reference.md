# Schema Reference

Along the other versions connected with Pacemaker, also the need to version
the schemas emerged.  This document provides a rationale as well a reference
schema-to-Pacemaker versions mapping.

## Versioned Schema Evolution

Most importantly, versioned scheme offers a transparent backward/forward
compatibility as it offers:

- reflecting the timeline of schema-backed features (introduction,
  changes to the syntax, possibly the deprecation) through the versioned
  stable schema increments while keeping old schema versions untouched
  (i.e., fixed for any Pacemaker version using it by default and newer)

- for cases where internal reprezentation of the Pacemaker configuration
  follows the convention of the latest stable schema version, it relies on
  supplemental transformations to promote instances of the configuration
  based on older, incompatible schema version into the desired form

- it allows experimental features with possibly unstable configuration
  interface to be developed using the special `next` version of the schema

Consult `Readme.md` of `xml` directory for details about how the versions
are maintained by the developers.

## Pacemaker to Particular Schema Version Mapping

| Pacemaker | Latest Schema | Changed
| --------- | ------------- | ----------------------------------------------
| `1.1.14`  | `2.4`         | `fencing`
| `1.1.13`  | `2.3`         | `constraints`
| `1.1.12`  | `2.0`         | `nodes`, `nvset`, `resources`, `tags` + `acls`
| `1.1.8`+  | `1.2`         |
