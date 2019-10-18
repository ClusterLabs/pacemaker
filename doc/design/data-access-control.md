# Data Access Control Model (verging on ACLs/RBAC)

## Table of contents

* [Preface](#preface)
	* [Abstract concepts with intuitive notions](#abstract-concepts-with-intuitive-notions)
* [High-level design](#high-level-design)
	* ["Access" on an atomic level](#access-on-an-atomic-level)
	* [Access control as a set of conjunctions-of-three](#access-control-as-a-set-of-conjunctions-of-three)
		* [Quadruples, actually?](#quadruples-actually)
* [The access control label](#the-access-control-label)
	* [Three levels](#three-levels)
	* [Multi-label resolution](#multi-label-resolution)
	* [Access control matrix completing rules: initialization + inheritance rules](#access-control-matrix-completing-rules-initialization-inheritance-rules)
	* [Life-cycle of access control label](#life-cycle-of-access-control-label)
* [The object](#the-object)
	* [No attribute-level granularity](#no-attribute-level-granularity)
	* [Historical excurse: multi-match resolution](#historical-excurse-multi-match-resolution)
* [The subject](#the-subject)
	* [Superactor untangled](#superactor-untangled)
	* [Subject specification indirection through roles](#subject-specification-indirection-through-roles)
	* [Actor matching criteria](#actor-matching-criteria)
		* [User class resolution: system user identifier](#user-class-resolution-system-user-identifier)
		* [Group class resolution: system user membership in system group](#group-class-resolution-system-user-membership-in-system-group)
		* [Synthesis of the actor matching criteria](#synthesis-of-the-actor-matching-criteria)
* [Practical examples of how the model works](#practical-examples-of-how-the-model-works)


## Preface

This design document captures the actual _access control model_ as
implemented on top of the pacemaker distributed database (hence the emphasis
on data, as opposed to a generic API surface) serving the configuration and
flow coordination purposes within the cluster.  It does *not* necessarily
closely follow what
[a means to access control configuration](https://clusterlabs.org/pacemaker/doc/en-US/Pacemaker/2.0/html-single/Pacemaker_Explained/index.html#ch-acls)
is there for users to steer particular instance of the model in
the actual deployment.

Some such differences, mostly comprising a *syntactic sugar*/convenience
encoding (uninteresting from our conceptual perspective), are expressly
pointed out, but this slight disconnect between the conceptual model
and the final hands-on configuration experience (for versed readers)
shall be kept in mind while reviewing this document.

Conversely, the scope of this document does *not* include _communication
layer_
<!-- XXX: desirable to have separate communication-layer.md document -->
(as in API end-point contact) access protections, even though it cannot
be concealed altogether since it actually sources the authoritative
bits about the access instigator (__Actor__), as briefly
[touched upon](#actor-matching-criteria) later.

To connect the concepts to the resulting pieces of code, implementation
and test case references are added where suitable.

### Abstract concepts with intuitive notions

For better understanding, let's prefigure some abstract concepts, written
with Capitalized first letter to hint this fact better; following is an
ahead-of-time enumeration to help getting reader prepared:

+ __Asset__

   - intuitively: what the _access control_ mechanism protects, to begin with

   - factually: see [explained later](#the-object)

+ __Actor__

   - intuitively: who acts towards __Assets__

   - factually: see [explained later](#the-subject)

+ __Superactor__

   - intuitively: a specialization of the former that is recognized
     as an overlord on the __Asset__ access boundary

   - factually: see [explained later](#superactor-untangled)

Tautologically, abstract _access control_ could then be defined as
a way to establish rules of under which conditions particular __Actors__
(that are not __Superactors__) can approach particular __Assets__.
For more formal, alternative explanatory context, it is convenient to
reference an otherwise withdrawn
[draft of POSIX.1e](https://simson.net/ref/1997/posix_1003.1e-990310.pdf),
subheaded *Protection, Audit and Control Interfaces*.  Such references
will look as follows, here likewise for _access control_:

> (alternative, general term definition:
> [POSIX.1e:2.2.2.3](https://simson.net/ref/1997/posix_1003.1e-990310.pdf#page=12))

Not without remark is that it also descents as low as down to so far
intuitively used _access_ term:

> (alternative, general term definition:
> [POSIX.1e:2.2.2.1](https://simson.net/ref/1997/posix_1003.1e-990310.pdf#page=12))

As an aside, there are more possibly relevant, normative documents
in the problem space, such as
[DCE 1.1: Authentication and Security Services](https://pubs.opengroup.org/onlinepubs/9668899/chap1.htm#tagcjh_03_08).
Correspondence with these was intentionally left out at this time¹.

* * *

> ¹ Note, for instance, that this other referenced document refers to
>   *POSIX P1003.6 Draft 12*, which precedes this closely matched
>   *POSIX.1e* by several years, so there are various evolutionary influences
>   that shall be taken into account as well.

* * *


## High-level design

Said pacemaker built-in distributed database is based on the tree-like
structure for storage of particular bits.  Implementation-wise, it's an
[*XML*](https://www.w3.org/TR/xml/) document as detailed elsewhere, but
in this context, it's important to keep that in mind, since we are about
to refer to it in terms of _elements_ and _attributes_ (just as with
related, formally specified terminology like
[_parent_ and _child_](https://www.w3.org/TR/xml/#dt-parentchild)),
as devised in the respective specification.

In turn, this XML structure is all that matters regarding assignment of
powers onto particular __Actors__<!--fix markup malforming-->².
It's not surprising hence it was natural to appoint XML elements
(attributes) as __Assets__ at hand.

Note this XML document alone is an abstract concept in a sense, since it
does *not* necessarily refer to cold bits in a file system, but that's
out of scope here.  More on-topic is the fact that the configurable
declaration of the access control specifics is self-hosted within the
database itself, hence there is a possibility of a reflexive self-capture
of particular configuration directive for itself, amongst other
interesting properties.  This makes it particular configuration snapshot
specific as to whether this  _access control model_ is rather of
*discretionary* (*DAC*) or *mandatory* (*MAC*) kind.

> (general *DAC* term definition:
> [POSIX.1e:2.2.2.22](https://simson.net/ref/1997/posix_1003.1e-990310.pdf#page=14))

> (general *MAC* term definition:
> [POSIX.1e:2.2.2.34](https://simson.net/ref/1997/posix_1003.1e-990310.pdf#page=15))

Let's review several properties of how this XML -- access control pairing
works in a pure high-level sense before getting to gory parts.

* * *

> ² Well, almost, but mangling with resources or even nodes directly and
>   hence without a material trace in said configuration base is clearly out
>   of scope here, since those are to be protected with regular OS enabled
>   access control.

* * *

### "Access" on an atomic level

Aligned with internal workings of the transitions between internal
database's states, there are principally just two manipulations,
therefore only these can be protected:

* *create*: something new (attribute/element) is added to the tree

* *delete*: something existing in the tree is remove from there

In a practical sense, this is only interesting when there's any sort
of asymmetry, which is exactly the case with
[provisional `write` allowance rule for creation](#access-control-matrix-completing-rules-initialization-inheritance-rules).
Otherwise, the term is used to refer to both these equally.

Note that other actions, such as a change in attribute's value, is
effectively a composition of "remove old" and "add new" steps
(generalized over subtrees, recursively) from pacemaker's standpoint.

### Access control as a set of conjunctions-of-three

Notion of _access control_ in our settings can be dissected into a matrix
of three dimensions that will get further recursively dissected over a few
following sections, respectively:

* [_the object_](#the-object): (access *to what*; which of __Assets__)

   - set of elements (attributes), generally __Assets__, matched with
     a formula in a format-specific _selection_ (capture, query) language
     ([*XPath*](https://www.w3.org/TR/1999/REC-xpath-19991116/))

   - note that each such individual element is to be interpreted as
     a discrete, _flat_ item within the tree, *not* to be understood as
     a _whole subtree_ delineation (unless, of course, that's how
     explicitly the XPath query is constructed, since XPath is capable
     of that also)

   - also, there are countless ways to match a subset of what's always
     a *finite set* (given XML document has always, now or in the
     future, a finite number of elements/attributes, and moreover, the
     construction of the document is constrained with a finite number
     of elements to only be present), i.e., one _object_ (said formula)
     from the access control matrix will always match zero or up to all
     selectable (and countable) __Assets__ from the currently evaluated
     document instance)

   - finally, since this above implied `0..M:0..N` directed
     _objects_:__Assets__ relation (single _object_ matches zero to `N`
     __Assets__, and a single __Asset__ may be matched with zero to `M`
     _objects_) leads to singular _object_ vs. plural __Assets__
     imbalance, we can introduce a thought simplification without
     affecting generality:

     > further in the text, _object_ may resolve to a single
     > __Asset__ only (as if some kind of preprocessor would predict that
     > the formula will match multiple __Assets__, replacing it with
     > a single-match-only formulae for each) --- this changes that
     > relation to `0..M:0..1`, and slightly simplifies the view

   > (intentionally aligned with the term as explained:
   > [POSIX.1e:2.2.2.36](https://simson.net/ref/1997/posix_1003.1e-990310.pdf#page=15))

* [_the subject_](#the-subject) (access *by whom*; which __Actor__)

   - note that the limits as to the enumerability of all possible
     __Actors__ strictly relies on the surrounding system

   > (intentionally aligned with the term as explained:
   > [POSIX.1e:2.2.2.50](https://simson.net/ref/1997/posix_1003.1e-990310.pdf#page=16))

* [_the access control label_](#the-access-control-label)
  (binds the former two with *which kind of access* is permissible,
  i.e., when particular __Actor__ is to approach particular __Asset__)

   - note that unlike with the former two, the value here comes from
     a small, fixed set of [possible constants](#three-levels)

   > (virtually aligned with the term *information label* as explained:
   > [POSIX.1e:2.2.2.30](https://simson.net/ref/1997/posix_1003.1e-990310.pdf#page=12))

Mathematical insight here is that the access control is formally defined
as a subset of the Cartesian product of `O x S x L`, where the
components correspond to particular sets of the respective individuals
in the order stated above (and associable per the respective letters).
Less formally, we will call a particular item in such a Cartesian
product as _access control triple_.

Apparently, such a matrix is usually initialized --- by the means of user
configuration --- with just a fraction of all possible coincidences, and
the rest is, [on ad-hoc basis](#life-cycle-of-access-control-label),
derived per the access control completing rules
[detailed below](#access-control-matrix-completing-rules-initialization-inheritance-rules).

At this point, it is appropriate to remark that while this access
control matrix is
[marketed](https://clusterlabs.org/pacemaker/doc/en-US/Pacemaker/2.0/html-single/Pacemaker_Explained/index.html#ch-acls)
to the users (at least at the low-level configuration grounds, but can be
anticipated in high-level as well) as
[_access control lists_](https://en.wikipedia.org/wiki/Access-control_list),
the established permissions framework as implemented is actually verging on
[_role-based access control_](https://en.wikipedia.org/wiki/Role-based_access_control)
style of access containment (just with no particular roles predefined),
so we will refrain from using either of these³.

While this order of entities sitting in _the access control triples_ is
intentionally like this for its intuitivness, let's start detailing these
in another, definition-friendly one.  It feels smoother to start explaining
which _access control labels_ are available and how they are complemented for
cases not covered with an explicit configuration, only then _the object_ and
_the subject_ are examined in depth, respectively.

* * *

> ³ This design document is not the right place to spread accidental
>   misnomers based on imprecise demarcation (just as with *DAC*/*MAC*
>   before).

* * *

#### Quadruples, actually?

An interesting aspect to mention at this point, since we are about to show
that _subjects_ can just as well be matched
[based on membership in the system group](#group-class-resolution-system-user-membership-in-system-group),
is that the situation with granted access is not necessarily the same
across the nodes in the cluster.  While the same is to some extent applicable
also to plain user-based matching of __Actors__, it is not that expected there
would be intentional differences about which user poses particular accessing
client.

On the other hand, for fixed users, there can indeed be intentional (or even
accidental) variations regarding on behalf of which groups they can act, unless
a centralized account management (such as [FreeIPA](https://www.freeipa.org/);
also possibly negatively influencing HA goals for possibly becoming a *SPOF*)
is devised in that computing segment.  It is not hard then to imagine
a hypothetical generalization that introduces yet another dimension to
aforementioned three --- which set of nodes are concerned for the initial
triple, since user-to-groups mapping would then be delivered through solely
node-local means.  Formally, it would be a quadrupple from Cartesian product
`O x S x L x P(N)`, where `P(N)` denotes *power set* of the set of all nodes
available, and only for such nodes would the initial triple be in effect.

We will not complicate our model like that, the point here is rather to
demonstrate how the overall configuration space is in actuality
a composition of in-domain and globally shared configuration, and off-domain
host-local configuration with potential of making the play field rather
non-uniform.  Granted, a good cluster administrator keeps this in mind
without saying (and perhaps puts significant effort to maintain homogenity
throughout the cluster where it matters, to avoid surprises).


## The access control label

### Three levels

There are three discrete (nominally but not semantically, as
[explained later](#multi-label-resolution)) _access control labels_ as
applicable to the *single* _object_ (rest is completed per the rules
[detailed below](#access-control-matrix-completing-rules-initialization-inheritance-rules).

* `read`

   this *only* asserts a privilege for _the subject_ to get to know the _flat_
   content of _the object_ in question, that is, its mere existence, and for
   element, the attributes (children are then subjected to a separate
   evaluation)

   > (alternative, general term definition:
   > [POSIX.1e:2.2.2.41](https://simson.net/ref/1997/posix_1003.1e-990310.pdf#page=16))

* `write`

   as `read`, plus a privilege is asserted for _the subject_ to:

   - create such an object if not (softly) matched down to existing one
   - delete such an object (ability to delete an attribute is currently
     driven solely by the `write` _access control label_ at its element)

   > (alternative, general term definition:
   > [POSIX.1e:2.2.2.54](https://simson.net/ref/1997/posix_1003.1e-990310.pdf#page=17))

* `deny`

   all of the above privileges are declined for _the subject_

### Multi-label resolution

Since a single __Asset__ can be matched multiple times (for an affixed
__Actor__ --- matter of [matching in itself](#actor-matching-criteria)
--- otherwise trivially holds when not), multiple labels can be
bound to the same in parallel.  Note however, this can only happen for
*user class* resolution (for that purpose, conceptually comparable to
[*file owner class*](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_174)
if the file access control), since this multi-match (simply) *always*
worked that way here.

Contrary, when *group class* gets considered, a different, practice proven
[approach](#group-class-resolution-system-user-membership-in-system-group)
is taken, and such approach then generalizes (stacks) over __Asset__
multi-match cases we discuss here, for a predictable uniformity
(as to whether it was the __Asset__ that was multi-matched, or it was
__Actor__ that was inherently multi-group-matched, or even both)
--- there is always only a single label coming from relevant _access
control triples_ that can be bound to the __Asset__ in that case, hence
the multi-label will *not* get applied at all, effectively keeping
following resolution rules applicable for *user class* only (for being
bypassed otherwise):

1. `deny` takes the foremost precedence when present

2. `write` takes precedence over `read` when both present

> (implementation reference as of
> [`d307f9df9`](https://github.com/ClusterLabs/pacemaker/commit/d307f9df9#diff-3b508373ace569a6af4c386d9124202aR1964):
> `lib/common/xml.c:__xml_acl_mode_test` [now
> [`lib/common/acl.c`](https://github.com/ClusterLabs/pacemaker/tree/master/lib/common/acl.c)`:__xml_acl_mode_test`])

> (sample test reference: *none* [no multi-label resolution occurs])

### Access control matrix completing rules: initialization + inheritance rules

Following rules are complementary to the explicit user configuration
that always takes a precedence (as can be sensed also in the rules
themselves).

A) *Initialization rule*:

   if not explicitly configured otherwise, the default access control label
   at the root XML element is `deny`⁴

   > (implementation reference as of
   > [`f441da133`](https://github.com/ClusterLabs/pacemaker/commit/f441da133#diff-3b508373ace569a6af4c386d9124202aR566):
   > `lib/common/xml.c:__xml_acl_apply` [now
   > [`lib/common/acl.c`](https://github.com/ClusterLabs/pacemaker/tree/master/lib/common/acl.c)`:pcmk__apply_acl`])

   > (sample test reference: *none* [top-level always explicitly bound
   > the label])

   - as an optimization, if _the subject_ is *not* known to the configuration
     (there's not a single mention in the explicit set of coincidences),
     the default is `deny` right away

      > (implementation reference as of
      > [`d307f9df9`](https://github.com/ClusterLabs/pacemaker/commit/d307f9df9#diff-3b508373ace569a6af4c386d9124202aR1995):
      > `lib/common/xml.c:__xml_acl_check` [now
      > [`lib/common/acl.c`](https://github.com/ClusterLabs/pacemaker/tree/master/lib/common/acl.c)`:pcmk__check_acl`])

      > (sample test reference as of
      > [`a802f9a0f`](https://github.com/ClusterLabs/pacemaker/commit/a802f9a0f#diff-93bbc5e3eaefb43c6c52a5113a5bffd9R371-R374))

B) *Inheritance rule*:

   a child (XML attribute or subelement) of an element receives an explicit
   access control label based on the configuration, otherwise it derives its
   access control label from its parent (possibly itself resolved using
   either A. or B.)

   > (implementation reference as of
   > [`d307f9df9`](https://github.com/ClusterLabs/pacemaker/commit/d307f9df9#diff-3b508373ace569a6af4c386d9124202aR2005):
   > `lib/common/xml.c:__xml_acl_check` [now
   > [`lib/common/acl.c`](https://github.com/ClusterLabs/pacemaker/tree/master/lib/common/acl.c)`:pcmk__check_acl`])

   > (sample test reference as of
   > [`a802f9a0f`](https://github.com/ClusterLabs/pacemaker/commit/a802f9a0f#diff-93bbc5e3eaefb43c6c52a5113a5bffd9R410-R412))

C) *Convenience expressiveness "sugar" of provisional `write` for creation*:

   when an expressly allowed element (_object_) is [to be created](#access-on-an-atomic-level)
   and for its existence at particular upper hiearchy throughtout XML new
   parents elements (i.e. a complement to what already exists) would need to
   be created, these get one-off birth-only `write` override if they satisfy:
    - either no attribute at all, or
    - the only attribute named `id` exists with them, and, at the same time,
    - there is no traversal tripping over `acls` element

   > (implementation reference as of
   > [`3183a9422`](https://github.com/ClusterLabs/pacemaker/commit/3183a9422#diff-ae7f704017d4550e25f2027ade5ee23fR474):
   > [`lib/common/acl.c`](https://github.com/ClusterLabs/pacemaker/tree/master/lib/common/acl.c)`:implicitly_allowed`)

   > (sample test reference as of
   > [`a802f9a0f`](https://github.com/ClusterLabs/pacemaker/commit/a802f9a0f#diff-93bbc5e3eaefb43c6c52a5113a5bffd9R449-R453))

Note, in the context of *B.*, that between each two consecutive levels as the
(sub)tree descends from a (sub)root element to a child element (attribute),
it is valid to change the level of access control in both more stringent and
more relaxed direction (and both of these have their cases of use).

Also note, in the context of *C.*, that such "sugar" can be mechanically
removed, complementing equivalently each access control definition based on
XPath expression containing `nvpair` element (and perhaps some others as
can be derived from the schemas) as its tail path item & binding `write`
access control label with an additional `write` one whereby the XPath
expression would look like:

```
<ORIGINAL-XPATH-EXPRESSION>/..[
  (count(@*) = 0 or count(@*) = 1 and @id)
  and
  not(ancestor-or-self::*[name() = 'acls'])
]
```

Apparently, there's a little catch, since this is to only be applied on
enforced
[creation](#access-on-an-atomic-level)
of the missing "scaffolding", otherwise some unexpected deletions might
be mistakenly allowed as well.

* * *

> ⁴ This apparently does not apply for a distinguished __Superactor__,
>   see [below](#superactor-untangled), since access control is not evaluted
>   per these rules for such at all, and, as a corollary, the all-over
>   default in that case is `write` unconditionally, i.e., no child ever
>   receives an explicit access control label per B., and C. is hence not
>   applicable (everything is all-in implicitly).

* * *


### Life-cycle of access control label

Currently, the access control labels will get bound through the XML
tree (denoting _the object_) in the context of particular _subject_
making the underlying request in a dynamic, short-lived fashion.
No caching of such once evaluated assignments is attempted, perhaps
because of the possibly fast pace of changes that would invalidate anything
cached so far when simplistic and conservative approach would be taken,
unless elaborate guards are put in place, which would then require
a great amount of unit tests to assure this security sensitive handling
is safe and sound.

There are two main discrete phases in the life-cycle of _access control
labels_:

a) *passive*: preparation work whereby the applicable parts of _access control_
              as configured will get fetched and subsequently transformed as
              (private) properties throughout the XML tree --- in a breakdown:

   - *a1*: given particular user (specified with string encoded user name),
           matching _access control triples_ are grabbed from what's explicitly
           configured, and stored in an auxiliary per-document cache

      > (implementation reference as of
      > [`d307f9df9`](https://github.com/ClusterLabs/pacemaker/commit/d307f9df9#diff-3b508373ace569a6af4c386d9124202aR479-R517):
      > `lib/common/xml.c:__xml_acl_unpack` [now
      > [`lib/common/acl.c`](https://github.com/ClusterLabs/pacemaker/tree/master/lib/common/acl.c)`:pcmk__unpack_acl`])

   - *a2*: using the evaluated data from *a1*, the XML tree of the base
           document in question will receive (in a sparse,
           where-explicitly-configured-only manner) final private annotations
           denoting the set of _access control labels_ towards given
           and now implicit _subject_, without any effect of
           [the stated completing rules](#access-control-matrix-completing-rules-initialization-inheritance-rules)

      > (implementation reference as of
      > [`e2ed85fe0`](https://github.com/ClusterLabs/pacemaker/commit/e2ed85fe#diff-3b508373ace569a6af4c386d9124202aR511):
      > `lib/common/xml.c:__xml_acl_apply` [now
      > [`lib/common/acl.c`](https://github.com/ClusterLabs/pacemaker/tree/master/lib/common/acl.c)`:pcmk__apply_acl`])

b) *active*: as-needed comparisons of what the selected _object_ allows
             (towards given and now implicit _subject_; either per the
             explicit configuration as carried over in *a2*, or according
             to [the known rules](#access-control-matrix-completing-rules-initialization-inheritance-rules))
             vs. which access is requested

   > (implementation reference as of
   > [`d307f9df9`](https://github.com/ClusterLabs/pacemaker/commit/d307f9df9#diff-3b508373ace569a6af4c386d9124202aR1980):
   > `lib/common/xml.c:__xml_acl_check` [now
   > [`lib/common/acl.c`](https://github.com/ClusterLabs/pacemaker/tree/master/lib/common/acl.c)`:pcmk__check_acl`])

There's also a special extension on top of *active* phase for cases where
new element(s) can be added, that moreover plugs in
[the rule *C.* of provisional `write`](#access-control-matrix-completing-rules-initialization-inheritance-rules)
(also those implementation references are relevant).

*Forward-looking, optimization notice*:
The above two phases can be merged, building upon principles of lazy
evaluation, at the cost of lower time-complexity predictability (on the
other hand, it was WCET in a. previously, and here, it'd be better on
average) and, indeed, complexity.  Note that application of
[the inheritance rule *B.*](#access-control-matrix-completing-rules-initialization-inheritance-rules)
is already a part of the *active* phase.


## The object

[Already known](#access-control-as-a-set-of-conjunctions-of-three)
is that the __Assets__ in this access control model are
[elements](https://www.w3.org/TR/xml/#dt-element) and
[attributes](https://www.w3.org/TR/xml/#dt-attr) within the XML document
that represents the key dataset of pacemaker.  At this time, other
components of XML are treated as follows:

* [comments](https://www.w3.org/TR/xml/#dt-comment):

   - implicit `write` _access control label_ is assumed, that is, arbitrary
     _subject_ can add arbitrary comments anywhere(!), regardless of any
    [rules](#access-control-matrix-completing-rules-initialization-inheritance-rules)
    that apply to casual __Assets__.

      > (sample test reference: *none* [only elements get changed])

* the rest
  ([text nodes](https://www.w3.org/TR/xml/#dt-text) and
  [processing instructions](https://www.w3.org/TR/xml/#dt-pi)):

   - shall not figure in the XML document being processed, to begin with

      > (sample test reference: *none* [ditto])

Likewise, we already
[defined](#access-control-as-a-set-of-conjunctions-of-three)
*the object* being a declarative selection of these __Assets__, and we
further simplified the landscape by assuming such selection applicable
to at most a single __Asset__.

### No attribute-level granularity

While there's a way to select particular elements also conditionally per the
predicates related to their attribute(s) --- stemming naturally from the
expressiveness of the XPath selection applied under the hood --- XML attributes
are currently below the _access control_ granularity, i.e., their _access
control_ is solely driven by the respective containing element.

*Forward-looking notice*:
ACLs visualization per _the subject_ as exposed with `cibadmin --acls-render`
is ready to deal with attribute-level granularity shall it be introduced later
on.  Any SW dealing with such outputs shall not rely on attributes always
matching their parent elements on _the access control label_ applied.

### Historical excurse: multi-match resolution

It may so happen that a single _object_ will get matched multiple times
related to _the_ same _subject_ at hand.  In that case, there used to be
two possible behaviours possible, merely for the sake of completeness:

- [*SUSE-compatibility-specific*](https://github.com/ClusterLabs/pacemaker/commit/d200ed0cd):

   only the first (in
   [document order](https://www.w3.org/TR/1999/REC-xpath-19991116/#dt-document-order)
   within the respective configuration section in the XML tree) assignment
   related to particular *object* and *subject* will apply

- *default*:

   a mix of _access control labels_ can be assigned to the *object*
   (for particular implicit *subject*), the resolution is then governed
   per [the stated rules](#multi-label-resolution)


## The subject

In the preceding text, the notion of __Actor__ and its "all powerful"
specialization __Superactor__ were briefly mentioned.  It's time to look
at these instances of _the subject_ in our access control model.

### Superactor untangled

Abstract __Superactor__ concept is currently defined in terms of either
[*real*](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_315),
`ruid` (Linux), or
[*effective*](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_142),
`euid` (practically all other semi/supported POSIX systems),
*user identification*, as derived from the process connecting to one
of the pacemaker daemons so as to make a request (_pull_ model, any _push_
model arrangement needs to be initiated with a _pull_ of sorts),
and resolves to either of:

- `root` (beware, against intuition, regardless of `ruid=0`/`euid=0`!)
- [`hacluster`](https://github.com/ClusterLabs/pacemaker/blob/Pacemaker-2.0.2/configure.ac#L1084)

As stated, __Superactor__ is exempted from any access control considerations
(hence this "all powerful" tag).  Plugging the raw communication layer into
the picture for a bit again, this is a two-fold "free pass":

1. when accessing pacemaker daemons' API end-points as such, since
   this is one of the parallel prerequisites⁵ (alternatively, the user
   connecting in needs to be in
   [`haclient`](https://github.com/ClusterLabs/pacemaker/blob/Pacemaker-2.0.2/configure.ac#L1088)
   group)

2. access control per the discussed model (if the feature is enabled at all)

* * *

> ⁵ Note, however, that being `ruid=0`/`euid=0` alone in this API end-point
>   connection context may not be sufficient in the current arrangement of
>   pacemaker daemons that would offer the shared memory files to client
>   under `haclient` user ownership when such nominal __Superactor__ is
>   constrained from otherwise implicitly assumed "*DAC* override"
>   (in Linux in particular, lacking
>   [`CAP_DAC_OVERRIDE`](https://linux.die.net/man/7/credentials)
>   capability) privileges, as may happen, e.g., under *SELinux* containment.

* * *

### Subject specification indirection through roles

For casual __Actors__ (not satisifying __Superactor__ criteria), there's
a configuration layer indirection allowing to put a multiple individually
selected ones in to one set, and only this set can actually figure in
_the access control triple_.  But it's only another kind of syntactic
sugar for the configuration purposes otherwise not increasing the
expression power a tiny bit, we will hence keep it out of this scope.

Even if it is insignificant from conceptual perspective, it is worth
mentioning, though, for two reasons:

* it's what actually plugs the concept of roles (as in
  [said](#access-control-as-a-set-of-conjunctions-of-three) _RBAC_)
  into the picture

* to rectify the gap between the design sketch here and the actual
  configuration facilitated grip into it

### Actor matching criteria

At this point, there are two properties to discriminate particular
__Actor__ from the universum so as to expressly specify _the access
control triple_:

1. [*user class* resolution: system user identifier](#user-class-resolution-system-user-identifier)

2. [*group class* resolution: system-user-membership-in-system-group](#group-class-resolution-system-user-membership-in-system-group)

Both are elaborated in the respective following sections.  Subsequent section
than deals with how both criteria combine together.

Orthogonal to that, any __Actor__ interfacing with pacemaker API end-points
needs to satisfy the hard-wired communication layer imposed prerequisite that
shall be detailed elsewhere,
<!-- XXX: desirable to have separate communication-layer.md document -->
but for completeness, the intuitive `(user, groups)` identity of the
process making an access needs to satisfy either of:

* `ruid`/`euid` resolved to `root` (literally, without considering
  `ruid=0`/`euid=0` once the API end-point was successfully passed!) or
  [`hacluster`](https://github.com/ClusterLabs/pacemaker/blob/Pacemaker-2.0.2/configure.ac#L1084)
  (corresponds to __Superactor__ [per above](#superactor-untangled))

* [`egid`](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_141)
  (group counterpart to `euid`) resolved to, or associated
  [_supplementary groups_](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_378)
  include one resolved to
  [`haclient`](https://github.com/ClusterLabs/pacemaker/blob/Pacemaker-2.0.2/configure.ac#L1088)

   - the above expresses (is rather a corollary of) the concept of
     [*file group class*](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_167)
     that is being relied upon here

> (implementation reference as of
> [`165b05e9b`](https://github.com/ClusterLabs/pacemaker/commit/165b05e9b#diff-f0c579bcdba77d0ea4c6f0a89ee91b86R238-R274):
> `lib/common/ipc.c:crm_client_new`)

#### User class resolution: system user identifier

As preceded, this is currently the only available criterion to identify
particular __Actor__ (_subject_) with, unless already identified as
__Superactor__.

Likewise, the communication layer authentication is to be back-referenced
here, since that's what normally implies where said user identifier will
be sourced from.  Simply put, there's no better assurance about the _subject_
to make than what's derived (assurable given the OS authenticity attestation
guarantees) from the actual Unix socket based connection.

Call stack wise, let's start the excursion with
[`libqb`](https://github.com/ClusterLabs/libqb) provided
[`qb_ipcs_service_t` abstraction](https://clusterlabs.github.io/libqb/1.0.5/doxygen/qbipcs_8h.html#a098e863e2720e4611d49621487c9ca9d).
This is also what encapsulates the process of obtaining such OS assured
user identification for us, which is then passed into pacemaker
daemon-specific `connection_accept` callback stored within such
`qb_ipc_service_t` object, eventually triping over a common
[client entry function](https://github.com/ClusterLabs/pacemaker/blob/Pacemaker-2.0.2/lib/common/ipc.c#L364-L408).
Deep down, `libqb` relies on `libc` provided (and generally fairly
[platform specific](https://docs.fedoraproject.org/en-US/Fedora_Security_Team/1/html/Defensive_Coding/sect-Defensive_Coding-Authentication-UNIX_Domain.html),
without any POSIX imposed unification) means to obtain `ruid`/`euid` and
`rgid`/`egid` of the _subject_.  Corollary is that whenever the process
connecting towards pacemaker is not exercising any kind of
[credentials](https://linux.die.net/man/7/credentials)
twist (as in `seteuid`, `setegid`, etc., or conversely, when absolute
reset of the respective identification is used, as in `setuid`, is made
prior to any connection; both satisified with native pacemaker tooling),
we can freely ignore the difference between *real* and *effective*
tag to particular identifier.

Value of interest here, `ruid`/`euid`, is then converted to full-fledged
system user identifier using the standard `libc` function
[`getpwuid`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpwuid.html).
This means that eventually what can be denoted as system
[_user database_](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_435)
will be consulted.

Moreover, corollary is that with some implementations of `libc` and their
broader interpretation as to what _user database_ is, fully synthetic entries
originated in, say, a particular
[*NSS* module](https://www.gnu.org/software/libc/manual/html_node/Name-Service-Switch.html),
can get into the mix when such overrides are not configured for strict
consistency with the surrounding system⁶.

Finally, such obtained string is matched against explicitly configured
__Actors__ in _the access control triple_.

* * *

> ⁶ POSIX OS kernel really only deals with integer based identifications under
>   the hood for access control for basic resource abstractions like files and
>   processes; the resolution to and from human friendly names is just a user
>   space/`libc` convenience of sorts.

* * *

#### Group class resolution: system user membership in system group

Just as with [system user identifier](#user-class-resolution-system-user-identifier) that referred to
the concept of system _user database_, system group membership is likewise tight
to system
[_group database_](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_188).

Note however, the landscape gets more complicated with a simple fact that
whereas there is just a single entity to be associated with the user (behind
the accessing client), there is a `0..M:1..N` relation between such user and
the respective groups, as was already
[touched upon](#actor-matching-criteria)
(see `euid` vs. _supplementary groups_).

Even without considering multi-match with both *system user* and *system group*
membership criteria applied (discussed
[in the subsequent section](#synthesis-of-the-actor-matching-criteria),
there is a concern of how to deal with situation that particular
__Actor__ matches multiple groups at once.
What naturally follows is to approach this situation in a similar
fashion it is dealt with in
[POSIX.1e ACL facility](https://simson.net/ref/1997/posix_1003.1e-990310.pdf#page=52),
i.e., deferring to the
[already introduced](#abstract-concepts-with-intuitive-notions)
(for being on-topic here), withdrawn part of POSIX.
Note that while it is not an official component of that specification,
some platforms, such as Linux with standard GNU userspace, implemented it,
nonetheless, hence a bit of familiarity with this extension is assumed⁷.

The conflict resolution in such a case is hence equivalent to the respective
part of
[ACL access check algorithm](https://simson.net/ref/1997/posix_1003.1e-990310.pdf#page=52),
part **(3)** of the algorithm in particular (denoted lines 189-201), as quoted
below:

```
	[...]

	if the effective group ID or any of the supplementary group IDs of the process
	   match the group ID of the object or match the group ID specified in any
	   ACL_GROUP or ACL_GROUP_OBJ tag type ACL entry
	then

		if the requested access modes are granted by at least one entry matched
		   by the effective group ID or any of the supplementary group IDs of
		   the process
		then

			set matched entry to a granting entry

		else

			access is denied

		endiF

	[...]

	endif
```

where "setting matched entry" is just a distinctive phrasing for "selecting
the respective access verdict justification, out of possibly many".

In practical terms, the corollary interpretation to be applied is:

> Multiple differing permissions coming from the group class resolution of
> particular __Actor__ are flattened into the most allowing of these,
> i.e., whichever of these _access control labels_ occurs in
> the candidate set of the partial per-resolution intermediaries first,
> in order: `write`, `read`, `deny`.

It is vital to realize that this does *not* correspondgroup[per-subject multi-label resolution](#multi-label-resolution),
which is *only* applied when __Actor__ gets matched at
[*user class* resolution](#user-class-resolution-system-user-identifier),
shall the conflicting multi-label bindings arise as stated.

Likewise, it was already pointed out that this approach is generalized
so that it does *not* matter how particular __Asset__ gets matched,
given that all the respective _access control triples_ match
particular __Actor__ through *group class* only (when it is *not*
the case, is elaborated
[in the next section](#synthesis-of-the-actor-matching-criteria)).

* * *

> ⁷ Beside the referenced, platform-neutral POSIX part, you can also refer to
>   [acl(5)](https://linux.die.net/man/5/acl) manual page from the
>   [Linux access control lists](https://savannah.nongnu.org/projects/acl)
>   project (which conceptually follows said *POSIX.1e*, making it a full
>   circle).

* * *

#### Synthesis of the actor matching criteria

Now that the mechanics of how the multi-group membership
[was clarified](#group-class-resolution-system-user-membership-in-system-group),
we can continue our anabasis with how such group-level resolution (if any, but
then, there is just a single input from that line of resolution that feeds this
very resolution level) combines with the user-level one (that is itself already
flattened per
[the detailed multi-label resolution](#multi-label-resolution).

There are no surprises, since it literally complements
[ACL access check algorithm](https://simson.net/ref/1997/posix_1003.1e-990310.pdf#page=52)
part of which was
[already assumed on the group-level](#group-class-resolution-system-user-membership-in-system-group).
Specifically, the focus is on part **(2)** of the algorithm (denoted lines
185-189, note that part **(1)** is not applicable for a lack of *ownership*
concept), as quoted:


```
	[...]

	if the effective user ID of the process matches the use ID specified
	   in any ACL_USER tag type ACL entry
	then

		set matched entry to the matching ACL_USER entry

	else

		see quoted step (3) of the algorithm in the previous section

	[...]

	endif
```

Again, in practical terms, the corollary interpretation to build the top-level
decision logic up is (as is the order within the reference algorithm):

> Whenever particular __Actor__ is matched in the first installment of the
> access evaluation
> [based on *user class* resolution](#user-class-resolution-system-user-identifier)
> (also reflecting
> [per-subject multi-label resolution](#multi-label-resolution)), it is
> a final, explicit assessment.  Otherwise, the second installment of
> the evaluation
> [based on *group class* resolution](#group-class-resolution-system-user-membership-in-system-group)
> can possibly yield a final, explicit assessment.  Otherwise, only
> [implicit rules](#access-control-matrix-completing-rules-initialization--inheritance-rules)
> contribute to the final assessment, making for a mutualexclusivity
> for which of these installments will be applied in order.


## Practical examples of how the model works

* _objects_ (given through XPath expressions):

   - `obj1`: `/cib/configuration`
   - `obj2`: `/cib/configuration/crm_config`
   - `obj3`: `//crm_config` (intentionally, `obj2` = `obj3`
     for a schema-conformant pacemaker base document)

* explicitly configured _access control triples_ for _objects_:

   - `act1`: `(obj1, user:alice, read)`
   - `act2`: `(obj1, user:bob, read)`
   - * * *
   - `act3`: `(obj1, user:carol, deny)`
   - `act4`: `(obj1, user:carol, read)`
   - * * *
   - `act5`: `(obj2, user:alice, read)`
   - `act6`: `(obj3, user:alice, write)`
   - `act7`: `(obj3, user:alice, deny)`
   - * * *
   - `act8`: `(obj2, group:bluehats, deny)`
   - `act9`: `(obj3, group:redhats, read)`
   - * * *
   - `act10`: `(obj2, user:poki, write)`

* relevant system user to group(s) memberships:

   - user `alice`: `haclient`
   - user `bob`: *not in any relevant group*
   - user `root`: *not in any relevant group*, note we assume,
     conventionally, `uid = 0` and no kind of *DAC* override
     involved, so it is not refused
     [at the API end-point entry](#superactor-untangled)
     right away
   - user `hacluster`: `haclient` (a strict prerequisite for when
     particular pacemaker daemon runs as [super]privileged
     user on its own)
   - user `carol`: `haclient`
   - * * *
   - user `frankenstein`: `haclient`, `bluehats`, `redhats`
   - user `poki`: `haclient`, `redhats`

1. *user class* resolution only (assuming existence of the objects in question)

   - *Ex. 1*: for `/cib`, user `alice` gets `deny` assessment of
     _access control_, based on the *initialization rule* (*A.*) from
     [the stated implicit fallbacks](#access-control-matrix-completing-rules-initialization-inheritance-rules)
     that the root XML element not explicitly configured otherwise will get
     initialized like this

   - *Ex. 2*: for `/cib/status`, user `alice` gets `read` assessment of
     _access control_, based on the *inheritance rule* (*B.*) from
     [the stated implicit fallbacks](#access-control-matrix-completing-rules-initialization-inheritance-rules)
     that carries over the resolution from the immediate parent _object_,
     which so happens to likewise not be regulated explicitly and gets
     likewise implicitly completed --- see the previous *Ex 1.*

   - *Ex. 3*: for `/cib/configuration` (`obj1`), user `alice` gets `read`
     assessment of _access control_, since this is a trivial match with `act1`
     explicitly resolving triple, without any further involvement

   * * *

   - *Ex. 4*: for `/cib/configuration` (`obj1`), user `bob` gets
     *equivalent of* `deny` assessment of _access control_, since a basic
     prerequisite of the API end-point layer ---
     [membership in the `haclient` group](#actor-matching-criteria)
     --- is not fulfilled, so that the respective data _access
     control_ will not get questioned at all, for a premature denial
     (the same principle applies also for *group class* resolution, and is
     is not reproduced there for its obviousness)

   - *Ex. 5*: for `/cib/configuration` (`obj1`), user `root` under
     above assumptions
     [will get said free pass](#superactor-untangled)

   - *Ex. 6*: for `/cib/configuration` (`obj1`), user `haclient` under
     above assumptions
     [will get said free pass](#superactor-untangled)

   - *Ex. 7*: for `/cib/configuration` (`obj1`), user `carol` (who does not
     suffer from the lack of `haclient` group membership, which was
     a showstopper for `bob`, see the previous *Ex. 6*) gets `deny` assessment
     of _access control_, since the candidate set of intermediaries
     `{deny, read}` --- coming from `act3`, `act4` respectively --- is
     processed per [multi-label resolution](#multi-label-resolution)
     whereby `deny` dominates the other "accomplice" label, `read` (see 1.)

   * * *

   - *Ex. 8*: for `/cib/configuration/crm_config` (`obj2` = `obj3`), user
     `alice` gets `deny` assessment of _access control_, since the candidate
     set of intermediaries `{read, write, deny}` --- coming from `act5`,
     `act6`, `act7`, respectively --- is processed per
     [multi-label resolution](#multi-label-resolution)
     whereby `deny` dominates any other "accomplice" label (see 1.)

   - *Ex. 9*: for `/cib/configuration/crm_config/cluster_property_set`, user
     `alice` gets `deny` assessment of _access control_, based on the
     *inheritance rule* (*B.*) from
     [the stated implicit fallbacks](#access-control-matrix-completing-rules-initialization-inheritance-rules)
     that carries over the resolution from the immediate parent _object_
     --- see the previous *Ex. 8*

2. *group class* resolution only

   - *Ex. 10*: for `/cib/configuration/crm_config` (`obj2` = `obj3`), user
     `frankenstein` gets `read` assessment of _access control_, since the
     candidate set of intermediaries `{deny, read}` --- coming from `act8`,
     `act9`, or `bluehats`, `redhats` groups, respectively --- is processed per
     [*group class* resolution](#group-class-resolution-system-user-membership-in-system-group)
     whereby `read` dominates the other "accomplice" label, `deny`

3. mix of *user* and *group class* potential resolutions

   - *Ex. 11*: for `/cib/configuration/crm_config` (`obj2` = `obj3`), user
     `poki` gets `write` assessment of _access control_, since this is
     a trivial match with `act10` explicitly resolving triple, without
     any further involvement; note that,
     [as stated](#synthesis-of-the-actor-matching-criteria),
     applicability of *user class* precludes the second installment based
     on *group class* (which itself would yield `read` assessment)
