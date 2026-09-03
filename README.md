```
  Title: FROST Signing Protocol for Ed25519 Signatures
  Authors: Sivaram Dhakshinamoorthy <siv2ram@gmail.com>
  License: CC0-1.0
```

## Abstract

This document proposes a standard for the Flexible Round-Optimized Schnorr Threshold (FROST) signing protocol for Ed25519. The protocol produces ordinary 64-byte Ed25519 signatures as specified in [RFC 8032][rfc8032], verifying under a 32-byte Ed25519 threshold public key.

## Copyright

This document is made available under [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/).
The accompanying source code is licensed under the [MIT license](https://opensource.org/license/mit).

## Motivation

The FROST signature scheme enables threshold Ed25519 signatures. In a *t-of-n* threshold configuration, any *t*[^t-edge-cases] participants can cooperatively produce a signature that is indistinguishable from a signature produced by a single signer. FROST signatures are unforgeable as long as fewer than *t* participants are compromised. The signing protocol remains functional provided that at least *t* honest participants retain access to their secret shares.

[^t-edge-cases]: While *t = n* and *t = 1* are in principle supported, simpler alternatives are available in these cases. In the case *t = n*, using a dedicated *n-of-n* multi-signature scheme instead of FROST avoids the need for an interactive DKG (if using a trusted dealer for key generation is undesirable). The case *t = 1* can be realized by letting one signer generate an ordinary Ed25519 key pair ([RFC 8032][rfc8032]) and transmitting the key pair to every other signer, who can check its consistency and then simply use the ordinary Ed25519 signing algorithm. Signers still need to ensure that they agree on a key pair. The case *n = 1* is even simpler: it forces *t = 1*, and with no other signers to transmit the key pair to, the sole participant can directly use an ordinary Ed25519 key pair.

The IRTF has published [RFC 9591][rfc9591], which specifies the FROST signing protocol for several elliptic curve and hash function combinations, including edwards25519 with SHA-512. However, RFC 9591 specifies the original FROST protocol, in which every signer must process the full list of the other signers' nonce commitments. This document instead specifies the more efficient FROST3 variant, whose single nonce coefficient allows the coordinator to aggregate all public nonces into one constant-size aggregate nonce. In addition, this document adds partial signature verification with identifiable aborts, a coordinator-based communication model, and deterministic and stateless signing.

Following the initial publication of the FROST protocol[[KG20][frost1]], several optimized variants have been proposed to improve computational efficiency and bandwidth optimization: FROST2[[CKM21][frost2]], FROST2-BTZ[[BTZ21][stronger-security-frost]], and FROST3[[RRJSS][roast], [CGRS23][olaf]]. Among these variants, FROST3 is the most efficient variant to date.

This document specifies the FROST3 variant[^frost3-security]. It is an Ed25519 adaptation of the secp256k1 [FROST Signing Protocol for BIP340 Signatures][bip-frost-signing-secp], carrying over that specification's design while producing ordinary Ed25519 signatures ([RFC 8032][rfc8032]) in place of BIP 340 Schnorr signatures. Key generation for FROST signing is out of scope for this document.

[^frost3-security]: FROST3 has been proven existentially unforgeable under the Algebraic One-More Discrete Logarithm (AOMDL) assumption, for both trusted dealer and distributed key generation using the SimplPedPop protocol[[CGRS23][olaf]].

A FROST signature is a single 64-byte Ed25519 signature, and the threshold public key is a single 32-byte Ed25519 public key. Verifiers therefore need not be aware that a key is controlled by multiple parties: a *t-of-n* policy has the same size and verification cost as a single-signer key, the group membership remains private towards verifiers, and the number *n* of participants is not limited by the verifier.

## Overview

Implementers must make sure to understand this section thoroughly to avoid subtle mistakes that may lead to catastrophic failure.

### Optionality of Features

The goal of this proposal is to support a wide range of possible application scenarios.
Given a specific application scenario, some features may be unnecessary or not desirable, and implementers can choose not to support them.
Such optional features include:

- Identifying a malicious signer after aborting (aborting itself remains mandatory).
- The modified nonce generation algorithms *CounterNonceGen* and *DeterministicSign* (see [Modifications to Nonce Generation](#modifications-to-nonce-generation)).

If applicable, the corresponding algorithms should simply fail when encountering inputs unsupported by a particular implementation.
Similarly, the test vectors that exercise the unimplemented features should be re-interpreted to expect an error, or be skipped if appropriate.

### Key Material and Setup

A FROST key generation protocol configures a group of *n* participants with a *threshold public key* (representing a *t-of-n* threshold policy).
The corresponding *threshold secret key* is Shamir secret-shared among all *n* participants, where each participant holds a distinct long-term *secret share*.
This ensures that any subset of at least *t* participants can jointly run the FROST signing protocol to produce a signature under the *threshold secret key*.

Key generation for FROST signing is out of scope for this document. Implementations can use either a trusted dealer setup, as specified in [Appendix C of RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html#name-trusted-dealer-key-generati), or a distributed key generation (DKG) protocol such as [ChillDKG][chilldkg]. The appropriate choice depends on the implementation's trust model and operational requirements.

Public keys and signatures use the encodings of [RFC 8032][rfc8032]: *public shares* and *threshold public keys* are 32-byte point encodings, and signatures are 64 bytes.
There is only a single public key format, and no transformation of key material is required at any point of the signing protocol: signatures verify directly under the threshold public key output by key generation.

#### Protocol Parties and Network Setup

There are *u* (where *1 <= t <= u <= n < 2^32*)[^n-bound] signers[^participant-vs-signer] and one coordinator initiating the FROST signing protocol.
Each signer has a point-to-point communication link to the coordinator (but signers do not have direct communication links to each other).

> [!NOTE]
> The signer set need not be fixed before the first communication round.
> The coordinator may request *pubnonces* from more than *u* participants, even all *n* of them, and select the *u* signers afterwards, e.g., the first *t* participants that respond.
> The robust signing wrapper ROAST[[RRJSS][roast]] relies on exactly this pattern.
> The *pubnonces* of participants that are not selected are simply never aggregated.

[^n-bound]: This bound on *n* comes from the identifier encoding. A participant identifier is serialized as a 4-byte big-endian integer and fed into the tagged hash function that binds the nonces to the signer set, so it must fit in 32 bits. No realistic threshold setup approaches 2^32 participants, so the bound doesn't limit practical implementations.

[^participant-vs-signer]: This document says *participant* for anyone who took part in key generation, all *n* of them, and *signer* for a participant taking part in the current signing session, the *u* of them. Key material issued during key generation keeps the participant label, so *secshare*, *pubshare*, and the identifiers stay participant values even when a signer supplies them to an algorithm.

If there is no dedicated coordinator, one of the signers can act as the coordinator. Alternatively, the protocol can be run without any coordinator, with each signer sending its contributions to every other signer.

This document is written from the coordinator's perspective because the key generation methods compatible with this specification, a trusted dealer setup and ChillDKG, also involve a central third party. Implementations are therefore likely to reuse the same setup for signing.

#### Signing Inputs and Outputs

Each signing session requires two inputs: a participant's long-term *secret share* (individual to each participant, not shared with the coordinator) and a [Signers Context](#signers-context)[^signers-ctx-struct] data structure (common to all signers and the coordinator).

[^signers-ctx-struct]: The Signers Context represents the public data of signers: their identifiers (*id<sub>1..u</sub>*) and public shares (*pubshare<sub>1..u</sub>*).
Implementations may represent this as simply as two separate lists passed to signing APIs.
The threshold public key *thresh_pk* can be stored for efficiency or recomputed when needed using *DeriveThreshPubkey*.
Similarly, the values *n* and *t* are used only by *ValidateSignersCtx*.

This signing protocol is compatible with any key generation protocol that produces valid FROST keys.
Valid keys satisfy: (1) each *secret share* is a Shamir share of the *threshold secret key*, and (2) each *public share* equals the scalar multiplication *secshare &middot; B*.[^chilldkg-keys]
Before signing, the signers context must pass *ValidateSignersCtx*, which rejects duplicate identifiers and confirms the key material reproduces the threshold public key. The signing algorithms (*Sign*, *PartialSigVerify*, and *PartialSigAgg*) include this check for clarity, so an implementation can instead validate a context once and skip the repeated checks in later calls.
For comprehensive validation of the entire key material, *ValidateSignersCtx* can be run on all possible *u* signing participants.

[^chilldkg-keys]: ChillDKG satisfies both conditions, so its [DKG output](https://github.com/mllwchrry/bip-frost-dkg#dkg-outputs) can be used directly as key material.

> [!IMPORTANT]
> Passing *ValidateSignersCtx* ensures functional compatibility with the signing protocol but does not guarantee the security of the key generation protocol itself.

The output of the FROST signing protocol is an ordinary Ed25519 signature that verifies under the *threshold public key* as if it were produced by a single signer using the *threshold secret key*.

### General Signing Flow

The coordinator and signers must be determined before initiating the signing protocol.
The signer information is stored in a [Signers Context](#signers-context) data structure.

Whenever the signers want to sign a message, the basic order of operations to create a threshold signature is as follows:

**First communication round:**
Signers begin the signing session by running *NonceGen* to compute their *secnonce* and *pubnonce*.[^nonce-serialization-detail]
Each signer sends their *pubnonce* to the coordinator, who aggregates them using *NonceAgg* to produce an aggregate nonce and sends it back to all signers.

[^nonce-serialization-detail]: We treat the *secnonce* and *pubnonce* as grammatically singular even though they include serializations of two scalars and two elliptic curve points, respectively.
This treatment may be confusing for readers familiar with the internal workings of FROST.
However, the internal structure of the *secnonce* and the *pubnonce* is a technical detail that is irrelevant for users of FROST interfaces.

**Second communication round:**
At this point, every signer has the required data to sign, which, in the algorithms specified below, is stored in a data structure called [Session Context](#session-context).
Every signer computes a partial signature by running *Sign* with their long-term *secret share*, *secnonce* and the session context.
Then, each signer sends their partial signature to the coordinator, who runs *PartialSigAgg* to produce the final signature.
If all parties behaved honestly, the result is a valid Ed25519 signature under the threshold public key (see [Signature Verification](#signature-verification)).

![Frost signing flow](./docs/frost-signing-flow.png)

A malicious coordinator can cause the signing session to fail but cannot compromise the unforgeability of the scheme. Even when colluding with up to *t-1* signers, a malicious coordinator cannot forge a signature.

> [!WARNING]
> The *Sign* algorithm must **not** be executed twice with the same *secnonce*.
> Otherwise, it is possible to extract the secret share from the two partial signatures output by the two executions of *Sign*.
> To avoid accidental reuse of *secnonce*, an implementation may securely erase the *secnonce* argument by overwriting it with 64 zero bytes after it has been read by *Sign*.
> A *secnonce* consisting of only zero bytes is invalid for *Sign* and will cause it to fail.

To simplify the specification of the algorithms, some intermediary values are unnecessarily recomputed from scratch, e.g., when executing *GetSessionValues* multiple times.
Actual implementations can cache these values.
As a result, the [Session Context](#session-context) may look very different in implementations or may not exist at all.

> [!WARNING]
> The computation of *GetSessionValues* and storage of the result must be protected against modification from an untrusted third party.
> Such a party would have complete control over the threshold public key and message to be signed.

### Nonce Generation

*NonceGen* must have access to a high-quality random generator to draw an unbiased, uniformly random value *rand*.

> [!WARNING]
> In contrast to single-signer Ed25519 signing ([RFC 8032][rfc8032]), which derives its nonce deterministically from the secret key and the message, the values *k<sub>1</sub>* and *k<sub>2</sub>* **must not be derived deterministically** from the session parameters, because deterministic nonces enable a complete key-recovery attack in multi-party discrete-logarithm signatures[[MPSW18][musig]].[^det-nonce]

The optional arguments to *NonceGen* enable a defense-in-depth mechanism that may prevent secret share exposure if *rand* is accidentally not drawn uniformly at random.
If the value *rand* was identical in two *NonceGen* invocations, but any other argument was different, the *secnonce* would still be guaranteed to be different as well (with overwhelming probability), and thus accidentally using the same *secnonce* for *Sign* in both sessions would be avoided.
Therefore, it is recommended to provide the optional arguments *secshare*, *pubshare*, *thresh_pk*, and *m* if these session parameters are already determined during nonce generation.
The auxiliary input *extra_in* can contain additional contextual data that has a chance of changing between *NonceGen* runs,
e.g., a supposedly unique session id (taken from the application), a session counter wide enough not to repeat in practice, any nonces by other signers (if already known), or the serialization of a data structure containing multiple of the above.
However, the protection provided by the optional arguments should only be viewed as a last resort.
In most conceivable scenarios, the assumption that the arguments are different between two executions of *NonceGen* is relatively strong, particularly when facing an active adversary.

In some applications, the coordinator may enable preprocessing of nonce generation to reduce signing latency.
Signers run *NonceGen* to generate a batch of *pubnonce* values before the message or Signers Context[^preprocess-round1] is known, which are stored with the coordinator (e.g., on a centralized server).
During this preprocessing phase, only the available arguments are provided to *NonceGen*.
When a signing session begins, the coordinator selects and aggregates *pubnonces* of the signers, enabling them to run *Sign* immediately once the message is determined.
This way, the final signature is created quicker and with fewer round trips.
However, applications that use this method presumably store the nonces for a longer time and must therefore be even more careful not to reuse them.
Generating the nonces ahead of time in this manner does not affect the unforgeability of the scheme if nonce reuse is properly excluded,
but this method is not compatible with the defense-in-depth mechanism described in the previous paragraph.

[^det-nonce]: A signer's partial signature has the form *s = k<sub>1</sub> + b k<sub>2</sub> + e &lambda; d*, where *(k<sub>1</sub>, k<sub>2</sub>)* is the secret nonce, *d* is the secret share, and the coefficients *b* (nonce coefficient), *e* (challenge), and *&lambda;* (Lagrange interpolation over the signer set) are public. With deterministic nonces, an honest signer reproduces the identical *(k<sub>1</sub>, k<sub>2</sub>)* on every signing attempt for a given message. A malicious co-signer exploits this by replaying the session three times on that message and contributing a different nonce each time, which changes the aggregate nonce and therefore both *b* and *e*, while *&lambda;* stays fixed because the signer set is unchanged. The three resulting partial signatures form three linear equations in the unknowns *(k<sub>1</sub>, k<sub>2</sub>, d)*, which the co-signer solves to recover the victim's secret share *d*. This adapts the derandomization attack from Section 3.2 ("Derandomized Signing") of [[MPSW18][musig]], and a similar replay attack is noted for the stateless deterministic signing case in [^det-signer-set].

[^preprocess-round1]: When preprocessing *NonceGen* round, the Signers Context can be extended to include the *pubnonces* of the signers, as these are generated and stored before the signing session begins.

FROST signers are typically stateful: they generate *secnonce*, store it, and later use it to produce a partial signature after receiving the aggregated nonce.
However, stateless signing is possible when one signer receives the aggregate nonce of all OTHER signers before generating their own nonce.
In coordinator-based setups, the coordinator facilitates this by collecting pubnonces from the other signers, computing their aggregate (*aggothernonce*), and providing it to the stateless signer.
The stateless signer then runs *NonceGen*, *NonceAgg*, and *Sign* in sequence, sending its *pubnonce* and partial signature simultaneously to the coordinator, who computes the final aggregate nonce for all OTHER signers.
In coordinator-less setups, any one signer can achieve stateless operation by generating their nonce after seeing all other signers' *pubnonces*.
Stateless signers may want to consider signing deterministically (see [Modifications to Nonce Generation](#modifications-to-nonce-generation)) to remove the reliance on the random number generator in the *NonceGen* algorithm.

### Identifying Malicious Signers

The signing protocol makes it possible to identify malicious signers who send invalid contributions to a signing session in order to make the signing session abort and prevent the honest signers from obtaining a valid signature.
This property is called "identifiable aborts" and ensures that honest parties can assign blame to malicious signers who cause an abort in the signing protocol.

Aborts are identifiable for an honest party if the following conditions hold in a signing session:

- The contributions received from all signers have not been tampered with (e.g., because they were sent over authenticated connections).
- Nonce aggregation is performed honestly (e.g., because the coordinator is trusted to aggregate the *pubnonces* correctly).
- The partial signatures received from all signers are verified using the algorithm *PartialSigVerify*.

If these conditions hold and an honest party (signer or coordinator) runs an algorithm that fails due to invalid protocol contributions from malicious signers, then the algorithm run by the honest party will output the index (within the input list) of exactly one malicious signer.
Additionally, whenever more than one honest party runs an aborting algorithm on the same contributions, they all identify the same malicious signer.

In the coordinator setup assumed by this document, a signer receives only the aggregate nonce from the coordinator and never the individual *pubnonces* of the other signers, so it cannot recompute the aggregation to confirm it was done honestly and must trust the coordinator for the second condition. Because *PartialSigVerify* requires the full list of *pubnonces* and partial signatures, the coordinator (or a signer acting as the coordinator) is the natural party to run it and assign blame, as it is the only party that receives every signer's contribution.[^coordinator-less]

[^coordinator-less]: In coordinator-less setups (see the [Protocol Parties and Network Setup](#protocol-parties-and-network-setup) section), each signer broadcasts its contributions to every other signer, so every honest signer holds the full set of *pubnonces* and partial signatures and can run *PartialSigVerify* to assign blame on its own.

#### Further Remarks

Some of the algorithms specified below may also assign blame to a malicious coordinator.
While this is possible for some particular misbehavior of the coordinator, it is not guaranteed that a malicious coordinator can be identified.
More specifically, a malicious coordinator (whose existence violates the second condition above) can always make signing abort and wrongly hold honest signers accountable for the abort (e.g., by claiming to have received an invalid contribution from a particular honest signer).

The only purpose of the algorithm *PartialSigVerify* is to ensure identifiable aborts, and it is not necessary to use it when identifiable aborts are not desired.
In particular, partial signatures are *not* signatures.
An adversary can forge a partial signature, i.e., create a partial signature without knowing the secret share for that particular participant public share.[^partialsig-forgery]
However, if *PartialSigVerify* succeeds for all partial signatures then *PartialSigAgg* will return a valid Ed25519 signature.

[^partialsig-forgery]: Assume a malicious signer intends to forge a partial signature for the signer with public share *P*. It participates in the signing session pretending to be two distinct signers: one with the public share *P* and the other with its own public share. The adversary then sets the nonce for the second signer in such a way that allows it to generate a partial signature for *P*. As a side effect, it cannot generate a valid partial signature for its own public share. An explanation of the steps required to create a partial signature forgery can be found in [this document](https://gist.github.com/siv2r/0eab97bae9b7186ef2a4919e49d3b426).

## Algorithms

The following specification of the algorithms has been written with a focus on clarity. As a result, the specified algorithms are not always optimal in terms of computation and space. In particular, some values are recomputed but can be cached in actual implementations (see [General Signing Flow](#general-signing-flow)).

### Notation

The algorithms are defined over the **edwards25519 curve and its prime-order subgroup**, as specified in [RFC 8032][rfc8032]. The curve group has order *8 &middot; L*, where *L* is a prime; all protocol values are points of the prime-order subgroup of order *L*, which the strict decoding function defined below enforces. The identity element of the group is the point *(0, 1)*. We note that adapting this proposal to other elliptic curves is not straightforward and can result in an insecure scheme.

#### Cryptographic Types and Operations

We rely on the following types and conventions throughout this document:

- **Types:** Points on the curve are represented by the object *GE*, and scalars are represented by *Scalar*.
- **Naming:** Points are denoted using uppercase letters (e.g., *P*, *A*), while scalars are denoted using lowercase letters (e.g., *r*, *s*).
- **Encodings:** A point is encoded in 32 bytes as specified in RFC 8032: the little-endian encoding of its y-coordinate, with the sign of the x-coordinate stored in the most significant bit of the last byte. There is a single point encoding, and the identity element is encodable like any other point, so each decoding function states explicitly whether it accepts the identity. A scalar is an integer modulo *L*, encoded in 32 bytes in little-endian. Hash outputs are mapped to scalars by reducing the full 64-byte SHA-512 output modulo *L* ("wide reduction"). Other integers (identifiers, lengths) are encoded in big-endian.
- **Arithmetic:** The operators +, -, and &middot; are overloaded depending on their operands:
  - **Scalar Arithmetic:** When applied to two *Scalar* operands, +, -, and &middot; denote integer addition, subtraction, and multiplication modulo *L*.
  - **Point Addition:** When applied to two *GE* operands, + denotes the elliptic curve [group addition operation](https://en.wikipedia.org/wiki/Elliptic_curve#The_group_law). The Edwards addition law is complete, i.e., it has no special cases.
  - **Scalar Multiplication:** The notation r &middot; P denotes [scalar multiplication](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication) (the repeated addition of point P, r times).

The reference code vendors the ed25519lab library to handle underlying arithmetic, serialization, deserialization, and auxiliary functions. To improve the readability of this specification, we utilize simplified notation aliases for the library's internal methods, as mapped below:

<!-- markdownlint-disable MD033 -->
| Notation | ed25519lab | Description |
| --- | --- | --- |
| *p* | *FE.SIZE* | Field element size |
| *L* | *Scalar.SIZE*, *GE.ORDER* | Order of the prime-order subgroup |
| *B* | *B* | The Ed25519 base point |
| *identity* | *GE()* | The identity element *(0, 1)* |
| *is_identity(P)* | *P.is_identity* | Returns whether *P* is the identity element |
| *bytes(P)* | *P.to_bytes()* | Returns the 32-byte serialization of a point *P*; fails if *P* is the identity element |
| *bytes_ext(P)* | *P.to_bytes<br>_with_identity()* | Returns the 32-byte serialization of a point *P*. The identity element is serialized canonically like any other point |
| *point(b)* | *GE.from_bytes(b)* | Decodes a 32-byte serialization *b* into a point; fails if *b* is not canonical, not on the curve, not in the prime-order subgroup, or the identity element |
| *point_ext(b)* | *GE.from_bytes<br>_with_identity(b)* | Like *point(b)*, but accepts the canonical serialization of the identity element |
| *scalar_to_bytes(s)* | *s.to_bytes()* | Returns the 32-byte little-endian serialization of a scalar *s* |
| *scalar_from_bytes_checked(b)* | *Scalar.from_bytes_checked(b)* | Deserializes a 32-byte array *b* to a scalar, fails if the value is ≥ *L* |
| *scalar_from_bytes<br>_nonzero_checked(b)* | *Scalar.from_bytes<br>_nonzero_checked(b)* | Deserializes a 32-byte array *b* to a scalar, fails if the value is zero or ≥ *L* |
| *scalar_from_bytes_wide(b)* | *Scalar.from_bytes_wide(b)* | Deserializes a 64-byte array *b* to a scalar, reducing the value modulo *L* (wide reduction) |
| *hash(x)* | *hash_sha512(x)* | Computes the plain (untagged) 64-byte SHA-512 hash of the byte array *x* |
| *hash<sub>tag</sub>(x)* | *tagged_hash(tag, x)* | Computes a 64-byte domain-separated hash of the byte array *x*. The output is *SHA512(SHA512(tag)\[0:32] \|\| x)*, where *tag* is a UTF-8 encoded string unique to the context |
| *random_bytes(n)* | - | Returns *n* bytes, sampled uniformly at random using a cryptographically secure pseudorandom number generator (CSPRNG) |
| *xor_bytes(a, b)* | *xor_bytes(a, b)* | Returns byte-wise xor of *a* and *b* |
<!-- markdownlint-enable MD033 -->

> [!WARNING]
> The tagged hash hashes the tag into a fixed 32-byte prefix (the first 32 bytes of *SHA512(tag)*) instead of prepending the raw tag string. This is required for domain separation, not a stylistic choice, and implementations must not simplify it to a flat *SHA512(tag || x)*. Two of the tags are in a prefix relationship, *FROST3-ed25519-v1/nonce* and *FROST3-ed25519-v1/noncecoef*: under a flat prefix, *SHA512("FROST3-ed25519-v1/nonce" || "coef" || x)* would equal *SHA512("FROST3-ed25519-v1/noncecoef" || x)*, collapsing the domain separation between nonce derivation and the binding coefficient. Hashing the tag to a fixed length keeps the tag and data unambiguously separated, so no such collision can occur.

#### Auxiliary and Byte-string Operations

The following helper functions and notation are used for operations on standard integers and byte arrays, independent of curve arithmetic. Note that like Scalars, these variables are denoted by lowercase letters (e.g., *x*, *n*); the intended type is implied by context.

| Notation | Description |
| --- | --- |
| *\|\|* | Refers to byte array concatenation |
| *len(x)* | Returns the length of the byte array *x* in bytes |
| *x[i:j]* | Returns the sub-array of the byte array *x* starting at index *i* (inclusive) and ending at *j* (exclusive). The result has length *j - i* |
| *empty_bytestring* | A constant representing an empty byte array where length is 0 |
| *bytes(n, x)* | Returns the big-endian *n*-byte encoding of the integer *x* |
| *has_duplicates(lst)* | Returns *True* if any element in *lst* appears more than once, *False* otherwise |
| *sorted(lst)* | Returns a new list containing the elements of *lst* arranged in ascending order |
| *(a, b, ...)* | Refers to a tuple containing the listed elements |

> [!NOTE]
> In the following algorithms, all scalar arithmetic is understood to be modulo *L*. For example, *a &middot; b* implicitly means *a &middot; b mod L*

### Key Material and Setup

#### Signers Context

The Signers Context is a data structure consisting of the following elements:

- The total number *n* of participants involved in key generation: an integer with *1 ≤ n < 2<sup>32</sup>*[^t-edge-cases]
- The threshold number *t* of participants required to issue a signature: an integer with *1 ≤ t ≤ n*
- The list of participant identifiers *id<sub>1..u</sub>*: *u* distinct integers, each with *0 ≤ id<sub>i</sub> ≤ n - 1*, where the number *u* of signers satisfies *t ≤ u ≤ n*
- The list of participant public shares *pubshare<sub>1..u</sub>*: *u* 32-byte arrays, each a serialized point
- The threshold public key *thresh_pk*: a 32-byte array, serialized point

The lists *id<sub>1..u</sub>* and *pubshare<sub>1..u</sub>* are aligned by index: for every *i*, *id<sub>i</sub>* and *pubshare<sub>i</sub>* are the identifier and public share of the same participant. This correspondence is load-bearing (*DeriveThreshPubkey* pairs each *id<sub>i</sub>* with *pubshare<sub>i</sub>*, and *PartialSigVerify* reads *id<sub>i</sub>*, *pubshare<sub>i</sub>*, and *pubnonce<sub>i</sub>* together at a single index), and preserving it is the caller's responsibility: the algorithms check only that a given *pubshare* and *my_id* each appear somewhere in their list, not that they occupy the same position.

We write "Let *(n, t, id<sub>1..u</sub>, pubshare<sub>1..u</sub>, thresh_pk) = signers_ctx*" to assign names to the elements of Signers Context.

Algorithm *ValidateSignersCtx(signers_ctx)*:

- Inputs:
  - The *signers_ctx*: a [Signers Context](#signers-context) data structure
- *(n, t, id<sub>1..u</sub>, pubshare<sub>1..u</sub>, thresh_pk) = signers_ctx*
- Fail if not *1 ≤ t ≤ n*
- Fail if not *t ≤ u ≤ n*
- For *i = 1 .. u*:
  - Fail if not *0 ≤ id<sub>i</sub> ≤ n - 1*
  - Let *P<sub>i</sub> = point(pubshare<sub>i</sub>)*; fail if that fails
- Fail if *has_duplicates(id<sub>1..u</sub>)*
- Let *thresh_pk' = DeriveThreshPubkey(id<sub>1..u</sub>, P<sub>1..u</sub>)*; fail if that fails
- Fail if *thresh_pk' ≠ thresh_pk*
- No return

Internal Algorithm *DeriveThreshPubkey(id<sub>1..u</sub>, P<sub>1..u</sub>)*[^derive-thresh-no-validate-inputs]

- *A = identity*
- For *i = 1..u*:
  - *&lambda; = DeriveInterpolatingValue(id<sub>1..u</sub>, id<sub>i</sub>)*
  - *A = A + &lambda; &middot; P<sub>i</sub>*
- Fail if *is_identity(A)*
- Return *bytes(A)*

[^derive-thresh-no-validate-inputs]: *DeriveThreshPubkey* does not validate its inputs. Its only caller, *ValidateSignersCtx*, deserializes the public shares into points and validates them (and the identifiers) beforehand.

Internal Algorithm *DeriveInterpolatingValue(id<sub>1..u</sub>, my_id):*

- Fail if *my_id* not in *id<sub>1..u</sub>*
- Fail if *has_duplicates(id<sub>1..u</sub>)*
- Let *num = Scalar(1)*
- Let *deno = Scalar(1)*
- For *i = 1..u*:
  - If *id<sub>i</sub> ≠ my_id*:
    - Let *num = num &middot; Scalar(id<sub>i</sub> + 1)[^lagrange-shift] &ensp;(mod L)*
    - Let *deno = deno &middot; Scalar(id<sub>i</sub> - my_id) &ensp;(mod L)*
- *&lambda; = num &middot; deno<sup>-1</sup> &ensp;(mod L)*
- Return *&lambda;*

[^lagrange-shift]: The standard Lagrange interpolation coefficient uses the formula *id<sub>i</sub> / (id<sub>i</sub> - my_id)* for each term in the product, where identifiers are in the range *1..n*. However, since participant identifiers in this protocol are zero-indexed (range *0..n-1*), we shift them by adding 1. This transforms each term to *(id<sub>i</sub>+1) / (id<sub>i</sub> - my_id)*.

### Nonce Generation

Algorithm *NonceGen(secshare, pubshare, thresh_pk, m, extra_in)*:

- Inputs:
  - The participant secret share *secshare*: a 32-byte array, serialized scalar (optional argument)
  - The participant public share *pubshare*: a 32-byte array, serialized point (optional argument)
  - The threshold public key *thresh_pk*: a 32-byte array, serialized point (optional argument)
  - The message *m*: a byte array (optional argument)[^max-msg-len]
  - The auxiliary input *extra_in*: a byte array with *0 ≤ len(extra_in) ≤ 2<sup>32</sup>-1* (optional argument)
- Let *rand = random_bytes(32)*
- If the optional argument *secshare* is present:
  - Let *rand' = xor_bytes(secshare, hash<sub>FROST3-ed25519-v1/aux</sub>(rand)\[0:32])*[^sk-xor-rand]
- Else:
  - Let *rand' = rand*
- If the optional argument *pubshare* is not present:
  - Let *pubshare* = *empty_bytestring*
- If the optional argument *thresh_pk* is not present:
  - Let *thresh_pk* = *empty_bytestring*
- If the optional argument *m* is not present:
  - Let *m_prefixed = bytes(1, 0)*
- Else:
  - Let *m_prefixed = bytes(1, 1) || bytes(8, len(m)) || m*
- If the optional argument *extra_in* is not present:
  - Let *extra_in = empty_bytestring*
- Let *k<sub>i</sub> = scalar_from_bytes_wide(hash<sub>FROST3-ed25519-v1/nonce</sub>(rand' || bytes(1, len(pubshare)) || pubshare || bytes(1, len(thresh_pk)) || thresh_pk || m_prefixed || bytes(4, len(extra_in)) || extra_in || bytes(1, i - 1)))* for *i = 1,2*
- Fail if *k<sub>1</sub> = Scalar(0)* or *k<sub>2</sub> = Scalar(0)*[^negligible-zero-scalar]
- Let *R<sub>\*,1</sub> = k<sub>1</sub> &middot; B*, *R<sub>\*,2</sub> = k<sub>2</sub> &middot; B*
- Let *pubnonce = bytes(R<sub>\*,1</sub>) || bytes(R<sub>\*,2</sub>)*
- Let *secnonce = scalar_to_bytes(k<sub>1</sub>) || scalar_to_bytes(k<sub>2</sub>)*[^secnonce-ser][^secnonce-no-pubshare]
- Return *(secnonce, pubnonce)*

[^sk-xor-rand]: The random data is hashed (with a unique tag) as a precaution against situations where the randomness may be correlated with the secret share itself. It is xored with the secret share (rather than combined with it in a hash) to reduce the number of operations exposed to the actual secret share. Since the tagged hash outputs 64 bytes, it is truncated to the 32-byte width of the secret share; the truncation loses no security, as the mask needs only as many bytes as the value it hides.

[^secnonce-ser]: The algorithms as specified here assume that the *secnonce* is stored as a 64-byte array using the serialization *secnonce = scalar_to_bytes(k<sub>1</sub>) || scalar_to_bytes(k<sub>2</sub>)*. The same format is used in the reference implementation and in the test vectors. However, since the *secnonce* is (obviously) not meant to be sent over the wire, compatibility between implementations is not a concern, and this method of storing the *secnonce* is merely a suggestion. The *secnonce* is effectively a local data structure of the signer which comprises the value pair *(k<sub>1</sub>, k<sub>2</sub>)*, and implementations may choose any suitable method to carry it from *NonceGen* (first communication round) to *Sign* (second communication round). In particular, implementations may choose to hide the *secnonce* in internal state without exposing it in an API explicitly, e.g., in an effort to prevent callers from reusing a *secnonce* accidentally.

[^secnonce-no-pubshare]: The [MuSig2][bip327] signing protocol appends the serialized individual public key to the *secnonce* to avoid a vulnerability that may arise when MuSig2 signers derive a different individual key pair between nonce generation and signing. In FROST, a participant's public share and the threshold public key are fixed at key generation, so this vulnerability does not apply, and appending the public share to the *secnonce* is not necessary.

[^max-msg-len]: In theory, the allowed message size is restricted because SHA-512 accepts byte strings only up to size of 2^125-1 bytes (and because of the 8-byte length encoding).

[^negligible-zero-scalar]: These are unreachable errors, included for completeness: such a value equals *Scalar(0)* only with negligible probability. The reference implementation checks the condition with an assertion.

### Nonce Aggregation

Algorithm *NonceAgg(pubnonce<sub>1..u</sub>)*:

- Inputs:
  - The list of signers' public nonces *pubnonce<sub>1..u</sub>*: *u* 64-byte arrays, each an output of *NonceGen*
- For *j = 1 .. 2*:
  - For *i = 1 .. u*:
    - Let *R<sub>i,j</sub> = point(pubnonce<sub>i</sub>[(j-1)\*32:j\*32])*; fail if that fails and blame signer at index *i* for invalid *pubnonce*
  - Let *R<sub>j</sub> = R<sub>1,j</sub> + R<sub>2,j</sub> + ... + R<sub>u,j</sub>*
- Return *aggnonce = bytes_ext(R<sub>1</sub>) || bytes_ext(R<sub>2</sub>)*

### Session Context

The Session Context is a data structure consisting of the following elements:

- The *signers_ctx*: a [Signers Context](#signers-context) data structure
- The aggregate public nonce *aggnonce*: a 64-byte array, output of *NonceAgg*
- The message *m*: a byte array[^max-msg-len]

We write "Let *(signers_ctx, aggnonce, m) = session_ctx*" to assign names to the elements of a Session Context.

Algorithm *GetSessionValues(session_ctx)*:

- Let *(signers_ctx, aggnonce, m) = session_ctx*
- *ValidateSignersCtx(signers_ctx)*; fail if that fails
- Let *(_, _, id<sub>1..u</sub>, pubshare<sub>1..u</sub>, thresh_pk) = signers_ctx*
- Let *ser_ids* = *SerializeIds(id<sub>1..u</sub>)*[^canonical-ids-det-sign]
- Let *b* = *scalar_from_bytes_wide(hash<sub>FROST3-ed25519-v1/noncecoef</sub>(bytes(4, u) || ser_ids || aggnonce || thresh_pk || m))*
- Fail if *b = Scalar(0)*[^negligible-zero-scalar]
- Let *R<sub>1</sub> = point_ext(aggnonce[0:32]), R<sub>2</sub> = point_ext(aggnonce[32:64])*; fail if that fails and blame the coordinator for invalid *aggnonce*.
- Let *R' = R<sub>1</sub> + b &middot; R<sub>2</sub>*
- If *is_identity(R'):*
  - Let final nonce *R = B* ([see Dealing with the Identity Element in Nonce Aggregation](#dealing-with-the-identity-element-in-nonce-aggregation))
- Else:
  - Let final nonce *R = R'*
- Let *e = scalar_from_bytes_wide(hash(bytes(R) || thresh_pk || m))*[^untagged-challenge]
- Fail if *e = Scalar(0)*[^negligible-zero-scalar]
- Return *(id<sub>1..u</sub>, pubshare<sub>1..u</sub>, b, R, e)*

Internal Algorithm *SerializeIds(id<sub>1..u</sub>)*:

- Let *sorted_id<sub>1..u</sub> = sorted(id<sub>1..u</sub>)*
- *res = empty_bytestring*
- For *i = 1..u*:
  - *res = res || bytes(4, sorted_id<sub>i</sub>)*
- Return *res*

[^untagged-challenge]: The challenge *e* is deliberately computed without a tag, exactly as specified in [RFC 8032][rfc8032]. This is what makes the aggregate signature an ordinary Ed25519 signature (see [Signature Verification](#signature-verification)). All other hashes in this document are domain-separated with tags under the *FROST3-ed25519-v1/* namespace.

[^canonical-ids-det-sign]: The identifiers are sorted so that *b* commits to the signer *set*, not the order they appear in. This matters for *DeterministicSign*, where a signer reproduces the same secret nonce *(k<sub>1</sub>, k<sub>2</sub>)* whenever its inputs are unchanged. Suppose an implementation sorts the identifiers when deriving this nonce but not when deriving *b*. A malicious coordinator can then replay one signing session under three orderings of the same signer set: the victim returns the same nonce each time, but *b* and the challenge *e* change with the order. The three partial signatures *s = k<sub>1</sub> + b k<sub>2</sub> + e &lambda; d* form a system of three linear equations in *(k<sub>1</sub>, k<sub>2</sub>, d)*, which the coordinator solves to recover the secret share *d*. Sorting prevents this. It is the order analog of the attack in [^det-signer-set].

### Signing

Algorithm *Sign(secnonce, secshare, my_id, session_ctx)*:

- Inputs:
  - The secret nonce *secnonce* that has never been used as input to *Sign* before: a 64-byte array[^secnonce-ser]
  - The participant secret share *secshare*: a 32-byte array, serialized scalar
  - The participant identifier *my_id*: an integer with *0 ≤ my_id ≤ n-1*
  - The *session_ctx*: a [Session Context](#session-context) data structure
- Let *(id<sub>1..u</sub>, pubshare<sub>1..u</sub>, b, _, e) = GetSessionValues(session_ctx)*; fail if that fails
- Let *k<sub>1</sub> = scalar_from_bytes_nonzero_checked(secnonce[0:32])*; fail if that fails
- Let *k<sub>2</sub> = scalar_from_bytes_nonzero_checked(secnonce[32:64])*; fail if that fails
- Let *d = scalar_from_bytes_nonzero_checked(secshare)*; fail if that fails
- Let *pubshare = bytes(d &middot; B)*
- Fail if *pubshare* not in *pubshare<sub>1..u</sub>*
- Fail if *my_id* not in *id<sub>1..u</sub>*
- Let *&lambda; = DeriveInterpolatingValue(id<sub>1..u</sub>, my_id)*; fail if that fails
- Let *s = k<sub>1</sub> + b &middot; k<sub>2</sub> + e &middot; &lambda; &middot; d &ensp;(mod L)*
- Let *psig = scalar_to_bytes(s)*
- Let *pubnonce = bytes(k<sub>1</sub> &middot; B) || bytes(k<sub>2</sub> &middot; B)*
- If *PartialSigVerifyInternal(psig, my_id, pubnonce, pubshare, session_ctx)* (see below) returns failure, fail[^why-verify-partialsig]
- Return partial signature *psig*

[^why-verify-partialsig]: Verifying the signature before leaving the signer prevents random or adversarially provoked computation errors. This prevents publishing invalid signatures which may leak information about the secret share. It is recommended but can be omitted if the computation cost is prohibitive.

### Partial Signature Verification

Both *PartialSigVerify* and the self-check that *Sign* runs on its own partial signature delegate the core verification to the internal *PartialSigVerifyInternal* algorithm defined below.

Algorithm *PartialSigVerify(psig, pubnonce<sub>1..u</sub>, signers_ctx, m, i)*:

- Inputs:
  - The partial signature *psig*: a 32-byte array, serialized scalar
  - The list of public nonces *pubnonce<sub>1..u</sub>*: *u* 64-byte arrays, each an output of *NonceGen*
  - The *signers_ctx*: a [Signers Context](#signers-context) data structure
  - The message *m*: a byte array[^max-msg-len]
  - The index *i* of the signer in the list of public nonces where *0 ≤ i ≤ u - 1*
- *ValidateSignersCtx(signers_ctx)*; fail if that fails
- Let *(_, _, id<sub>1..u</sub>, pubshare<sub>1..u</sub>, _) = signers_ctx*
- Let *aggnonce = NonceAgg(pubnonce<sub>1..u</sub>)*; fail if that fails
- Let *session_ctx = (signers_ctx, aggnonce, m)*
- Run *PartialSigVerifyInternal(psig, id<sub>i</sub>, pubnonce<sub>i</sub>, pubshare<sub>i</sub>, session_ctx)*
- Return success iff no failure occurred before reaching this point.

Internal Algorithm *PartialSigVerifyInternal(psig, my_id, pubnonce, pubshare, session_ctx)*:

- Let *(id<sub>1..u</sub>, pubshare<sub>1..u</sub>, b, _, e) = GetSessionValues(session_ctx)*; fail if that fails
- Let *s = scalar_from_bytes_checked(psig)*; fail if that fails
- Fail if *pubshare* not in *pubshare<sub>1..u</sub>*
- Fail if *my_id* not in *id<sub>1..u</sub>*
- Let *R<sub>\*,1</sub> = point(pubnonce[0:32]), R<sub>\*,2</sub> = point(pubnonce[32:64])*; fail if either fails
- Let effective nonce *Re<sub>\*</sub> = R<sub>\*,1</sub> + b &middot; R<sub>\*,2</sub>*
- Let *P = point(pubshare)*; fail if that fails
- Let *&lambda; = DeriveInterpolatingValue(id<sub>1..u</sub>, my_id)*[^lambda-cant-fail]
- Fail if *s &middot; B ≠ Re<sub>\*</sub> + e &middot; &lambda; &middot; P*
- Return success iff no failure occurred before reaching this point.

[^lambda-cant-fail]: *DeriveInterpolatingValue(id<sub>1..u</sub>, my_id)* cannot fail when called from *PartialSigVerifyInternal* as *PartialSigVerify* picks *my_id* from *id<sub>1..u</sub>*

### Partial Signature Aggregation

Algorithm *PartialSigAgg(psig<sub>1..u</sub>, session_ctx)*:

- Inputs:
  - The list of partial signatures *psig<sub>1..u</sub>*: *u* 32-byte arrays, each an output of *Sign*
  - The *session_ctx*: a [Session Context](#session-context) data structure
- Let *(id<sub>1..u</sub>, _, _, R, _) = GetSessionValues(session_ctx)*; fail if that fails
- For *i = 1 .. u*:
  - Let *s<sub>i</sub> = scalar_from_bytes_checked(psig<sub>i</sub>)*; fail if that fails and blame signer at index *i* for invalid partial signature.
- Let *s = s<sub>1</sub> + ... + s<sub>u</sub> &ensp;(mod L)*
- Return *sig = bytes(R) || scalar_to_bytes(s)*

### Signature Verification

The output of *PartialSigAgg* is an ordinary Ed25519 signature: the challenge is computed exactly as specified in [RFC 8032][rfc8032] (see [^untagged-challenge]), so the signature can be verified for the threshold public key *thresh_pk* and message *m* by any conforming Ed25519 verifier.

RFC 8032 leaves verifiers a choice between two group equations: the *cofactored* check *\[8]\[s]B = \[8]R + \[8]\[e]A* and the *cofactorless* check *\[s]B = R + \[e]A*. The two disagree only on signatures containing points outside the prime-order subgroup, which honest signers never produce. This document specifies the cofactorless equation together with a strict decoding policy. The cofactorless equation is the stricter of the two permitted choices and the one implemented by widely deployed verifiers (e.g., libsodium and ed25519-dalek's `verify_strict`); the decoding policy specified here is stricter than both, rejecting mixed-order points that those verifiers accept because they screen out only small-order points:

Algorithm *Verify(thresh_pk, m, sig)*:

- Inputs:
  - The threshold public key *thresh_pk*: a 32-byte array, serialized point
  - The message *m*: a byte array[^max-msg-len]
  - The signature *sig*: a 64-byte array
- Let *A = point(thresh_pk)*; fail if that fails
- Let *R = point(sig[0:32])*; fail if that fails
- Let *s = scalar_from_bytes_checked(sig[32:64])*; fail if that fails
- Let *e = scalar_from_bytes_wide(hash(sig[0:32] || thresh_pk || m))*
- Fail if *s &middot; B ≠ R + e &middot; A*
- Return success iff no failure occurred before reaching this point.

Because *point(b)* rejects non-canonical encodings, points outside the prime-order subgroup, and the identity element, every component of an accepted signature is canonical and of prime order. Signatures produced by this protocol satisfy these conditions by construction, so they are accepted both by this verifier and by more permissive RFC 8032 verifiers (cofactored, or without subgroup checks). The converse does not hold: verifiers may disagree on adversarially crafted signatures containing small-order or mixed-order points. Applications in which multiple parties must reach the same verdict on signature validity should therefore agree on a single verification policy, such as the one specified here.

Note that *PartialSigVerifyInternal* checks each signer's contribution with the same cofactorless equation, restricted to that signer's effective nonce and public share.

### Test Vectors & Reference Code

We provide a naive, highly inefficient, and non-constant time [pure Python 3 reference implementation of the nonce generation, partial signing, and partial signature verification algorithms](./python/frost_ref/).

Standalone JSON test vectors are also available in the [same directory](./python/vectors/), to facilitate porting the test vectors into other implementations.

> [!CAUTION]
> The reference implementation is for demonstration purposes only and not to be used in production environments.

## Remarks on Security and Correctness

### Modifications to Nonce Generation

Implementers must avoid modifying the *NonceGen* algorithm without being fully aware of the implications.
We provide two modifications to *NonceGen* that are secure when applied correctly and may be useful in special circumstances, summarized in the following table.

| | needs secure randomness | needs secure counter | needs to keep state securely | needs aggregate nonce of all other signers (only possible for one signer) |
| --- | --- | --- | --- | --- |
| **NonceGen** | ✓ | | ✓ | |
| **CounterNonceGen** | | ✓ | ✓ | |
| **DeterministicSign** | | | | ✓ |

First, on systems where obtaining uniformly random values is much harder than maintaining a global atomic counter, it can be beneficial to modify *NonceGen*.
The resulting algorithm *CounterNonceGen* does not draw *rand* uniformly at random but instead sets *rand* to the value of an atomic counter that is incremented whenever it is read.
With this modification, the secret share *secshare* of the signer generating the nonce is **not** an optional argument and must be provided to *NonceGen*.
The security of the resulting scheme then depends on the requirement that reading the counter must never yield the same counter value in two *NonceGen* invocations with the same *secshare*.

Second, if there is a unique signer who generates their nonce last (i.e., after receiving the aggregate nonce from all other signers), it is possible to modify nonce generation for this single signer to not require high-quality randomness.
Such a nonce generation algorithm *DeterministicSign* is specified below.
It has two optional arguments: *aux_rand*, which can be omitted if randomness is entirely unavailable, and *aggothernonce*, which is omitted by a sole signer (*u = 1*) who has no other signers' nonces to aggregate.
When present, *aggothernonce* should be set to the output of *NonceAgg* run on the *pubnonce* value of **all** other signers (but can be provided by an untrusted party).
Hence, using *DeterministicSign* is only possible for the last signer to generate a nonce, or for a sole signer who is the only participant signing, and it makes the signer stateless, similar to the stateless signer described in the [Nonce Generation](#nonce-generation) section.
In FROST, the deterministic nonce must also bind to the signer set *id<sub>1..u</sub>*; otherwise a malicious coordinator can recover the victim's secret share via replayed sessions with varying signer sets.[^det-signer-set]

#### Deterministic and Stateless Signing for a Single Signer

Algorithm *DeterministicSign(secshare, my_id, aggothernonce, signers_ctx, m, aux_rand)*:

- Inputs:
  - The participant secret share *secshare*: a 32-byte array, serialized scalar
  - The participant identifier *my_id*: an integer with *0 ≤ my_id ≤ n-1*
  - The aggregate public nonce *aggothernonce* (see [above](#modifications-to-nonce-generation)): a 64-byte array, output of *NonceAgg* (optional argument)[^det-threshold-one]
  - The *signers_ctx*: a [Signers Context](#signers-context) data structure
  - The message *m*: a byte array[^max-msg-len]
  - The auxiliary randomness *aux_rand*: a 32-byte array (optional argument)
- If the optional argument *aux_rand* is present:
  - Let *secshare' = xor_bytes(secshare, hash<sub>FROST3-ed25519-v1/aux</sub>(aux_rand)\[0:32])*[^sk-xor-rand]
- Else:
  - Let *secshare' = secshare*
- *ValidateSignersCtx(signers_ctx)*; fail if that fails
- Let *(_, _, id<sub>1..u</sub>, _, thresh_pk) = signers_ctx*
- If the optional argument *aggothernonce* is present:
  - Let *aggothernonce' = aggothernonce*
- Else:
  - Let *aggothernonce' = empty_bytestring*
- Let *k<sub>i</sub> = scalar_from_bytes_wide(hash<sub>FROST3-ed25519-v1/deterministic/nonce</sub>(secshare' || bytes(4, my_id) || bytes(4, u) || SerializeIds(id<sub>1..u</sub>) || aggothernonce' || thresh_pk || bytes(8, len(m)) || m || bytes(1, i - 1)))* for *i = 1,2*
- Fail if *k<sub>1</sub> = Scalar(0)* or *k<sub>2</sub> = Scalar(0)*[^negligible-zero-scalar]
- Let *R<sub>\*,1</sub> = k<sub>1</sub> &middot; B, R<sub>\*,2</sub> = k<sub>2</sub> &middot; B*
- Let *pubnonce = bytes(R<sub>\*,1</sub>) || bytes(R<sub>\*,2</sub>)*
- Let *secnonce = scalar_to_bytes(k<sub>1</sub>) || scalar_to_bytes(k<sub>2</sub>)*
- If the optional argument *aggothernonce* is present:
  - Let *aggnonce = NonceAgg((pubnonce, aggothernonce))*; fail if that fails and blame coordinator for invalid *aggothernonce*.
- Else:
  - Let *aggnonce = pubnonce*
- Let *session_ctx = (signers_ctx, aggnonce, m)*
- Return *(pubnonce, Sign(secnonce, secshare, my_id, session_ctx))*

[^det-signer-set]: Without binding to the signer set, a malicious coordinator can replay the same *aggothernonce* to the last signer across three sessions while varying *id<sub>1..u</sub>*. The victim produces byte-identical secret nonces *(k<sub>1</sub>, k<sub>2</sub>)* across sessions, but because the Lagrange interpolating coefficient *&lambda;* and nonce coefficient *b* depend on the signer set, the three partial signatures form a system of three linear equations in *(k<sub>1</sub>, k<sub>2</sub>, d)* where *d* is the victim's secret share, enough to recover *d* by solving the system. This consideration does not apply to MuSig2's *DeterministicSign* because MuSig2 is always *n*-of-*n* and the signer set is fixed by the protocol.

[^det-threshold-one]: The threshold *t = 1* is a special case. In a *1-of-n* setup, every participant's *secret share* equals the *threshold secret key* itself, so any single participant can produce a signature alone (*u = 1*). The lone signer calls *DeterministicSign* without the *aggothernonce* argument, which makes the derived nonce fully deterministic, just as in ordinary single-signer Ed25519 signing ([RFC 8032][rfc8032]). The signer may instead run *Sign*, but that path still draws fresh randomness through *NonceGen*. Simplest of all, because a *1-of-n* group is effectively one secret key held by everyone, the participant can skip the FROST algorithms and sign with the ordinary Schnorr signing algorithm[^t-edge-cases].

### Dealing with the Identity Element in Nonce Aggregation

If the coordinator provides *aggnonce = bytes_ext(identity) || bytes_ext(identity)*, either the coordinator is dishonest or there is at least one dishonest signer (except with negligible probability).
If signing aborted in this case, it would be impossible to determine who is dishonest.
Therefore, signing continues so that the culprit is revealed when collecting and verifying partial signatures.

However, the final nonce *R* of an Ed25519 signature produced by this protocol cannot be the identity element.
While the identity is encodable on Ed25519, the verification procedure specified in [Signature Verification](#signature-verification) rejects any signature whose *R* is not a non-identity point of the prime-order subgroup, so a signature with *R* equal to the identity could never verify.
If we would nonetheless allow the final nonce to be the identity element, then the scheme would lose the following property:
if *PartialSigVerify* succeeds for all partial signatures, then *PartialSigAgg* will return a valid Ed25519 signature.
Since this is a valuable feature, we modify [FROST3 signing][roast] to avoid producing an invalid Ed25519 signature while still allowing detection of the dishonest signer: In *GetSessionValues*, if the final nonce *R* would be the identity element, set it to the base point *B* instead (an arbitrary choice).

This modification to *GetSessionValues* does not affect the unforgeability of the scheme.
Given a successful adversary against the unforgeability game (EUF-CMA) for the modified scheme, a reduction can win the unforgeability game for the original scheme by simulating the modification towards the adversary:
When the adversary provides *aggnonce' = bytes_ext(identity) || bytes_ext(identity)*, the reduction sets *aggnonce = bytes(B) || bytes_ext(identity)*.
For any other *aggnonce'*, the reduction sets *aggnonce = aggnonce'*.
(The case that the adversary provides an *aggnonce' ≠ bytes_ext(identity) || bytes_ext(identity)* but nevertheless *R'* in *GetSessionValues* is the identity element happens only with negligible probability.)

<!-- References -->
[rfc8032]: https://www.rfc-editor.org/rfc/rfc8032.html
[rfc9591]: https://www.rfc-editor.org/rfc/rfc9591.html
[chilldkg]: https://github.com/mllwchrry/bip-frost-dkg
[bip327]: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
[bip-frost-signing-secp]: https://github.com/siv2r/bip-frost-signing
[musig]: https://eprint.iacr.org/2018/068
[frost1]: https://eprint.iacr.org/2020/852
[frost2]: https://eprint.iacr.org/2021/1375
[stronger-security-frost]: https://eprint.iacr.org/2022/833
[olaf]: https://eprint.iacr.org/2023/899
[roast]: https://eprint.iacr.org/2022/550
