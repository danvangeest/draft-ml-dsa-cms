---
title: "Use of the ML-DSA Signature Algorithm in the Cryptographic Message Syntax (CMS)"
abbrev: "ML-DSA in CMS"
category: std
stand_alone: true # This lets us do fancy auto-generation of references
ipr: trust200902

docname: draft-vangeest-ml-dsa-cms-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - Dilithium
 - ML-DSA
venue:
#  group: LAMPS
#  type: Working Group
#  mail: spasm@ietf.org
#  arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  github: "danvangeest/draft-ml-dsa-cms"
  # latest: "https://danvangeest.github.io/draft-ml-dsa-cms/draft-vangeest-ml-dsa-cms.html"

author:
 -
    ins: D. Van Geest
    name: Daniel Van Geest
    org: CryptoNext Security
    email: daniel.vangeest.ietf@gmail.com
 -
    ins: M. Prorock
    name: Michael Prorock
    org: mesur.io
    email: mprorock@mesur.io
 -
    ins: M. Ounsworth
    name: Mike Ounsworth
    org: Entrust Limited
    email: mike.ounsworth@entrust.com

normative:
  FIPS204:
      title: TBD
  FIPS204-ipd:
      title: "Module-Lattice-Based Digital Signature Standard"
      date: 2023-08-24
      target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.ipd.pdf
      author:
        org: National Institute of Standards and Technology (NIST)

informative:
  NIST-PQC:
    target: https://csrc.nist.gov/projects/post-quantum-cryptography
    title: Post-Quantum Cryptography Project
    author:
      - org: National Institute of Standards and Technology
    date: 2016-12-20


--- abstract

This document specifies the conventions for using the Module-Lattice-Based Digital Signatures (ML-DSA) algorithm with the Cryptographic Message Syntax (CMS).

--- middle

# Introduction

Module-Lattice-Based Digital Signatures (ML-DSA) is a quantum-resistant digital signature scheme standardized in {{FIPS204}} \[EDNOTE: {{FIPS204-ipd}} until officially published] by the US National Institute of Standards and Technology (NIST) PQC project [NIST-PQC].  This document specifies the conventions for using ML-DSA with the Cryptographic Message Syntax (CMS) {{!RFC5652}} signed-data content type.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## ASN.1

CMS values are generated using ASN.1 {{!X680=CCITT.X680.2002}}, using the Basic Encoding Rules (BER) and the Distinguished Encoding Rules (DER) {{!X690=CCITT.X690.2002}}.

# ML-DSA Signature Algorithm

{{FIPS204}} defines parameter sets for ML-DSA at three security levels: ML-DSA-44, ML-DSA-65, and ML-DSA-87.

Table 3 in {{FIPS204}} gives the targeted security strength for the NIST PQC Project [NIST-PQC]. ML-DSA-44 targets category 2 - at least as hard as a collision search on 256-bit hash function, e.g. SHA3-256 {{?FIPS202}}.  ML-DSA-65 targets category 3 - at least as hard as a key search on block cipher with 192-bit key, e.g. AES-192 {{?FIPS197=FIPS.197.2001}}.  ML-DSA-87 targets category 5 - at least as hard as a key search on block cipher with 256-bit key, e.g. AES-256 {{?FIPS197}}.

## Algorithm Identifiers

Each algorithm is identified by an object identifier, and the algorithm identifier may contain parameters if needed.

The ALGORITHM definition is repeated here for convenience:

~~~
   ALGORITHM ::= CLASS {
       &id    OBJECT IDENTIFIER UNIQUE,
       &Type  OPTIONAL }
     WITH SYNTAX {
       OID &id [PARMS &Type] }
~~~

## ML-DSA Algorithm Identifiers

The ML-DSA signature algorithm is defined in {{FIPS204}}, and the conventions for encoding the public key are defined in {{!I-D.ietf-lamps-dilithium-certificates}}.

The id-ML-DSA-44, id-ML-DSA-65, and id-ML-DSA-87 object identifiers are used to identify ML-DSA public keys in certificates.  The object identifiers are specified in {{!I-D.ietf-lamps-dilithium-certificates}}, and they are repeated here for convenience:

~~~
   id-ML-DSA-44 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
             country(16) us(840) organization(1) gov(101) csor(3)
             nistAlgorithm(4) sigAlgs(3) TBD }

   id-ML-DSA-65 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
             country(16) us(840) organization(1) gov(101) csor(3)
             nistAlgorithm(4) sigAlgs(3) TBD }

   id-ML-DSA-87 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
             country(16) us(840) organization(1) gov(101) csor(3)
             nistAlgorithm(4) sigAlgs(3) TBD }
~~~

## Message Digest Algorithm Identifiers

When the signer includes signed attributes, a message digest algorithm is used to compute the message digest on the eContent value.

ML-DSA uses both SHAKE128 and SHAKE256 {{!FIPS202=NIST.FIPS.202}} internally as part of the signing operation.

When using ML-DSA to sign a message digest, Section 7.1 \[TODO: make sure this doesn't change] of {{FIPS204}} requires that the approved hash function or extendable-output function provides at least λ bits of classical security strength against both collision and second preimage attacks. The values for λ is specified in Table 1 \[TODO: make sure this doesn't change] of {{FIPS204}} and is summarized here in {{ml-dsa-collision-strength}}.

| Algorithm | λ - collision strength |
|--         |---                     |
| ML-DSA-44 | 128                    |
| ML-DSA-65 | 192                    |
| ML-DSA-87 | 256                    |
{: #ml-dsa-collision-strength title="ML-DSA λ - collision strength"}

ML-DSA uses both SHAKE128 and SHAKE256 {{!FIPS202}} internally as part of the signing operation.  Table 4 of {{!FIPS202}} includes the security strength of SHAKE128 and SHAKE256 and the relevant parts are summarized here in {{shake-strength}}.

| Function | Output Size | Collision Strength | 2nd Preimage Strength |
|--        |---          |---                 |---                    |
| SHAKE128 | d           | min(d/2, 128)      | min(d, 128)           |
| SHAKE256 | d           | min(d/2, 256)      | min(d, 256)           |
{: #shake-strength title="SHAKE security strength"}

When signing with ML-DSA-44, the message digest algorithm MUST be SHAKE128.  When signing with ML-DSA-65, the message digest algorithm MUST be SHAKE256.  When signing with ML-DSA-87, the message digest algorithm MUST be SHAKE256.  To avoid complexity in algorithm identifier encodings, the message digest algorithm used for ML-DSA-65 is stronger than strictly necessary.

{{!RFC8702}} defines the use of SHAKE128 and SHAKE258 in CMS.  The object identifiers are reproduced here for convenience:

~~~
   id-shake128 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
             country(16) us(840) organization(1) gov(101) csor(3)
             nistAlgorithm(4) 2 11 }

   id-shake256 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
             country(16) us(840) organization(1) gov(101) csor(3)
             nistAlgorithm(4) 2 12 }
~~~

As described in {{!RFC8702}}, when using the id-shake128 or id-shake256 algorithm identifier, the OID encoding MUST omit the parameters field and the output length of SHAKE128 or SHAKE256 as the message digest MUST be 32 or 64 bytes, respectively.

## ML-DSA Signatures

The id-ML-DSA-44, id-ML-DSA-65, and id-ML-DSA-87 object identifiers are also used for signature values.  When used to identify signature algorithms, the AlgorithmIdentifier parameters field MUST be absent.

The data to be signed is processed using ML-DSA, and then a private key operation generates the signature value.  As described in Algorithm 20 \[TODO: make sure this doesn't change] of {{FIPS204}}, the sigEncode() algorithm encodes the signature into an opaque byte string. As described in Section 5.3 of {{!RFC5652}}, the signature value is ASN.1 encoded as an OCTET STRING and included in the signature field of SignerInfo.

# Signed Data Conventions

<!-- This section borrows heavily from Section 4 of draft-ietf-lamps-cms-sphincs-plus-03 -->

The processing depends on whether the signer includes signed attributes.

The inclusion of signed attributes is preferred, but the conventions for signed-data without signed attributes are provided for completeness.

## Signed-data Conventions with Signed Attributes

\[ EDNOTE: I based this section and the next on 3.1 and 3.2 from RFC 8419.  Should it instead be based on section 4 from draft-ietf-lamps-cms-sphincs-plus? ]

The SignedData digestAlgorithms field includes the identifiers of the message digest algorithms used by one or more signer.  There MAY be any number of elements in the collection, including zero.  When signing with ML-DSA-44, the digestAlgorithm SHOULD include id-shake128.  When signing with ML-DSA-65 or ML-DSA-87, the digestAlgorithm SHOULD include id-shake256.  In all cases the algorithm parameters field MUST be absent.

The SignerInfo digestAlgorithm field includes the identifier of the message digest algorithms used by the signer.  When signing with
ML-DSA-44, the digestAlgorithm MUST be id-shake128.  When signing with ML-DSA-65 or ML-DSA-87, the digestAlgorithm MUST be id-shake256.  In all cases the algorithm parameters field MUST be absent.

The SignerInfo signedAttributes MUST include the message-digest attribute as specified in Section 11.2 of {{!RFC5652}}.  When signing with ML-DSA-44, the message-digest attribute MUST contain the message digest computed over the eContent value using SHAKE128 with 32 bytes of output.  When signing with ML-DSA-65 or ML-DSA-87, the message-digest attribute MUST contain the message digest computed over the eContent value using SHAKE256 with 64 bytes of output.

The SignerInfo signatureAlgorithm field MUST contain either id-ML-DSA-44, id-ML-DSA-65, or id-ML-DSA-87, depending on the ML-DSA parameter set that was used by the signer.  The algorithm parameters field MUST be absent.

The SignerInfo signature field contains the octet string resulting from the ML-DSA private key signing operation.

## Signed-data Conventions without Signed Attributes

The SignedData digestAlgorithms field includes the identifiers of the message digest algorithms used by one or more signer.  There MAY be any number of elements in the collection, including zero.  When signing with ML-DSA-44, the list of identifiers MAY include id-shake128, and if present, the algorithm parameters field MUST be absent.  When signing with ML-DSA-65 or ML-DSA-87, the list of identifiers MAY include id-shake256, and if present, the algorithm parameters field MUST be absent.

The SignerInfo digestAlgorithm field includes the identifier of the message digest algorithms used by the signer.  When signing with ML-DSA-44, the digestAlgorithm MUST be id-shake128.  When signing with ML-DSA-65 or ML-DSA-87, the digestAlgorithm MUST be id-shake256.  In all cases the algorithm parameters field MUST be absent.

      NOTE: Either id-sha512 or id-shake256 is used as part to the
      private key signing operation.  However, the private key signing
      operation does not take a message digest computed with one of
      these algorithms as an input.

The SignerInfo signatureAlgorithm field MUST contain either id-ML-DSA-44, id-ML-DSA-65, or id-ML-DSA-87, depending on the ML-DSA parameter set that was used by the signer.  The algorithm parameters field MUST be absent.

The SignerInfo signature field contains the octet string resulting from the ML-DSA private key signing operation.

# Security Considerations

The Security Considerations section of {{!RFC5652}} applies to this specification as well.

ML-DSA is specified for use in Public Key Infrastructure X.509 (PKIX) certificates and Certificate Revocation Lists (CRLs) in {{!I-D.ietf-lamps-dilithium-certificates}}.  The Security Considerations section from there apply to this specification as well.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

Much of the structure and text of this document is based on {{?RFC8419}}.  Thanks to Russ Housley, author of that document, for making our work earier. "Copying always makes things easier and less error prone" - {{?RFC8411}}.

TODO: Hopefully others will help out.  They will be acknowledged here.  And if you've read this far...

<!--

\[ EDNOTE: This is all commented out text that I wrote elsewhere in this draft but was never published.  What is currently written is simpler, but I'm keeping the text around in case it needs to be added back. ]

# Removed Text
{:numbered="false"}

## From: Message Digest Algorithm Identifiers
{:numbered="false"}

When signing with ML-DSA, the message digest algorithm and output size MUST correspond to the values in {{message-digests}}.

| Parameter Set | Digest Algorithm | Output Size (bits) |
|-              |-                 |-                   |
| ML-DSA-44     | SHAKE128         | 256                |
| ML-DSA-65     | SHAKE256         | 384                |
| ML-DSA-87     | SHAKE256         | 512                |
{: #message-digests title="Required Message Digests and Lengths"}

Explicitly, when using the ML-DSA algorithm identifiers, the digest object identifiers and algorithm identifier parameters specified in {{message-digests-oids}} MUST be used.

| ML-DSA OID   | Digest OID      | Digest Alg Identifier Parameters |
|-             |-                |-                                 |
| id-ML-DSA-44 | id-shake128     | absent                           |
| id-ML-DSA-65 | id-shake256-len | 384                              |
| id-ML-DSA-87 | id-shake256     | absent                           |
{: #message-digests-oids title="Required Message Digest Algorithm Identifiers"}

\[ EDNOTE: add a normative reference for these OIDs. ]

\[ EDNOTE: for convenience, repeat the object identifiers and parameter syntax. ]

\[ EDNOTE: This mixing of digest algorithm identifiers with and without length parameters is not great.  And specifying all the IDs with length parameters is also not great.  Can we just overshoot on the digest security for ML-DSA-65 and specify ML-DSA-44:id-shake128, ML-DSA-65:id-shake256, and ML-DSA-87:id-shake256? ]


\[ EDNOTE: end of commented out text]

-->
