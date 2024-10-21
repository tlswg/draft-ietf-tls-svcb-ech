---
title: Bootstrapping TLS Encrypted ClientHello with DNS Service Bindings
abbrev: ECH in SVCB
docname: draft-ietf-tls-svcb-ech-latest
date: {DATE}
category: std

ipr: trust200902
area: Security
workgroup: TLS Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: B. Schwartz
    name: Ben Schwartz
    organization: Meta Platforms, Inc.
    email: ietf@bemasc.net
 -
    ins: M. Bishop
    name: Mike Bishop
    org: Akamai Technologies
    email: mbishop@evequefou.be
 -
    ins: E. Nygren
    name: Erik Nygren
    org: Akamai Technologies
    email: erik+ietf@nygren.org

--- abstract

To use TLS Encrypted ClientHello (ECH) the client needs to learn the ECH configuration for a server before it attempts a connection to the server.  This specification provides a mechanism for conveying the ECH configuration information via DNS, using a SVCB or HTTPS record.

--- middle

# Overview

The Service Bindings framework {{!SVCB=RFC9460}} allows server operators to publish a detailed description of their service in the Domain Name System (see {{!RFC1034}}, {{?BCP219}}) using SVCB or HTTPS records.  Each SVCB record describes a single "alternative endpoint", and contains a collection of "SvcParams" that can be extended with new kinds of information that may be of interest to a client.  Clients can use the SvcParams to improve the privacy, security, and performance of their connection to this endpoint.

This specification defines a new SvcParam to enable the use of TLS Encrypted ClientHello {{!ECH=I-D.ietf-tls-esni}} in TLS-based protocols.  This SvcParam can be used in SVCB, HTTPS or any future SVCB-compatible DNS records, and is intended to serve as the primary bootstrap mechanism for ECH.

# Terminology

{::boilerplate bcp14-tagged}

# SvcParam for ECH configuration {#ech-param}

The "ech" SvcParamKey is defined for conveying the ECH configuration of an alternative endpoint.  It is applicable to all schemes that use TLS-based protocols (including DTLS {{?RFC9147}} and QUIC version 1 {{?RFC9001}}) unless otherwise specified.

In wire format, the value of the parameter is an ECHConfigList ({{Section 4 of !ECH}}), including the redundant length prefix.  In presentation format, the value is the ECHConfigList in Base 64 Encoding ({{Section 4 of !RFC4648}}).  Base 64 is used here to simplify integration with TLS server software.  To enable simpler parsing, this SvcParam MUST NOT contain escape sequences.

~~~
ech="AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQ
VZWNoLXNpdGVzLmV4YW1wbGUubmV0AAA="
~~~
{: title="ECH SvcParam with a public_name of "ech-sites.example.com""}

# Server behavior

When publishing a record containing an "ech" parameter, the publisher MUST ensure that all IP addresses of TargetName correspond to servers that have access to the corresponding private key or are authoritative for the public name. (See {{Sections 6.1.7 and 8.1.1 of !ECH}} for requirements related to the public name.)  Otherwise, connections will fail entirely.

These servers SHOULD support a protocol version that is compatible with ECH.  At the time of writing, the compatible versions are TLS 1.3, DTLS 1.3, and QUIC version 1.  If the server does not support a compatible version, each connection attempt will have to be retried, delaying the connection and wasting resources.

# Client behavior {#ech-client-behavior}

This section describes client behavior in using ECH configurations provided in SVCB or HTTPS records.

## Disabling fallback

The SVCB-optional client behavior specified in ({{Section 3 of !SVCB}}) permits clients to fall back to a direct connection if all SVCB options fail.  This behavior is not suitable for ECH, because fallback would negate the privacy benefits of ECH.  Accordingly, ECH-capable SVCB-optional clients MUST switch to SVCB-reliant connection establishment if SVCB resolution succeeded (as defined in {{Section 3 of !SVCB}}) and all alternative endpoints have an "ech" SvcParam.

## ClientHello construction

When ECH is in use, the TLS ClientHello is divided into an unencrypted "outer" and an encrypted "inner" ClientHello.  The outer ClientHello is an implementation detail of ECH, and its contents are controlled by the ECHConfig in accordance with {{ECH}}.  The inner ClientHello is used for establishing a connection to the service, so its contents may be influenced by other SVCB parameters.  For example, the requirements related to ALPN protocol identifiers in {{Section 7.1.2 of SVCB}} apply only to the inner ClientHello.  Similarly, it is the inner ClientHello whose Server Name Indication (SNI) identifies the desired service.

## Performance optimizations

Prior to retrieving the SVCB records, the client does not know whether they contain an "ech" parameter.  As a latency optimization, clients MAY prefetch DNS records that will only be used if this parameter is not present (i.e. only in SVCB-optional mode).

The "ech" SvcParam alters the contents of the TLS ClientHello if it is present.  Therefore, clients that support ECH MUST NOT issue any TLS ClientHello until after SVCB resolution has completed.  (See {{Section 5.1 of !SVCB}}).

# Interaction with HTTP Alt-Svc

HTTP clients that implement both HTTP Alt-Svc {{?RFC7838}} and the HTTPS record type {{!SVCB}} can use them together, provided that they only perform connection attempts that are "consistent" with both sets of parameters ({{Section 9.3 of !SVCB}}).  At the time of writing, there is no defined parameter related to ECH for Alt-Svc.  Accordingly, a connection attempt that uses ECH is considered "consistent" with an Alt-Svc Field Value that does not mention ECH.

Origins that publish an "ech" SvcParam in their HTTPS record SHOULD also publish an HTTPS record with the "ech" SvcParam for every alt-authority offered in its Alt-Svc Field Values.  Otherwise, clients might reveal the name of the server in an unencrypted ClientHello to an alt-authority.

If all HTTPS records for an alt-authority contain "ech" SvcParams, the client MUST adopt SVCB-reliant behavior (as in {{disabling-fallback}}) for that RRSet.  This precludes the use of certain connections that Alt-Svc would otherwise allow, as discussed in {{Section 9.3 of !SVCB}}.

# Examples

~~~
$ORIGIN simple.example. ; Simple example zone
@ 300 IN A     192.0.2.1
         AAAA  2001:db8::1
         HTTPS 1 . ech=ABC...
www 300 IN A 192.0.2.1
           AAAA 2001:db8::1
           HTTPS 1 . ech=ABC...
~~~
{: title="Simple example zone with the same configuration on the apex and web domain.  It is compatible with clients that do or do not support HTTPS records."}

~~~
$ORIGIN heterogeneous.example. ; Example zone with two pools of servers
pool1 300 IN    A    192.0.2.1
                AAAA 2001:db8:1::a
pool2 300 IN    A    192.0.2.2
                AAAA 2001:db8:2::a
service 300 IN SVCB 1 pool1 ech=ABC...
               SVCB 1 pool2 ech=DEF...
               A 192.0.2.1
               A 192.0.2.2
               AAAA 2001:db8:1::a
               AAAA 2001:db8:2::a
~~~
{: title="Service that allows clients to choose between two server pools with different ECH configurations."}

~~~
$ORIGIN cdn.example. ; CDN operator zone
pool 300 IN A 192.0.2.1
            AAAA 2001:db8::1
            HTTPS 1 . ech=ABC...

$ORIGIN customer.example. ; CDN customer's zone
@   3600 IN HTTPS 0 pool.cdn.example.
; Apex IP records for compatibility with clients that do not support
; HTTPS records.
@   300  IN A    192.0.2.1
            AAAA 2001:db8::1

www 300  IN CNAME pool.cdn.example.
~~~
{: title="ECH usage pattern for an aliasing-based CDN."}

~~~
$ORIGIN secret.example. ; High confidentiality zone
www     3600 IN HTTPS 1 backend ech=ABC... mandatory=ech
backend 300  IN A     192.0.2.1
                AAAA  2001:db8::1
~~~
{: title="A domain that is only reachable using ECH."}

~~~
$ORIGIN cdn1.example. ; First CDN operator zone
pool 300 IN A     192.0.2.1
            AAAA  2001:db8::1
            HTTPS 1 . ech=ABC...

$ORIGIN cdn2.example. ; Second CDN operator zone
pool 300 IN A     192.0.2.2
            AAAA  2001:db8::2
            HTTPS 1 . ech=DEF...

;; Multi-CDN customer zone (version 1)
$ORIGIN customer.example.
@   3600 IN HTTPS 0 pool.cdn1.example.
; Apex IP records for compatibility with clients that do not support
; HTTPS records.
@   300  IN A    192.0.2.1
            AAAA 2001:db8::1
www 3600  IN CNAME pool.cdn1.example.

;; Multi-CDN customer zone (version 2)
@   3600 IN HTTPS 0 pool.cdn2.example.
@   300  IN A    192.0.2.2
            AAAA 2001:db8::2
www 3600  IN CNAME pool.cdn2.example.
~~~
{: title="Multi-CDN configuration using server-side selection."}

~~~
$ORIGIN dns.example. ; DNS server example.
@    3600 IN A     192.0.2.1
             AAAA  2001:db8::1
             HTTPS 1 . ech=ABC... alpn=h3 dohpath=/q{?dns}

_dns 3600 IN SVCB  1 @ ech=ABC... alpn=dot,doq,h3 dohpath=/q{?dns}
~~~
{: title="Example of a DNS server that supports ECH."}

# Security Considerations

A SVCB RRSet containing some RRs with "ech" and some without is vulnerable to a downgrade attack: a network intermediary can block connections to the endpoints that support ECH, causing the client to fall back to a non-ECH endpoint.  This configuration is NOT RECOMMENDED. Zone owners who do use such a mixed configuration SHOULD mark the RRs with "ech" as more preferred (i.e. lower SvcPriority value) than those without, in order to maximize the likelihood that ECH will be used in the absence of an active adversary.

In an idealized deployment, ECH protects the SNI with an anonymity set consisting of all the ECH-enabled server domains supported by a given client-facing server. Accordingly, an attacker who can enumerate this set can always guess the encrypted SNI with probability 1/K, where K is the number of domains in the set. In practice, this probability may be increased via traffic analysis, popularity weighting, and other mechanisms.

ECH ensures that TLS does not disclose the SNI, but the same information is also present in the DNS queries used to resolve the server's hostname.  This specification does not conceal the server name from the DNS resolver.  If DNS messages are sent between the client and resolver without authenticated encryption, an attacker on this path can also learn the destination server name.  A similar attack applies if the client can be linked to a request from the resolver to a DNS authority.

An attacker who can prevent SVCB resolution can deny clients any associated security benefits. A hostile recursive resolver can always deny service to SVCB queries, but network intermediaries can often prevent resolution as well, even when the client and recursive resolver validate DNSSEC {{!RFC9364}} and use a secure transport. These downgrade attacks can prevent a client from being aware that "ech" is configured which could result in the client sending the ClientHello in cleartext. To prevent downgrades, {{Section 3.1 of !SVCB}} recommends that clients abandon the connection attempt when such an attack is detected.

# IANA Considerations

IANA is instructed to modify the Service Parameter Keys Registry entry for "ech" as follows:

| Number      | Name            | Meaning                             | Format Reference                         | Change Controller |
| ----------- | ------          | ----------------------              | ---------------------------------------- | ----------------- |
| 5           | ech             | TLS Encrypted ClientHello Config    | (This document)                          | IETF              |
