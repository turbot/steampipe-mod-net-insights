## Overview

A Start of Authority (SOA) record is a type of resource record in the DNS containing administrative information about the zone, especially regarding zone transfers. An SOA resource record is created at the time of creating a managed zone.

Every domain must have a SOA record at the cutover point where the domain is delegated from its parent. A zone without a SOA record does not conform to the standard required by [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035).

The compliance performs following checks on SOA record:

- The primary name server for the domain.
- The email address of the responsible person for this zone.
- The serial number for this zone per [RFC1912 2.2](https://datatracker.ietf.org/doc/html/rfc1912#section-2.2).
- The number of seconds after which secondary name servers should query the master for the SOA record, to detect zone changes.
- The number of seconds after which secondary name servers should retry to request the serial number from the master if the master does not respond.
- The number of seconds after which secondary name servers should stop answering request for this zone if the master does not respond.
- The negative result TTL (for example, how long a resolver should consider a negative result for a subdomain to be valid before retrying).
