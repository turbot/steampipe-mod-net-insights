## Overview

A Start of Authority (SOA) record is a type of resource record in the DNS containing administrative information about the zone, especially regarding zone transfers. An SOA resource record is created at the time of creating a managed zone.

Every domain must have an SOA record at the cutover point where the domain is delegated from its parent. A zone without an SOA record does not conform to the standard required by [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035).

This benchmark contains best practices for SOA records.
