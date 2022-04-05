## Overview

The Domain Name System (DNS) is a hierarchical distributed database that stores IP addresses and other data and allows queries by name. The types of information elements associated with domain names, are categorized and organized with a list of DNS record types (or resource records), i.e. `A`, `AAAA`, `NS`, `SOA`, `MX` etc. These are most commonly used to map human-friendly domain names to the numerical IP addresses computers need to locate services and devices using the underlying network protocols, but have been extended over time to perform many other functions as well.

Following are the most common DNS record types:

| Type | Description |
| - | - |
| A | Address record, which maps host names to their IPv4 address. It allows you to use memonic names, such as `www.example.com`, in place of IP addresses like `127.0.0.1`. |
| AAAA | IPv6 Address record, which maps host names to their IPv6 address. |
| CNAME | Canonical name record, which specifies alias names. |
| MX | Mail exchange record, which is used in routing requests to mail servers. |
| NS | Name server record, which delegates a DNS zone to an authoritative server. |
| SOA | Start of authority, used to designate the primary name server and administrator responsible for a zone. Each zone hosted on a DNS server must have an SOA record. |
| TXT | This record is used to associate text with a domain. |
