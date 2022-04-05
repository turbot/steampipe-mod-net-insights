---
repository: "https://github.com/turbot/steampipe-mod-net-insights"
---

# Net Insights Mod

Run individual configuration, compliance and security controls or full compliance benchmarks to validate security best practices based on DNS and website response headers.

## Overview

Dashboards can help answer questions like:

- What are the name server records returned by the parent server?
- Are all the name server listed in parent responding?
- Are all IPs of name servers public?
- What is the SOA record for your domain?
- Are there any MX records contains IP in the host name?

Dashboards are available for 15+ checks based on DNS records, i.e NS, SOA, and MX!

## References

The Net plugin is a set of utility tables for steampipe to query attributes of X.509 certificates associated with websites, DNS records and connectivity to specific network socket addresses.

[Steampipe](https://steampipe.io) is an open source CLI to instantly query cloud APIs using SQL.

[Steampipe Mods](https://steampipe.io/docs/reference/mod-resources#mod) are collections of `named queries`, codified `controls` that can be used to test current configuration of your cloud resources against a desired configuration, and `dashboards` that organize and display key pieces of information.

## Documentation

- **[Benchmarks and controls →](https://hub.steampipe.io/mods/turbot/net_insights/controls)**
- **[Named queries →](https://hub.steampipe.io/mods/turbot/net_insights/queries)**

## Get started

Install the Net plugin with [Steampipe](https://steampipe.io):

```shell
steampipe plugin install net
```

Clone:

```sh
git clone https://github.com/turbot/steampipe-mod-net-insights.git
cd steampipe-mod-net-insights
```

Run all benchmarks:

```shell
steampipe check all
```

Run a single benchmark:

```shell
steampipe check benchmark.dns_checks
```

Run a specific control:

```shell
steampipe check control.dns_ns_at_least_two
```

Start your dashboard server to get started:

```shell
steampipe dashboard
```

By default, the dashboard interface will then be launched in a new browser window at `https://localhost:9194`.

From here, you can view all of your dashboards and reports.

### Credentials

No credentials required.

### Configuration

No extra configuration is required.

## Get involved

- Contribute: [GitHub Repo](https://github.com/turbot/steampipe-mod-net-insights)
- Community: [Slack Channel](https://steampipe.io/community/join)
