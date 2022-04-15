---
repository: "https://github.com/turbot/steampipe-mod-net-insights"
---

# Net Insights Mod

Run individual configuration, compliance and security controls to validate security best practices for DNS records.

<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-net-insights/initial-dashboard-compliance/docs/images/net_security_headers_report.png" width="50%" type="thumbnail"/>

## References

[Net plugin](https://hub.steampipe.io/plugins/turbot/net) is a set of utility tables for steampipe to query attributes of X.509 certificates associated with websites, DNS records and connectivity to specific network socket addresses.

[Steampipe](https://steampipe.io) is an open source CLI to instantly query cloud APIs using SQL.

[Steampipe Mods](https://steampipe.io/docs/reference/mod-resources#mod) are collections of `named queries`, codified `controls` that can be used to test current configuration of your cloud resources against a desired configuration, and `dashboards` that organize and display key pieces of information.

## Documentation

- **[Benchmarks and controls →](https://hub.steampipe.io/mods/turbot/net_insights/controls)**
- **[Named queries →](https://hub.steampipe.io/mods/turbot/net_insights/queries)**

## Getting started

### Installation

1. Install the Net plugin:

```shell
steampipe plugin install net
```

2. Clone this repo:

```sh
git clone https://github.com/turbot/steampipe-mod-net-insights.git
cd steampipe-mod-net-insights
```

### Usage

#### Running benchmarks

Preview running all benchmarks:

```shell
steampipe check all --dry-run
```

Run all benchmarks:

```shell
steampipe check all
```

Use Steampipe introspection to view all current benchmarks:

```shell
steampipe query "select resource_name, title, description from steampipe_benchmark;"
```

Run an individual benchmark:

```shell
steampipe check benchmark.dns_checks
```

#### Running controls

Use Steampipe introspection to view all current controls:

```shell
steampipe query "select resource_name, title, description from steampipe_control;"
```

Run a specific control:

```shell
steampipe check control.dns_ns_name_valid
```

### Credentials

No credentials required.

### Configuration

Several benchmarks have [input variables](https://steampipe.io/docs/using-steampipe/mod-variables) that can be configured to better match your environment and requirements. Each variable has a default defined in its source file, e.g., `controls/dns.sp`, but these can be overriden in several ways:

- Copy and rename the `steampipe.spvars.example` file to `steampipe.spvars`, and then modify the variable values inside that file
- Pass in a value on the command line:
  ```shell
  steampipe check benchmark.dns_checks --var 'dns_domain_names=["github.com", "amazon.com"]'
  ```
- Set an environment variable:
  ```shell
  SP_VAR_dns_domain_names='["github.com", "amazon.com"]' steampipe check control.dns_ns_name_valid
  ```
  - Note: When using environment variables, if the variable is defined in `steampipe.spvars` or passed in through the command line, either of those will take precedence over the environment variable value. For more information on variable definition precedence, please see the link below.

These are only some of the ways you can set variables. For a full list, please see [Passing Input Variables](https://steampipe.io/docs/using-steampipe/mod-variables#passing-input-variables).

## Get involved

- Contribute: [GitHub Repo](https://github.com/turbot/steampipe-mod-net-insights)
- Community: [Slack Channel](https://steampipe.io/community/join)
