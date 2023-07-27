---
repository: "https://github.com/turbot/steampipe-mod-net-insights"
---

# Net Insights Mod

Run individual configuration, compliance and security controls to validate security best practices for DNS records.

<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-net-insights/main/docs/images/net_dashboard.png" width="50%" type="thumbnail"/>
<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-net-insights/main/docs/images/net_dns_records_report.png" width="50%" type="thumbnail"/>
<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-net-insights/main/docs/images/net_dns_best_practices_dashboard.png" width="50%" type="thumbnail"/>
<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-net-insights/main/docs/images/net_dns_best_practices_output.png" width="50%" type="thumbnail"/>

## References

[Net plugin](https://hub.steampipe.io/plugins/turbot/net) is a set of utility tables for steampipe to query attributes of X.509 certificates associated with websites, DNS records and connectivity to specific network socket addresses.

[Steampipe](https://steampipe.io) is an open source CLI to instantly query cloud APIs using SQL.

[Steampipe Mods](https://steampipe.io/docs/reference/mod-resources#mod) are collections of `named queries`, codified `controls` that can be used to test current configuration of your cloud resources against a desired configuration, and `dashboards` that organize and display key pieces of information.

## Documentation

- **[Benchmarks and controls →](https://hub.steampipe.io/mods/turbot/net_insights/controls)**
- **[Dashboards →](https://hub.steampipe.io/mods/turbot/net_insights/dashboards)**

## Getting started

### Installation

Download and install Steampipe (https://steampipe.io/downloads). Or use Brew:

```sh
brew tap turbot/tap
brew install steampipe
```

Install the Net plugin with [Steampipe](https://steampipe.io):

```sh
steampipe plugin install net
```

Clone:

```sh
git clone https://github.com/turbot/steampipe-mod-net-insights.git
cd steampipe-mod-net-insights
```

### Usage

Start your dashboard server to get started:

```sh
steampipe dashboard
```

By default, the dashboard interface will then be launched in a new browser
window at https://localhost:9194. From here, you can view dashboards and
reports, and run benchmarks by selecting one or searching for a specific one.

Instead of running benchmarks in a dashboard, you can also run them within your
terminal with the `steampipe check` command:

Run all benchmarks:

```sh
steampipe check all
```

Run a single benchmark:

```sh
steampipe check benchmark.dns_best_practices
```

Run a specific control:

```sh
steampipe check control.dns_ns_name_valid
```

Different output formats are also available, for more information please see
[Output Formats](https://steampipe.io/docs/reference/cli/check#output-formats).

### Credentials

No credentials are required.

### Configuration

Several benchmarks have [input variables](https://steampipe.io/docs/using-steampipe/mod-variables) that can be configured to better match your environment and requirements. Each variable has a default defined in its source file, e.g., `controls/dns.sp`, but these can be overridden in several ways:

- Copy and rename the `steampipe.spvars.example` file to `steampipe.spvars`, and then modify the variable values inside that file
- Pass in a value on the command line:

  ```shell
  steampipe check benchmark.dns_best_practices --var 'domain_names=["github.com", "amazon.com"]'
  ```

- Set an environment variable:

  ```shell
  SP_VAR_domain_names='["github.com", "amazon.com"]' steampipe check control.dns_ns_name_valid
  ```

  - Note: When using environment variables, if the variable is defined in `steampipe.spvars` or passed in through the command line, either of those will take precedence over the environment variable value. For more information on variable definition precedence, please see the link below.

These are only some of the ways you can set variables. For a full list, please see [Passing Input Variables](https://steampipe.io/docs/using-steampipe/mod-variables#passing-input-variables).

## Contributing

If you have an idea for additional dashboards or controls, or just want to help maintain and extend this mod ([or others](https://github.com/topics/steampipe-mod)) we would love you to join the community and start contributing.

- **[Join #steampipe on Slack → →](https://turbot.com/community/join)** and hang out with other Mod developers.

Please see the [contribution guidelines](https://github.com/turbot/steampipe/blob/main/CONTRIBUTING.md) and our [code of conduct](https://github.com/turbot/steampipe/blob/main/CODE_OF_CONDUCT.md). All contributions are subject to the [Apache 2.0 open source license](https://github.com/turbot/steampipe-mod-net-insights/blob/main/LICENSE).

Want to help but not sure where to start? Pick up one of the `help wanted` issues:

- [Steampipe](https://github.com/turbot/steampipe/labels/help%20wanted)
- [Net Insights Mod](https://github.com/turbot/steampipe-mod-net-insights/labels/help%20wanted)
