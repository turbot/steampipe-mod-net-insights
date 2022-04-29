# Net Insights

20+ checks covering security best practices for DNS records.

![image](https://raw.githubusercontent.com/turbot/steampipe-mod-net-insights/main/docs/images/net_dns_best_practices_output.png)

## Getting started

### Installation

1. Download and install Steampipe (https://steampipe.io/downloads). Or use Brew:

```shell
brew tap turbot/tap
brew install steampipe

steampipe -v
steampipe version 0.13.6
```

2. Install the Net plugin:

```shell
steampipe plugin install net
```

3. Clone this repo:

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
steampipe check benchmark.dns_best_practices
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

### Configuration

Several benchmarks have [input variables](https://steampipe.io/docs/using-steampipe/mod-variables) that can be configured to better match your environment and requirements. Each variable has a default defined in its source file, e.g., `controls/dns.sp`, but these can be overridden in several ways:

- Copy and rename the `steampipe.spvars.example` file to `steampipe.spvars`, and then modify the variable values inside that file
- Pass in a value on the command line:

  ```shell
  steampipe check benchmark.dns_best_practices --var 'dns_domain_names=["github.com", "amazon.com"]'
  ```

- Set an environment variable:

  ```shell
  SP_VAR_dns_domain_names='["github.com", "amazon.com"]' steampipe check control.dns_ns_name_valid
  ```

  - Note: When using environment variables, if the variable is defined in `steampipe.spvars` or passed in through the command line, either of those will take precedence over the environment variable value. For more information on variable definition precedence, please see the link below.

These are only some of the ways you can set variables. For a full list, please see [Passing Input Variables](https://steampipe.io/docs/using-steampipe/mod-variables#passing-input-variables).

## Contributing

If you have an idea for additional compliance controls, or just want to help maintain and extend this mod ([or others](https://github.com/topics/steampipe-mod)) we would love you to join the community and start contributing. (Even if you just want to help with the docs.)

- **[Join our Slack community →](https://steampipe.io/community/join)** and hang out with other Mod developers.
- **[Mod developer guide →](https://steampipe.io/docs/using-steampipe/writing-controls)**

Please see the [contribution guidelines](https://github.com/turbot/steampipe/blob/main/CONTRIBUTING.md) and our [code of conduct](https://github.com/turbot/steampipe/blob/main/CODE_OF_CONDUCT.md). All contributions are subject to the [Apache 2.0 open source license](https://github.com/turbot/steampipe-mod-net-insights/blob/main/LICENSE).

`help wanted` issues:

- [Steampipe](https://github.com/turbot/steampipe/labels/help%20wanted)
- [Net Insights Mod](https://github.com/turbot/steampipe-mod-net-insights/labels/help%20wanted)
