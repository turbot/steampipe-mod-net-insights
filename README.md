# Net Insights

20+ checks covering industry defined security best practices based on DNS and website response headers.

![image](https://raw.githubusercontent.com/turbot/steampipe-mod-net-insights/initial-dashboard-compliance/docs/images/net_security_headers_report.png)

## Quick start

1) Download and install Steampipe (https://steampipe.io/downloads). Or use Brew:

```shell
brew tap turbot/tap
brew install steampipe

steampipe -v
steampipe version 0.13.3
```

2) Install the Net plugin

```shell
steampipe plugin install net
```

3) Clone this repo

```sh
git clone https://github.com/turbot/steampipe-mod-net-insights.git
cd steampipe-mod-net-insights
```

4) Run all benchmarks:

```shell
steampipe check all
```

### Other things to checkout

Run an individual benchmark:

```shell
steampipe check benchmark.dns_checks
```

Use Steampipe introspection to view all current controls:

```sh
steampipe query "select resource_name from steampipe_control;"
```

Run a specific control:

```shell
steampipe check control.dns_ns_name_valid
```

## Contributing

If you have an idea for additional compliance controls, or just want to help maintain and extend this mod ([or others](https://github.com/topics/steampipe-mod)) we would love you to join the community and start contributing. (Even if you just want to help with the docs.)

- **[Join our Slack community →](https://steampipe.io/community/join)** and hang out with other Mod developers.
- **[Mod developer guide →](https://steampipe.io/docs/using-steampipe/writing-controls)**

Please see the [contribution guidelines](https://github.com/turbot/steampipe/blob/main/CONTRIBUTING.md) and our [code of conduct](https://github.com/turbot/steampipe/blob/main/CODE_OF_CONDUCT.md). All contributions are subject to the [Apache 2.0 open source license](https://github.com/turbot/steampipe-mod-net-insights/blob/main/LICENSE).

`help wanted` issues:

- [Steampipe](https://github.com/turbot/steampipe/labels/help%20wanted)
- [Net Insights Mod](https://github.com/turbot/steampipe-mod-net-insights/labels/help%20wanted)
