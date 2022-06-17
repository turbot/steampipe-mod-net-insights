## v0.4 [2022-06-17]

_What's new?_

- New dashboards added:
  - [SSL Certificate Report](https://hub.steampipe.io/mods/turbot/net_insights/dashboards/dashboard.ssl_certificate_report) ([#13](https://github.com/turbot/steampipe-mod-net-insights/pull/13))
  - [SSL/TLS Server Configuration Report](https://hub.steampipe.io/mods/turbot/net_insights/dashboards/dashboard.ssl_configuration_report) ([#13](https://github.com/turbot/steampipe-mod-net-insights/pull/13))
- New controls added:
  - ssl_avoid_using_cbc_cipher_suite ([#13](https://github.com/turbot/steampipe-mod-net-insights/pull/13))

_Breaking changes_

- Updated variable name `dns_domain_names` to `domain_names`. Please update any uses of this variable in `steampipe.spvars`, command line arguments, and environment variables. ([#13](https://github.com/turbot/steampipe-mod-net-insights/pull/13))

## v0.3 [2022-06-09]

_What's new?_

- Added SSL/TLS Certificate Best Practices benchmark (`steampipe check benchmark.ssl_certificate_best_practices`) ([#8](https://github.com/turbot/steampipe-mod-net-insights/pull/8))
- Added SSL/TLS Server Configuration Best Practices benchmark (`steampipe check benchmark.ssl_configuration_best_practices`) ([#10](https://github.com/turbot/steampipe-mod-net-insights/pull/10))

## v0.2 [2022-05-09]

_What's new?_

- New dashboards added:
  - [DNS Records Report](https://hub.steampipe.io/mods/turbot/net_insights/dashboards/dashboard.dns_records_report) ([#5](https://github.com/turbot/steampipe-mod-net-insights/pull/5))

_Enhancements_

- Updated docs/index.md and README with new dashboard screenshots and latest format.

## v0.1 [2022-04-28]

_What's new?_

- Added: DNS Best Practices benchmark (`steampipe check benchmark.dns_best_practices`)
