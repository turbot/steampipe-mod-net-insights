## v1.0.1 [2024-10-24]

_Bug fixes_

- Renamed `steampipe.spvars.example` files to `powerpipe.ppvars.example` and updated documentation. 

## v1.0.0 [2024-10-22]

This mod now requires [Powerpipe](https://powerpipe.io). [Steampipe](https://steampipe.io) users should check the [migration guide](https://powerpipe.io/blog/migrating-from-steampipe).

## v0.7 [2024-04-06]

_Powerpipe_

[Powerpipe](https://powerpipe.io) is now the preferred way to run this mod!  [Migrating from Steampipe →](https://powerpipe.io/blog/migrating-from-steampipe)

All v0.x versions of this mod will work in both Steampipe and Powerpipe, but v1.0.0 onwards will be in Powerpipe format only.

_Enhancements_

- Focus documentation on Powerpipe commands.
- Show how to combine Powerpipe mods with Steampipe plugins.

## v0.6 [2023-11-03]

_Breaking changes_

- Updated the plugin dependency section of the mod to use `min_version` instead of `version`. ([#28](https://github.com/turbot/steampipe-mod-net-insights/pull/28))

_Enhancements_

- Added the `dns_mx_dmarc_record_enabled` control to the `dns_mx_best_practices` benchmark. ([#20](https://github.com/turbot/steampipe-mod-net-insights/pull/20))

_Bug fixes_

- Fixed dashboard localhost URLs in README and index doc. ([#23](https://github.com/turbot/steampipe-mod-net-insights/pull/23))

## v0.5 [2022-06-24]

_What's new?_

- New dashboards added:
  - [Security Headers Report](https://hub.steampipe.io/mods/turbot/net_insights/dashboards/dashboard.security_headers_report) ([#15](https://github.com/turbot/steampipe-mod-net-insights/pull/15))
- Added Security Headers Best Practices benchmark (`steampipe check benchmark.security_headers_best_practices`). ([#15](https://github.com/turbot/steampipe-mod-net-insights/pull/15))

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
