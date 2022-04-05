mod "net_compliance" {
  # hub metadata
  title         = "Net Compliance"
  description   = "Run individual configuration, compliance and security controls or full compliance benchmarks for DNS records and connectivity to specific network socket addresses."
  color         = "#005A9C"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/net-compliance.svg"
  categories    = ["security"]

  opengraph {
    title        = "Steampipe Mod for Net Compliance"
    description  = "Run individual configuration, compliance and security controls or full compliance benchmarks for DNS records and connectivity to specific network socket addresses."
    image        = "/images/mods/turbot/net-compliance-social-graphic.png"
  }
}