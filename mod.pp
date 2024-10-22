mod "net_insights" {
  # hub metadata
  title         = "Net Insights"
  description   = "Run individual configuration, compliance and security controls for DNS records using Powerpipe and Steampipe."
  color         = "#005A9C"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/net-insights.svg"
  categories    = ["security"]

  opengraph {
    title        = "Powerpipe Mod for Net Insights"
    description  = "Run individual configuration, compliance and security controls for DNS records using Powerpipe and Steampipe."
    image        = "/images/mods/turbot/net-insights-social-graphic.png"
  }

  require {
    plugin "net" {
      min_version = "0.5.0"
    }
  }
}
