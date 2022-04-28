mod "net_insights" {
  # hub metadata
  title         = "Net Insights"
  description   = "Run individual configuration, compliance and security controls for DNS records."
  color         = "#005A9C"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/net-insights.svg"
  categories    = ["security"]

  opengraph {
    title        = "Steampipe Mod for Net Insights"
    description  = "Run individual configuration, compliance and security controls for DNS records."
    image        = "/images/mods/turbot/net-insights-social-graphic.png"
  }

  require {
    plugin "net" {
      version = "0.3.0"
    }
  }
}
