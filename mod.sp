// Benchmarks and controls for specific services should override the "service" tag
locals {
  net_insights_common_tags = {
    category = "Compliance"
    plugin   = "net"
    service  = "Net"
  }
}

variable "domain_names" {
  type        = list(string)
  description = "A list of domain names to run DNS checks for. Each domain name should not contain http:// or https://."
  default     = [ "github.com", "microsoft.com" ]
}

variable "addresses" {
  type        = list(string)
  description = "A list of addresses to run SSL checks for. Each address should not contain http:// or https:// and must include a port number."
  default     = [ "github.com:443", "microsoft.com:443" ]
}

variable "website_urls" {
  type        = list(string)
  description = "Website URLs to run HTTP checks for. Each URL must contain http:// or https://."
  default     = [ "https://github.com", "https://microsoft.com" ]
}

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
      version = "0.5.0"
    }
  }
}
