variable "domain_names" {
  type        = list(string)
  description = "A list of domain names to run DNS and SSL checks for. Each domain name should not contain http:// or https://."
  default     = [ "github.com", "microsoft.com" ]
}

variable "website_urls" {
  type        = list(string)
  description = "Website URLs to run HTTP checks for. Each URL must contain http:// or https://."
  default     = [ "https://github.com", "https://microsoft.com" ]
}
