locals {
  ssl_best_practices_common_tags = merge(local.net_insights_common_tags, {
    service = "Net/SSL"
  })
}

benchmark "ssl_best_practices" {
  title       = "SSL/TLS Best Practices"
  description = "Best practices for your certificates."
  documentation = file("./controls/docs/ssl_overview.md")
  
  children = [
    benchmark.ssl_certificate_best_practices,
    benchmark.ssl_configuration_best_practices,
    benchmark.ssl_configuration_vulnerabilities_check,
    # benchmark.ssl_http_and_application_security,
  ]

  tags = merge(local.ssl_best_practices_common_tags, {
    type = "Benchmark"
  })
}
