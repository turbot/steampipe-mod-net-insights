locals {
  ssl_best_practices_common_tags = merge(local.net_insights_common_tags, {
    service = "Net/SSL"
  })
}

benchmark "ssl_best_practices" {
  title         = "SSL/TLS Best Practices"
  description   = "Best practices for your certificates and server configurations."
  documentation = file("./controls/docs/ssl/ssl_overview.md")

  children = [
    benchmark.ssl_certificate_best_practices,
    benchmark.ssl_configuration_best_practices
  ]

  tags = merge(local.ssl_best_practices_common_tags, {
    type = "Benchmark"
  })
}
