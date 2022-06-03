benchmark "ssl_configuration_best_practices" {
  title         = "SSL/TLS Server Configuration Best Practices"
  description   = "Best practices for your SSL and TLS deployment."
  documentation = file("./controls/docs/ssl/ssl_configuration_overview.md")

  children = [
    control.ssl_certificate_use_complete_certificate_chain,
    control.ssl_certificate_avoid_too_much_security
  ]

  tags = merge(local.ssl_best_practices_common_tags, {
    type = "Benchmark"
  })
}

control "ssl_certificate_use_complete_certificate_chain" {
  title       = "Certificates should have a complete chain of trusted certificates"
  description = "An invalid certificate chain effectively renders the server certificate invalid and results in browser warnings. End-entity SSL/TLS certificates are generally signed by intermediate certificates rather than a CA’s root key. It is recommended to use two or more certificates to build a complete chain of trust."

  sql = <<-EOT
    select
      common_name as resource,
      case
        when chain @> '[{"is_certificate_authority": true}]' then 'ok'
        when jsonb_array_length(chain) >= 2 then 'ok'
        else 'alarm'
      end as status,
      common_name || ' has ' || jsonb_array_length(chain) || ' certificate(s) along with the server certificates.' as reason
    from
      net_certificate
    where
      domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
    order by common_name;
  EOT

  param "dns_domain_names" {
    description = "DNS domain names."
    default     = var.dns_domain_names
  }
}

control "ssl_certificate_avoid_too_much_security" {
  title       = "Avoid implementing too much security"
  description = "Using RSA keys stronger than 2,048 bits and ECDSA keys stronger than 256 bits is a waste of CPU power and might impair user experience."

  sql = <<-EOT
    select
      common_name as resource,
      case
        when (public_key_algorithm = 'RSA' and public_key_length > 2048) then 'alarm'
        when (public_key_algorithm = 'ECDSA' and public_key_length > 256) then 'alarm'
        else 'ok'
      end as status,
      case
        when (
          (public_key_algorithm = 'RSA' and public_key_length > 2048)
          or
          (public_key_algorithm = 'ECDSA' and public_key_length > 256)
        )
        then common_name || ' is using larger keys.'
        else common_name || ' is not using larger keys.'
      end as reason
    from
      net_certificate
    where
      domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
    order by common_name;
  EOT

  param "dns_domain_names" {
    description = "DNS domain names."
    default     = var.dns_domain_names
  }
}
