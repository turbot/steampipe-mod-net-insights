locals {
  ssl_best_practices_common_tags = merge(local.net_insights_common_tags, {
    service = "Net/SSL"
  })
}

benchmark "ssl_best_practices" {
  title       = "SSL Best Practices"
  description = "Best practices for your certificates."
  #documentation = file("./controls/docs/ssl_overview.md")
  
  children = [
    control.ssl_certificate_valid,
    control.ssl_certificate_not_expired,
    control.ssl_certificate_not_self_signed,
    control.ssl_certificate_not_revoked,
    control.ssl_certificate_no_insecure_signature,
    control.ssl_certificate_secure_private_key,
    control.ssl_certificate_multiple_hostname,
    control.ssl_certificate_use_complete_certificate_chain,
    control.ssl_certificate_use_secure_protocol,
    control.ssl_certificate_use_secure_cipher_suite,
    control.ssl_certificate_use_strong_key_exchange
  ]

  tags = merge(local.ssl_best_practices_common_tags, {
    type = "Benchmark"
  })
}

# TODO: Control descriptions, docs
control "ssl_certificate_valid" {
  title       = "SSL certificate should be valid"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when now() < not_before then 'alarm'
        else 'ok'
      end as status,
      case
        when now() < not_before then common_name || ' is not yet valid.'
        else common_name || ' is valid.'
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

control "ssl_certificate_not_expired" {
  title       = "SSL certificate should not be expired"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when now() > not_after then 'alarm'
        else 'ok'
      end as status,
      case
        when now() > not_after then common_name || ' is expired.'
        else common_name || ' is yet to expire in ' || date_trunc('day', age(not_after, now())) || '.'
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

control "ssl_certificate_not_self_signed" {
  title       = "SSL certificate should not be self signed"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when common_name = issuer_name then 'alarm'
        else 'ok'
      end as status,
      case
        when common_name = issuer_name then common_name || ' is self-signed.'
        else common_name || ' is not self-signed.'
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

control "ssl_certificate_not_revoked" {
  title       = "SSL certificate should not be a revoked certificate"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when is_revoked then 'alarm'
        else 'ok'
      end as status,
      case
        when is_revoked then common_name || ' certificate was revoked.'
        else common_name || ' is not using any revoked certificate.'
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

control "ssl_certificate_no_insecure_signature" {
  title       = "SSL certificate should not use insecure certificate algorithm (i.e. MD2, MD5, SHA1)"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when signature_algorithm like any (array['%SHA1%', '%MD2%', '%MD5%']) then 'alarm'
        else 'ok'
      end as status,
      common_name || ' certificate using ' || signature_algorithm || ' signature algorithm.' as reason
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

control "ssl_certificate_secure_private_key" {
  title       = "SSL certificate should use secure private keys (i.e. 2,048-bit RSA, 256-bit ECDSA)"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when (public_key_algorithm = 'RSA' and public_key_length = 2048) or (public_key_algorithm = 'ECDSA' and public_key_length = 256) then 'ok'
        else 'alarm'
      end as status,
      common_name || ' using ' || public_key_length || '-bit ' || public_key_algorithm || ' key.' as reason
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

control "ssl_certificate_multiple_hostname" {
  title       = "SSL certificate should have sufficient hostname coverage"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when jsonb_array_length(dns_names) > 1 then 'ok'
        else 'alarm'
      end as status,
      case
        when jsonb_array_length(dns_names) > 1 then common_name || ' has sufficient hostname coverage.'
        else common_name || ' don''t have sufficient hostname coverage.'
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

control "ssl_certificate_use_complete_certificate_chain" {
  title       = "SSL certificate should have 2 or more certificates in certificate chain"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
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

control "ssl_certificate_use_secure_protocol" {
  title       = "SSL certificate should use secure protocol (i.e. TLS v1.2 or TLS v1.3)"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when protocol in ('TLS v1.2', 'TLS v1.3') then 'ok'
        else 'alarm'
      end as status,
      case
        when protocol in ('TLS v1.2', 'TLS v1.3') then common_name || ' using secure protocol.'
        else common_name || ' not using a secure protocol.'
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

control "ssl_certificate_use_secure_cipher_suite" {
  title       = "SSL certificate should use secure cipher suites"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when cipher_suite in ('TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256') then 'alarm'
        else 'ok'
      end as status,
      case
        when cipher_suite in ('TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256') then common_name || ' not using a secure cipher suite.'
        else common_name || ' using a secure cipher suite.'
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

control "ssl_certificate_use_strong_key_exchange" {
  title       = "SSL certificate should use strong key exchange (i.e. ECDHE)"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when protocol = 'TLS v1.3' then 'ok'
        when protocol = 'TLS v1.2' and split_part(cipher_suite, '_', 1) = 'ECDHE'  then 'ok'
        else 'alarm'
      end as status,
      case
        when protocol = 'TLS v1.3' or (protocol = 'TLS v1.2' and split_part(cipher_suite, '_', 1) = 'ECDHE') then common_name || ' using a strong key exchange.'
        else common_name || ' not using a strong key exchange.'
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
