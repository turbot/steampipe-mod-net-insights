locals {
  ssl_checks_common_tags = {
    plugin = "net"
  }
}

benchmark "ssl_checks" {
  title       = "SSL Best Practices"
  description = "SSL best practices."
  #documentation = file("./controls/docs/dns_overview.md")
  tags = local.ssl_checks_common_tags
  children = [
    control.ssl_certificate_valid,
    control.ssl_certificate_not_expired,
    control.ssl_certificate_not_self_signed,
    control.ssl_certificate_no_insecure_signature,
    control.ssl_certificate_rsa_2048,
    control.ssl_certificate_multiple_hostname,
    control.ssl_certificate_use_complete_certificate_chain
  ]
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

control "ssl_certificate_rsa_2048" {
  title       = "SSL certificate should use RSA 2048 bits RSA key"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when public_key_algorithm = 'RSA' and public_key_length = 2048 then 'ok'
        else 'alarm'
      end as status,
      common_name || ' using ' || public_key_length || ' bit ' || public_key_algorithm || ' key.' as reason
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
        when jsonb_array_length(subject_alternative_names) > 1 then 'ok'
        else 'alarm'
      end as status,
      common_name || ' has ' || jsonb_array_length(subject_alternative_names) || ' hostname(s).' as reason
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
