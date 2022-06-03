benchmark "ssl_certificate_best_practices" {
  title         = "SSL/TLS Certificate Best Practices"
  description   = "Best practices for your domain certificates."
  documentation = file("./controls/docs/ssl/ssl_certificate_overview.md")

  children = [
    control.ssl_certificate_domain_name_mismatch,
    control.ssl_certificate_valid,
    control.ssl_certificate_not_expired,
    control.ssl_certificate_not_self_signed,
    control.ssl_certificate_not_revoked,
    control.ssl_certificate_secure_private_key,
    control.ssl_certificate_multiple_hostname,
    control.ssl_certificate_check_for_reliable_ca,
    control.ssl_certificate_no_insecure_signature,
    control.ssl_certificate_transparent,
    control.ssl_certificate_caa_record_configured,
  ]

  tags = merge(local.ssl_best_practices_common_tags, {
    type = "Benchmark"
  })
}

control "ssl_certificate_domain_name_mismatch" {
  title       = "Certificate common name should be listed in subject alternative name (SAN)"
  description = "The common name or subject alternative name (SAN) of your SSL/TLS Certificate should match the domain or address bar in the browser."

  sql = <<-EOT
    select
      common_name as resource,
      case
        when dns_names ? common_name or dns_names ? concat('*.', common_name) then 'ok'
        else 'alarm'
      end as status,
      case
        when dns_names ? common_name or dns_names ? concat('*.', common_name) then common_name || ' listed in certificate''s SAN.'
        else common_name || ' not listed in certificate''s SAN.'
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

control "ssl_certificate_valid" {
  title       = "Certificates should be valid"
  description = "It is recommended that the certificate is not being used before the time when the certificate is valid from."

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
  title       = "Certificates should not be expired"
  description = "SSL certificates ensure secure connections between a server and other web entities and provide validation that a browser is indeed communicating with a validated website server. Once it expires, your website is no longer recognized on the web as safe and secure and it is vulnerable to cyber-attacks."

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
  title       = "Self-signed certificate should not be used"
  description = "Self-signed certificates contain private and public keys within the same entity, and they cannot be revoked, thus making it difficult to detect security compromises. It is recommended not to use self-signed certificate since it encourage dangerous public browsing behavior."

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
  title       = "Certificates should not be a revoked certificate"
  description = "Check for certificate revocation on a server describes if the certificate being used has been revoked by the certificate authority before it was set to expire. It is recommended not to use revoked certificate since they are no longer trustworthy."

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

control "ssl_certificate_secure_private_key" {
  title       = "Use strong and secure private key (at least a 2,048-bit RSA or 256-bit ECDSA key)"
  description = "Private key is the single most important component of your SSL certificate that's used in the encryption/decryption of data sent between your server and the connecting clients. Larger keys are harder to crack, but require more computing overhead. It is recommended to use secure private key algorithm (at least a 2,048-bit RSA or 256-bit ECDSA) to make your website secure."

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
  title       = "Ensure certificates have sufficient hostname coverage"
  description = "It is recommended that your certificates cover all the names you wish to use with a site, since you cannot control how your users arrive at the site or how others link to it. Make sure you have added all the necessary domain names to certificate's Subject Alternative Name (SAN)."

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

control "ssl_certificate_check_for_reliable_ca" {
  title       = "Issuing certificate authority (CA) should support for both CRL and OCSP revocation methods"
  description = "Acquire your certificate from a trusted certificate authority (CA) that is reliable and serious about its certificate business and security, which should provide support for both Certificate Revocation List (CRL) and Online Certificate Status Protocol (OCSP) revocation methods."

  sql = <<-EOT
    with revocation_info as (
      select 
        common_name,
        case 
          when crl_distribution_points is null then 0
          else jsonb_array_length(crl_distribution_points)
        end as crl_count,
        jsonb_array_length(ocsp_server) as ocsp_count
      from
        net_certificate
      where
        domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      order by common_name
    )
    select
      common_name as resource,
      case
        when (crl_count > 0 and ocsp_count > 0) then 'ok'
        else 'alarm'
      end as status,
      (common_name || ' has ' || ocsp_count || ' OCSP endpoint(s) and ' || crl_count || ' CRL endpoint(s)') as reason
    from
      revocation_info;
  EOT

  param "dns_domain_names" {
    description = "DNS domain names."
    default     = var.dns_domain_names
  }
}

control "ssl_certificate_no_insecure_signature" {
  title       = "Certificates should not use insecure certificate algorithm (i.e. MD2, MD5, SHA1)"
  description = "MD2 and MD5 are part of the Message Digest Algorithm family which was created to verify the integrity of any message or file that is hashed. It has been cryptographically broken which means they are vulnerable to collision attacks and hence considered insecure. Also SHA1 is considered cryptographically weak. It is recommended not to use these insecure signatures."

  sql = <<-EOT
    select
      common_name as resource,
      case
        when signature_algorithm like any (array['%SHA1%', '%MD2%', '%MD5%']) then 'alarm'
        else 'ok'
      end as status,
      common_name || ' using ' || signature_algorithm || ' signature algorithm.' as reason
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

control "ssl_certificate_transparent" {
  title       = "Certificates should be visible in Certificate Transparency (CT) logs"
  description = "Certificate Transparency (CT) is an internet security standard for monitoring and auditing digital certificates. If a certificate authority issues an SSL certificate without adding it to the logs this can trigger certain browser errors. It is recommended that whenever issuing any certificate, add it to one or more public certificate transparency logs."

  sql = <<-EOT
    select
      common_name as resource,
      case
        when transparent then 'ok'
        else 'alarm'
      end as status,
      case
        when transparent then common_name || ' certificate is visible.'
        else common_name || ' certificate is not visible.'
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

control "ssl_certificate_caa_record_configured" {
  title       = "Ensure domain has CAA record configured to whitelist a CA for issuing certificates"
  description = "The CAA record is a type of DNS record used to provide additional confirmation for the Certification Authority (CA) when validating an SSL certificate. With CAA in place, the attack surface for fraudulent certificates is reduced, effectively making sites more secure."

  sql = <<-EOT
    with domain_list as (
      select distinct domain from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[]))) order by domain
    ),
    domain_with_caa_record as (
      select distinct domain from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[]))) and type = 'CAA'
    )
    select
      domain_list.domain as resource,
      case
        when domain_with_caa_record.domain is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when domain_with_caa_record.domain is not null then domain_list.domain || ' has CAA record.'
        else domain_list.domain || ' don''t have a CAA record.'
      end as reason
    from
      domain_list
      left join domain_with_caa_record on domain_list.domain = domain_with_caa_record.domain
    order by domain_list.domain;
  EOT

  param "dns_domain_names" {
    description = "DNS domain names."
    default     = var.dns_domain_names
  }
}
