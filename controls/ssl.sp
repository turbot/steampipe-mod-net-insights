locals {
  ssl_best_practices_common_tags = merge(local.net_insights_common_tags, {
    service = "Net/SSL"
  })
}

benchmark "ssl_best_practices" {
  title       = "SSL Best Practices"
  description = "Best practices for your certificates."
  documentation = file("./controls/docs/ssl_overview.md")
  
  children = [
    control.ssl_certificate_valid,
    control.ssl_certificate_not_expired,
    control.ssl_certificate_not_self_signed,
    control.ssl_certificate_not_revoked,
    control.ssl_certificate_no_insecure_signature,
    control.ssl_certificate_secure_private_key,
    control.ssl_certificate_multiple_hostname,
    control.ssl_certificate_caa_record_configured,
    control.ssl_certificate_use_complete_certificate_chain,
    control.ssl_certificate_use_secure_protocol,
    control.ssl_certificate_use_secure_cipher_suite,
    control.ssl_certificate_use_perfect_forward_secrecy,
    control.ssl_certificate_use_strong_key_exchange
  ]

  tags = merge(local.ssl_best_practices_common_tags, {
    type = "Benchmark"
  })
}

control "ssl_certificate_valid" {
  title       = "SSL certificate should be valid"
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
  title       = "SSL certificate should not be expired"
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
  title       = "SSL certificate should not be self signed"
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
  title       = "SSL certificate should not be a revoked certificate"
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

control "ssl_certificate_no_insecure_signature" {
  title       = "SSL certificate should not use insecure certificate algorithm (i.e. MD2, MD5, SHA1)"
  description = "MD2 and MD5 are part of the Message Digest Algorithm family which was created to verify the integrity of any message or file that is hashed. It has been cryptographically broken which means they are vulnerable to collision attacks and hence considered insecure. Also SHA1 is considered cryptographically weak. It is recommended not to use these insecure signatures."

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
  description = "Private key is the single most important component of your SSL certificate that's used in the encryption/decryption of data sent between your server and the connecting clients. It is recommended to use secure private key algorithm (i.e. 2,048-bit RSA, 256-bit ECDSA) to make your website secure."

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
  description = "It is recommended that your certificates cover all the names you wish to use with a site, since you cannot control how your users arrive at the site or how others link to it."

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

control "ssl_certificate_caa_record_configured" {
  title       = "SSL server should have CAA record for your certificate to whitelist a CA"
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

control "ssl_certificate_use_complete_certificate_chain" {
  title       = "SSL certificate should have 2 or more certificates in certificate chain"
  description = "An invalid certificate chain effectively renders the server certificate invalid and results in browser warnings. It is recommended to use two or more certificates to build a complete chain of trust."

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
  description = "It is recommended to use secure protocols (i.e. TLS v1.2 or TLS v1.3), since these versions offers modern authenticated encryption, improved latency and don't have obsolete features like cipher suites, compression etc. TLS v1.0 and TLS v1.1 are legacy protocol and shouldn't be used."

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
  description = "A cipher suite is a set of cryptographic algorithms. The set of algorithms that cipher suites usually contain include: a key exchange algorithm, a bulk encryption algorithm, and a message authentication code (MAC) algorithm. It is recommended to use secure ciphers like Authenticated Encryption with Associated Data (AEAD) cipher suites and Perfect Forward Secrecy (PFS) ciphers."

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

control "ssl_certificate_use_perfect_forward_secrecy" {
  title       = "SSL certificate should use forward secrecy protocol"
  description = "In cryptography, forward secrecy (FS), also known as perfect forward secrecy (PFS), is a feature of specific key agreement protocols that gives assurances that session keys will not be compromised even if long-term secrets used in the session key exchange are compromised."

  sql = <<-EOT
    select
      common_name as resource,
      case
        when protocol = 'TLS v1.3' or cipher_suite like any (array['%ECDHE_RSA%', '%ECDHE_ECDSA%', '%DHE_RSA%', '%DHE_DSS%', '%CECPQ1%']) then 'ok'
        else 'alarm'
      end as status,
      case
        when protocol = 'TLS v1.3' or cipher_suite like any (array['%ECDHE_RSA%', '%ECDHE_ECDSA%', '%DHE_RSA%', '%DHE_DSS%', '%CECPQ1%']) then common_name || ' cipher suites provides forward secrecy.'
        else common_name || ' cipher suites does not provide forward secrecy.'
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
  description = "It is recommended to use strong key exchange mechanism to keep data being transferred across the network more secure. Both parties agree on a single cipher suite and generate the session keys (symmetric keys) to encrypt and decrypt the information during an SSL session."

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
