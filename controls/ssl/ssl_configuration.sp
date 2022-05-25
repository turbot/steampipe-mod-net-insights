benchmark "ssl_configuration_best_practices" {
  title         = "SSL/TLS Configuration Best Practices"
  description   = "Best practices for your SSL and TLS deployment."
  documentation = file("./controls/docs/ssl_configuration_overview.md")

  children = [
    control.ssl_certificate_use_complete_certificate_chain,
    control.ssl_use_secure_protocol,
    control.ssl_use_secure_cipher_suite,
    control.ssl_use_perfect_forward_secrecy,
    control.ssl_use_strong_key_exchange,
    benchmark.ssl_configuration_vulnerabilities_check
  ]
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

control "ssl_use_secure_protocol" {
  title       = "SSL server should use secure protocol (i.e. TLS v1.2 or TLS v1.3)"
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

control "ssl_use_secure_cipher_suite" {
  title       = "SSL server should use secure cipher suites"
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

control "ssl_use_perfect_forward_secrecy" {
  title       = "SSL server should use perfect forward secrecy (PFS) protocol"
  description = "In cryptography, forward secrecy (FS), also known as perfect forward secrecy (PFS), is a feature of specific key agreement protocols that gives assurances that session keys will not be compromised even if long-term secrets used in the session key exchange are compromised."

  sql = <<-EOT
    with pfs_cipher_suites as (
      select * from (
        values
          ('TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'),
          ('TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'),
          ('TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'),
          ('TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'),
          ('TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256'),
          ('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'),
          ('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'),
          ('TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'),
          ('TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'),
          ('TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'),
          -- Below cipher suites are not supported by golang package
          -- since it returns an ID value of the cipher suite
          ('0xc024'), -- TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
          ('0xco28'), -- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
          ('0x009e'), -- TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
          ('0x009f'), -- TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
          ('0x0033'), -- TLS_DHE_RSA_WITH_AES_128_CBC_SHA
          ('0x0039'), -- TLS_DHE_RSA_WITH_AES_256_CBC_SHA
          ('0x0067'), -- TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
          ('0x006b') -- TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
      ) as a (cipher_suite)
    )
    select
      common_name as resource,
      case
        when protocol = 'TLS v1.3' then 'ok'
        when cipher_suite in (select * from pfs_cipher_suites) then 'ok'
        else 'alarm'
      end as status,
      case
        when protocol = 'TLS v1.3' or cipher_suite in (select * from pfs_cipher_suites) then common_name || ' cipher suites provides forward secrecy.'
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

control "ssl_use_strong_key_exchange" {
  title       = "SSL server should use strong key exchange mechanism(i.e. ECDHE)"
  description = "It is recommended to use strong key exchange mechanism to keep data being transferred across the network more secure. Both parties agree on a single cipher suite and generate the session keys (symmetric keys) to encrypt and decrypt the information during an SSL session."

  sql = <<-EOT
    select
      common_name as resource,
      case
        when protocol = 'TLS v1.3' then 'ok'
        when protocol = 'TLS v1.2' and split_part(cipher_suite, '_', 2) = 'ECDHE'  then 'ok'
        else 'alarm'
      end as status,
      case
        when protocol = 'TLS v1.3' 
          or (protocol = 'TLS v1.2' and split_part(cipher_suite, '_', 2) = 'ECDHE') then common_name || ' using a strong key exchange.'
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
