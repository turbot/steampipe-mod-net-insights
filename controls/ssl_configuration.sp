benchmark "ssl_configuration_best_practices" {
  title         = "SSL/TLS Server Configuration Best Practices"
  description   = "Best practices for your SSL and TLS deployment."
  documentation = file("./controls/docs/ssl_configuration_overview.md")

  children = [
    control.ssl_certificate_use_complete_certificate_chain,
    control.ssl_use_secure_protocol,
    control.ssl_use_secure_cipher_suite,
    control.ssl_use_perfect_forward_secrecy,
    control.ssl_use_strong_key_exchange,
    control.ssl_use_tls_fallback_scsv,
    control.ssl_avoid_using_rc4_cipher_suite,
    control.ssl_avoid_using_cbc_cipher_suite,
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

control "ssl_use_secure_protocol" {
  title       = "SSL/TLS servers should avoid using insecure protocols"
  description = "There are six protocols in the SSL/TLS family: SSL v2, SSL v3, TLS v1.0, TLS v1.1, TLS v1.2, and TLS v1.3. It is recommended to use secure protocols (i.e. TLS v1.2 or TLS v1.3), since these versions offers modern authenticated encryption, improved latency and don't have obsolete features like cipher suites. TLS v1.0 and TLS v1.1 are legacy protocol and shouldn't be used."

  sql = <<-EOT
    with domain_list as (
      select domain, concat(domain, ':443') as address from jsonb_array_elements_text(to_jsonb($1::text[])) as domain
    ),
    check_insecure_protocol as (
      select
        address,
        count(*)
      from
        net_tls_connection
      where
        address in (select address from domain_list)
        and version in ('TLS v1.0', 'TLS v1.1')
        and handshake_completed
      group by address
    )
    select
      d.domain as resource,
      case
        when i.address is null or i.count < 1 then 'ok'
        else 'alarm'
      end as status,
      case
        when i.address is null or i.count < 1 then d.domain || ' doesn''t support insecure protocols.'
        else d.domain || ' supports insecure protocols.'
      end as reason
    from
      domain_list as d
      left join check_insecure_protocol as i on d.address = i.address;
  EOT

  param "dns_domain_names" {
    description = "DNS domain names."
    default     = var.dns_domain_names
  }
}

control "ssl_use_secure_cipher_suite" {
  title       = "SSL/TLS servers should use secure cipher suites"
  description = "A cipher suite is a set of cryptographic algorithms. The set of algorithms that cipher suites usually contain include: a key exchange algorithm, a bulk encryption algorithm, and a message authentication code (MAC) algorithm. It is recommended to use secure ciphers like Authenticated Encryption with Associated Data (AEAD) cipher suites and Perfect Forward Secrecy (PFS) ciphers. The following cipher suites are considered insecure: TLS_RSA_WITH_RC4_128_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256."

  sql = <<-EOT
    with domain_list as (
      select domain, concat(domain, ':443') as address from jsonb_array_elements_text(to_jsonb($1::text[])) as domain
    ),
    check_insecure_cipher as (
      select
        address,
        count(*)
      from
        net_tls_connection
      where
        address in (select address from domain_list)
        and cipher_suite_name in ('TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256')
        and handshake_completed
      group by address
    )
    select
      d.domain as resource,
      case
        when i.address is null or i.count < 1 then 'ok'
        else 'alarm'
      end as status,
      case
        when i.address is null or i.count < 1 then d.domain || ' uses secure cipher suites.'
        else d.domain || ' does not use secure cipher suites.'
      end as reason
    from
      domain_list as d
      left join check_insecure_cipher as i on d.address = i.address;
  EOT

  param "dns_domain_names" {
    description = "DNS domain names."
    default     = var.dns_domain_names
  }
}

control "ssl_use_perfect_forward_secrecy" {
  title       = "Ensure SSL/TLS servers uses perfect forward secrecy (PFS)"
  description = "In cryptography, forward secrecy (FS), also known as perfect forward secrecy (PFS), is a feature of specific key agreement protocols that gives assurances that session keys will not be compromised even if long-term secrets used in the session key exchange are compromised."

  sql = <<-EOT
    with domain_list as (
      select domain, concat(domain, ':443') as address from jsonb_array_elements_text(to_jsonb($1::text[])) as domain
    ),
    check_pfs_cipher as (
      select
        address,
        count(*)
      from
        net_tls_connection
      where
        address in (select address from domain_list)
        and cipher_suite_name in ('TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256')
        and handshake_completed
      group by address
    )
    select
      d.domain as resource,
      case
        when i.address is not null and i.count > 1 then 'ok'
        else 'alarm'
      end as status,
      case
        when i.address is not null and i.count > 1 then d.domain || ' cipher suites provide forward secrecy.'
        else d.domain || ' cipher suites do not provide forward secrecy.'
      end as reason
    from
      domain_list as d
      left join check_pfs_cipher as i on d.address = i.address;
  EOT

  param "dns_domain_names" {
    description = "DNS domain names."
    default     = var.dns_domain_names
  }
}

control "ssl_use_strong_key_exchange" {
  title       = "SSL/TLS servers should use strong key exchange mechanism (e.g., ECDHE)"
  description = "It is recommended to use strong key exchange mechanism to keep data being transferred across the network more secure. Both parties agree on a single cipher suite and generate the session keys (symmetric keys) to encrypt and decrypt the information during an SSL session."

  sql = <<-EOT
    with domain_list as (
      select domain, concat(domain, ':443') as address from jsonb_array_elements_text(to_jsonb($1::text[])) as domain
    ),
    all_ecdhe_ciphers as (
      select
        address,
        version,
        cipher_suite_name
      from
        net_tls_connection
      where
        address in (select address from domain_list)
        and version in ('TLS v1.3', 'TLS v1.2')
        and cipher_suite_name in ('TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256')
        and handshake_completed
    )
    select
      d.domain as resource,
      case
        when (select count(*) from all_ecdhe_ciphers where address = d.address and version = 'TLS v1.3') > 0 then 'ok'
        when (select count(*) from all_ecdhe_ciphers where address = d.address and version = 'TLS v1.2') > 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when
          (select count(*) from all_ecdhe_ciphers where address = d.address and version = 'TLS v1.3') > 0
          or (select count(*) from all_ecdhe_ciphers where address = d.address and version = 'TLS v1.2' and split_part(cipher_suite_name, '_', 2) = 'ECDHE') > 0
            then d.domain || ' uses strong key exchange mechanism.'
        else d.domain || ' does not use strong key exchange mechanism.'
      end as reason
    from
      domain_list as d;
  EOT

  param "dns_domain_names" {
    description = "DNS domain names."
    default     = var.dns_domain_names
  }
}

control "ssl_use_tls_fallback_scsv" {
  title       = "SSL/TLS servers should support TLS fallback SCSV for preventing protocol downgrade attacks"
  description = "A Signaling Cipher Suite Value (SCSV) helps in preventing protocol downgrade attacks on the Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS) protocols. If enabled, the server makes sure that the strongest protocol that both client and server understand is used. It is recommended that the server should support more than 1 protocol version, excluding SSL v2."

  sql = <<-EOT
    with domain_list as (
      select domain, concat(domain, ':443') as address from jsonb_array_elements_text(to_jsonb($1::text[])) as domain
    ),
    tls_connections as (
      select
        address,
        version,
        fallback_scsv_supported
      from
        net_tls_connection
      where
        address in (select address from domain_list)
        and handshake_completed
    ),
    tls_connection_version_count as (
      select
        address,
        version,
        count(*)
      from
        tls_connections
      group by address, version
    )
    select
      d.domain as resource,
      case
        when (select count(*) from tls_connection_version_count where address = d.address) < 2 then 'info'
        when (select count(*) from tls_connections where address = d.address and fallback_scsv_supported) > 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when (select count(*) from tls_connection_version_count where address = d.address) < 2 then d.domain || ' requires support for at least 2 protocols.'
        when (select count(*) from tls_connections where address = d.address and fallback_scsv_supported) > 0 then d.domain || ' supports TLS fallback SCSV.'
        else d.domain || ' doesn''t support TLS fallback SCSV.'
      end as reason
    from
      domain_list as d;
  EOT

  param "dns_domain_names" {
    description = "DNS domain names."
    default     = var.dns_domain_names
  }
}

control "ssl_avoid_using_rc4_cipher_suite" {
  title       = "SSL/TLS servers should avoid using RC4 cipher suites"
  description = "RC4 is a stream cipher, and it is more malleable than common block ciphers. If not used together with a strong message authentication code (MAC), then encryption is vulnerable to cyber attacks. RC4 is demonstrably broken, weak and unsafe to use in TLS as currently implemented."

  sql = <<-EOT
    with domain_list as (
      select domain, concat(domain, ':443') as address from jsonb_array_elements_text(to_jsonb($1::text[])) as domain
    ),
    check_rc4_cipher as (
      select
        address,
        count(*)
      from
        net_tls_connection
      where
        address in (select address from domain_list)
        and cipher_suite_name in ('TLS_RSA_WITH_RC4_128_SHA', 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA')
        and handshake_completed
      group by address
    )
    select
      d.domain as resource,
      case
        when i.address is null or i.count < 1 then 'ok'
        else 'alarm'
      end as status,
      case
        when i.address is null or i.count < 1 then d.domain || ' does not use RC4 cipher suites.'
        else d.domain || ' uses RC4 cipher suites.'
      end as reason
    from
      domain_list as d
      left join check_rc4_cipher as i on d.address = i.address;
  EOT

  param "dns_domain_names" {
    description = "DNS domain names."
    default     = var.dns_domain_names
  }
}

control "ssl_avoid_using_cbc_cipher_suite" {
  title       = "SSL/TLS servers should avoid using CBC cipher suites"
  description = "Cipher block chaining (CBC) is a mode of operation for a block cipher in which a sequence of bits are encrypted as a single unit, or block, with a cipher key applied to the entire block. The problem with CBC mode is that the decryption of blocks is dependent on the previous ciphertext block, which means attackers can manipulate the decryption of a block by tampering with the previous block using the commutative property of XOR. If the server uses TLS 1.2 or TLS 1.1, or TLS 1.0 with CBC cipher modes, there is a chance that the server gets vulnerable to Zombie POODLE, GOLDENDOODLE, 0-Length OpenSSL and Sleeping POODLE."

  sql = <<-EOT
    with domain_list as (
      select domain, concat(domain, ':443') as address from jsonb_array_elements_text(to_jsonb($1::text[])) as domain
    ),
    check_cbc_cipher as (
      select
        address,
        count(*)
      from
        net_tls_connection
      where
        address in (select address from domain_list)
        and cipher_suite_name in ('TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256')
        and handshake_completed
      group by address
    )
    select
      d.domain as resource,
      case
        when i.address is null or i.count < 1 then 'ok'
        else 'alarm'
      end as status,
      case
        when i.address is null or i.count < 1 then d.domain || ' does not use CBC cipher suites.'
        else d.domain || ' uses CBC cipher suites.'
      end as reason
    from
      domain_list as d
      left join check_cbc_cipher as i on d.address = i.address;
  EOT

  param "dns_domain_names" {
    description = "DNS domain names."
    default     = var.dns_domain_names
  }
}

control "ssl_certificate_avoid_too_much_security" {
  title       = "Avoid implementing too much security for certificates"
  description = "Using RSA keys stronger than 2048 bits or ECDSA keys stronger than 256 bits is a waste of CPU power and might impair user experience."

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
