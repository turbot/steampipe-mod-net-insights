dashboard "ssl_configuration_report" {

  title         = "SSL/TLS Server Configuration Report"
  documentation = file("./dashboards/docs/ssl_configuration_report.md")

  tags = merge(local.ssl_common_tags, {
    type     = "Report"
    category = "Networking"
  })

  input "domain_input" {
    title       = "Enter a domain:"
    width       = 4
    type        = "text"
    placeholder = "example.com"
  }

  # Cards
  container {

    width = 12

    card {
      width = 3
      query = query.ssl_server_supported_protocols
      args  = {
        domain_input = self.input.domain_input.value
      }
    }

    // TODO: What should this link to?
    /*
    card {
      width = 3
      query = query.ssl_server_insecure_cipher_count
      args  = {
        domain_input = self.input.domain_input.value
      }
    }
    */

    card {
      width = 3
      query = query.ssl_server_rc4_cipher_count
      args  = {
        domain_input = self.input.domain_input.value
      }
    }

    card {
      width = 3
      query = query.ssl_server_cbc_cipher_count
      args  = {
        domain_input = self.input.domain_input.value
      }
    }
  }

  # Protocols and Cipher Suites
  container {
    title = "Protocols and Cipher Suites"

    table {

      width = 6
      query = query.ssl_server_supported_cipher_suites

      column "Cipher Suites" {
        wrap = "all"
      }
    }

    table {

      width = 6
      query = query.ssl_server_configuration_checks
        args  = {
        domain_input = self.input.domain_input.value
      }

      column "Recommendation" {
        wrap = "all"
      }

      column "Result" {
        wrap = "all"
      }
    }
  }
}

query "ssl_server_supported_protocols" {
  sql = <<-EOQ
    with supported_protocols as (
      select
        distinct version
      from
        net_tls_connection
      where
        address = $1 || ':443'
        and handshake_completed
      order by version desc
    )
    select
      'Protocols Supported' as label,
      string_agg(version, ', ') as value,
      'info' as type
    from
      supported_protocols;
  EOQ

  param "domain_input" {}
}

query "ssl_server_insecure_cipher_count" {
  sql = <<-EOQ
    with domain_list as (
      select $1 as domain, $1 || ':443' as address
    ),
    insecure_cipher_count as (
      select
        address,
        count(address) as cipher_count
      from
        net_tls_connection
      where
        address in (select address from domain_list)
        and cipher_suite_name in ('TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256')
        and handshake_completed
      group by
        address
    )
    select
      'Insecure Ciphers' as label,
      i.cipher_count as value,
      case
        when i.cipher_count is null then 'ok'
        when i.cipher_count < 1 then 'ok'
        else 'alert'
      end as type
    from
      domain_list as d
      left join insecure_cipher_count as i on d.address = i.address;
  EOQ

  param "domain_input" {}
}

query "ssl_server_rc4_cipher_count" {
  sql = <<-EOQ
    with domain_list as (
      select $1 as domain, $1 || ':443' as address
    ),
    rc4_cipher_count as (
      select
        address,
        count(address) as cipher_count
      from
        net_tls_connection
      where
        address in (select address from domain_list)
        and version in ('TLS v1.2', 'TLS v1.1', 'TLS v1.0')
        and cipher_suite_name in ('TLS_RSA_WITH_RC4_128_SHA', 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA')
        and handshake_completed
      group by
        address
    )
    select
      'RC4 Cipher Suites' as label,
      case
        when i.cipher_count is null then 0
        else i.cipher_count
      end as value,
      case
        when i.cipher_count is null then 'ok'
        when i.cipher_count < 1 then 'ok'
        else 'alert'
      end as type
    from
      domain_list as d
      left join rc4_cipher_count as i on d.address = i.address;
  EOQ

  param "domain_input" {}
}

query "ssl_server_cbc_cipher_count" {
  sql = <<-EOQ
    with domain_list as (
      select $1 as domain, $1 || ':443' as address
    ),
    cbc_cipher_count as (
      select
        address,
        count(address) as cipher_count
      from
        net_tls_connection
      where
        address in (select address from domain_list)
        and cipher_suite_name in ('TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256')
        and handshake_completed
      group by
        address
    )
    select
      'CBC Cipher Suites' as label,
      case
        when i.cipher_count is null then 0
        else i.cipher_count
      end as value,
      case
        when i.cipher_count is null then 'ok'
        when i.cipher_count < 1 then 'ok'
        else 'alert'
      end as type
    from
      domain_list as d
      left join cbc_cipher_count as i on d.address = i.address
  EOQ

  param "domain_input" {}
}

query "ssl_server_supported_cipher_suites" {
  sql = <<-EOQ
    select
      version as "Protocol",
      concat(cipher_suite_name, ' (', cipher_suite_id, ')') as "Cipher Suite"
    from
      net_tls_connection
    where
      address = 'turbot.com:443'
      and handshake_completed
    order by version desc, "Cipher Suite"
  EOQ
}

query "ssl_server_configuration_checks" {
  sql = <<-EOQ
    with domain_list as (
      select $1 as domain, $1 || ':443' as address
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
    ),
    check_rc4_cipher as (
      select
        address,
        count(*)
      from
        net_tls_connection
      where
        address in (select address from domain_list)
        and version in ('TLS v1.2', 'TLS v1.1', 'TLS v1.0')
        and cipher_suite_name in ('TLS_RSA_WITH_RC4_128_SHA', 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA')
        and handshake_completed
      group by address
    ),
    check_cbc_cipher as (
      select
        address,
        count(*)
      from
        net_tls_connection
      where
        address in (select address from domain_list)
        and version in ('TLS v1.2', 'TLS v1.1', 'TLS v1.0')
        and cipher_suite_name in ('TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256')
        and handshake_completed
      group by address
    )
    select
      'Use complete chain of trusted certificates' as "Recommendation",
      case
        when chain @> '[{"is_certificate_authority": true}]' then '✅'
        when jsonb_array_length(chain) >= 2 then '✅'
        else '❌'
      end as "Status",
      common_name || ' has ' || jsonb_array_length(chain) || ' certificate(s) along with the server certificates. An invalid certificate chain effectively renders the server certificate invalid and results in browser warnings. End-entity SSL/TLS certificates are generally signed by intermediate certificates rather than a CA’s root key. It is recommended to use two or more certificates to build a complete chain of trust.' as "Result"
    from
      net_certificate
    where
      domain = $1
    UNION
    select
      'Use secure protocols' as "Recommendation",
      case
        when i.address is null or i.count < 1 then '✅'
        else '❌'
      end as "Status",
      case
        when i.address is null or i.count < 1 then d.domain || ' doesn''t support insecure protocols.'
        else d.domain || ' supports insecure protocols.'
      end
        || ' There are six protocols in the SSL/TLS family: SSL v2, SSL v3, TLS v1.0, TLS v1.1, TLS v1.2, and TLS v1.3. It is recommended to use secure protocols (e.g., TLS v1.2, TLS v1.3) since these versions offer modern authenticated encryption, improved latency and don''t have obsolete features like cipher suites. TLS v1.0 and TLS v1.1 are legacy protocols and shouldn''t be used.' as "Result"
    from
      domain_list as d
      left join check_insecure_protocol as i on d.address = i.address
    UNION
    select
      'Use secure cipher suites' as "Recommendation",
      case
        when i.address is null or i.count < 1 then '✅'
        else '❌'
      end as "Status",
      case
        when i.address is null or i.count < 1 then d.domain || ' uses secure cipher suites.'
        else d.domain || ' does not use secure cipher suites.'
      end
        || ' A cipher suite is a set of cryptographic algorithms. The set of algorithms that cipher suites usually contain includes: a key exchange algorithm, a bulk encryption algorithm, and a message authentication code (MAC) algorithm. It is recommended to use secure ciphers like Authenticated Encryption with Associated Data (AEAD) cipher suites and Perfect Forward Secrecy (PFS) ciphers. The following cipher suites are considered insecure: TLS_RSA_WITH_RC4_128_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.' as "Result"
    from
      domain_list as d
      left join check_insecure_cipher as i on d.address = i.address
    UNION
    select
      'Use perfect forward secrecy' as "Recommendation",
      case
        when i.address is not null and i.count > 1 then '✅'
        else '❌'
      end as "Status",
      case
        when i.address is not null and i.count > 1 then d.domain || ' cipher suites provide forward secrecy.'
        else d.domain || ' cipher suites do not provide forward secrecy.'
      end
        || ' In cryptography, forward secrecy (FS), also known as perfect forward secrecy (PFS), is a feature of specific key agreement protocols that gives assurances that session keys will not be compromised even if long-term secrets are used in the session key exchange are compromised.' as "Result"
    from
      domain_list as d
      left join check_pfs_cipher as i on d.address = i.address
    UNION
      select
        'Use strong key exchange mechanism' as "Recommendation",
        case
          when (select count(*) from all_ecdhe_ciphers where address = d.address and version = 'TLS v1.3') > 0 then '✅'
          when (select count(*) from all_ecdhe_ciphers where address = d.address and version = 'TLS v1.2') > 0 then '✅'
    else '❌'
        end as "Status",
        case
          when (select count(*) from all_ecdhe_ciphers where address = d.address and version = 'TLS v1.3') > 0 or (select count(*) from all_ecdhe_ciphers where address = d.address and version = 'TLS v1.2' and split_part(cipher_suite_name, '_', 2) = 'ECDHE') > 0
        then d.domain || ' uses strong key exchange mechanism.'
        else d.domain || ' does not use strong key exchange mechanism.'
        end
          || ' It is recommended to use a strong key exchange mechanism to keep data being transferred across the network more secure. Both parties agree on a single cipher suite and generate the session keys (symmetric keys) to encrypt and decrypt the information during an SSL session.' as "Result"
      from
        domain_list as d
    UNION
      select
        'Avoid using RC4 ciphers' as "Recommendation",
        case
          when i.address is null then '✅'
          when i.count < 1 then '✅'
          else '❌'
        end as "Status",
        case
          when i.address is null or i.count < 1 then d.domain || ' does not use RC4 cipher suites.'
          else d.domain || ' uses RC4 cipher suites.'
        end
          || ' RC4 is a stream cipher and is more malleable than common block ciphers. Encryption is vulnerable to cyber-attacks if not used together with a strong message authentication code (MAC). RC4 is demonstrably broken, weak and unsafe to use in TLS as currently implemented.' as "Result"
      from
        domain_list as d
        left join check_rc4_cipher as i on d.address = i.address
    UNION
      select
        'Avoid using CBC ciphers' as "Recommendation",
        case
          when i.address is null then '✅'
          when i.count < 1 then '✅'
          else '❌'
        end as "Status",
        case
          when i.address is null or i.count < 1 then d.domain || ' does not use CBC cipher suites.'
          else d.domain || ' uses CBC cipher suites.'
        end
          || ' Cipher block chaining (CBC) is a mode of operation for a block cipher in which a sequence of bits are encrypted as a single unit, or block, with a cipher key applied to the entire block. The problem with CBC mode is that the decryption of blocks is dependent on the previous ciphertext block, which means attackers can manipulate the decryption of a block by tampering with the previous block using the commutative property of XOR. If the server uses TLS 1.2 or TLS 1.1, or TLS 1.0 with CBC cipher modes, there is a chance that the server gets vulnerable to Zombie POODLE, GOLDENDOODLE, 0-Length OpenSSL and Sleeping POODLE.' as "Result"
      from
        domain_list as d
        left join check_cbc_cipher as i on d.address = i.address
  EOQ

  param "domain_input" {}
}
