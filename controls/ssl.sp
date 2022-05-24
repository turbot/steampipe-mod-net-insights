locals {
  ssl_best_practices_common_tags = merge(local.net_insights_common_tags, {
    service = "Net/SSL"
  })
}

variable "cbc_cipher_suites" {
  type        = list(string)
  description = "A list of domain names to run DNS checks for."
  default     = [
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "0x0006", # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
    "0x0008", # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
    "0x0010", # TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
    "0x0085", # TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
    "0x0011", # TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
    "0x0007", # TLS_RSA_WITH_IDEA_CBC_SHA
    "0x0019", # TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
    "0x0012", # TLS_DHE_DSS_WITH_DES_CBC_SHA
    "0x000A", # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    "0x001A", # TLS_DH_anon_WITH_DES_CBC_SHA
    "0x0016", # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    "0x000B", # TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
    "0x001B", # TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
    "0x000C", # TLS_DH_DSS_WITH_DES_CBC_SHA
    "0x0015", # TLS_DHE_RSA_WITH_DES_CBC_SHA
    "0x000D", # TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
    "0x001E", # TLS_KRB5_WITH_DES_CBC_SHA
    "0x000E", # TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
    "0x0009", # TLS_RSA_WITH_DES_CBC_SHA
    "0x001F", # TLS_KRB5_WITH_3DES_EDE_CBC_SHA
    "0x0013", # TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
    "0x000F", # TLS_DH_RSA_WITH_DES_CBC_SHA
    "0x003A", # TLS_DH_anon_WITH_AES_256_CBC_SHA
    "0x0014", # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
    "0x0021", # TLS_KRB5_WITH_IDEA_CBC_SHA
    "0x003C", # TLS_RSA_WITH_AES_128_CBC_SHA256
    "0x0022", # TLS_KRB5_WITH_DES_CBC_MD5
    "0x006B", # TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    "0x006A", # TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
    "0x006C", # TLS_DH_anon_WITH_AES_128_CBC_SHA256
    "0x003D", # TLS_RSA_WITH_AES_256_CBC_SHA256
    "0x0023", # TLS_KRB5_WITH_3DES_EDE_CBC_MD5
    "0x006D", # TLS_DH_anon_WITH_AES_256_CBC_SHA256
    "0x003E", # TLS_DH_DSS_WITH_AES_128_CBC_SHA256
    "0x0067", # TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    "0x003F", # TLS_DH_RSA_WITH_AES_128_CBC_SHA256
    "0x0068", # TLS_DH_DSS_WITH_AES_256_CBC_SHA256
    "0x0069", # TLS_DH_RSA_WITH_AES_256_CBC_SHA256
    "0x0043", # TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
    "0x002F", # TLS_RSA_WITH_AES_128_CBC_SHA
    "0x0030", # TLS_DH_DSS_WITH_AES_128_CBC_SHA
    "0x0044", # TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
    "0x0025", # TLS_KRB5_WITH_IDEA_CBC_MD5
    "0x0040", # TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
    "0x0026", # TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA
    "0x0084", # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
    "0x0031", # TLS_DH_RSA_WITH_AES_128_CBC_SHA
    "0x0027", # TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA
    "0x0041", # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
    "0x0032", # TLS_DHE_DSS_WITH_AES_128_CBC_SHA
    "0x0033", # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    "0x0029", # TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5
    "0x002A", # TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5
    "0x0034", # TLS_DH_anon_WITH_AES_128_CBC_SHA
    "0x0045", # TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
    "0x0046", # TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA
    "0x0042", # TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
    "0x0035", # TLS_RSA_WITH_AES_256_CBC_SHA
    "0x0086", # TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
    "0x0038", # TLS_DHE_DSS_WITH_AES_256_CBC_SHA
    "0x0037", # TLS_DH_RSA_WITH_AES_256_CBC_SHA
    "0x0039", # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    "0x0096", # TLS_RSA_WITH_SEED_CBC_SHA
    "0x0095", # TLS_RSA_PSK_WITH_AES_256_CBC_SHA
    "0x0036", # TLS_DH_DSS_WITH_AES_256_CBC_SHA
    "0x0097", # TLS_DH_DSS_WITH_SEED_CBC_SHA
    "0x0087", # TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
    "0x009A", # TLS_DHE_RSA_WITH_SEED_CBC_SHA
    "0x009B", # TLS_DH_anon_WITH_SEED_CBC_SHA
    "0x0098", # TLS_DH_RSA_WITH_SEED_CBC_SHA
    "0x0088", # TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
    "0x0089", # TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA
    "0x00AE", # TLS_PSK_WITH_AES_128_CBC_SHA256
    "0x00AF", # TLS_PSK_WITH_AES_256_CBC_SHA384
    "0x008B", # TLS_PSK_WITH_3DES_EDE_CBC_SHA
    "0x008C", # TLS_PSK_WITH_AES_128_CBC_SHA
    "0x008D", # TLS_PSK_WITH_AES_256_CBC_SHA
    "0x00B2", # TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
    "0x0099", # TLS_DHE_DSS_WITH_SEED_CBC_SHA
    "0x008F", # TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
    "0x00B3", # TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
    "0x0090", # TLS_DHE_PSK_WITH_AES_128_CBC_SHA
    "0xC017", # TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
    "0x0091", # TLS_DHE_PSK_WITH_AES_256_CBC_SHA
    "0xC04B", # TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384
    "0x00B6", # TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
    "0x0093", # TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
    "0x00B7", # TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
    "0x0094", # TLS_RSA_PSK_WITH_AES_128_CBC_SHA
    "0xC009", # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    "0xC018", # TLS_ECDH_anon_WITH_AES_128_CBC_SHA
    "0xC00A", # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    "0x00BA", # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
    "0xC019", # TLS_ECDH_anon_WITH_AES_256_CBC_SHA
    "0x00BB", # TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256
    "0x00BC", # TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256
    "0xC01A", # TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA
    "0x00BD", # TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
    "0xC01B", # TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
    "0x00BE", # TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
    "0x00BF", # TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256
    "0xC01C", # TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
    "0x00C0", # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
    "0xC00D", # TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    "0x00C1", # TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256
    "0xC01D", # TLS_SRP_SHA_WITH_AES_128_CBC_SHA
    "0xC00E", # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    "0x00C2", # TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256
    "0xC01E", # TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
    "0x00C3", # TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
    "0xC00F", # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    "0x00C4", # TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
    "0xC01F", # TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
    "0x00C5", # TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256
    "0xC020", # TLS_SRP_SHA_WITH_AES_256_CBC_SHA
    "0xC003", # TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    "0xC021", # TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
    "0xC004", # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    "0xC005", # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    "0xC012", # TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    "0xC036", # TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
    "0xC074", # TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
    "0xC022", # TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
    "0xC013", # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    "0xC023", # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    "0xC008", # TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    "0xC024", # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    "0xC025", # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
    "0xC026", # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
    "0xC037", # TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
    "0xC027", # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    "0xC014", # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    "0xC028", # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    "0xC038", # TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
    "0xC04C", # TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256
    "0xC029", # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    "0xC02A", # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    "0xC075", # TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
    "0xC076", # TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
    "0xC077", # TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
    "0xC078", # TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256
    "0xC03C", # TLS_RSA_WITH_ARIA_128_CBC_SHA256
    "0xC079", # TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
    "0xC04D", # TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384
    "0xC03D", # TLS_RSA_WITH_ARIA_256_CBC_SHA384
    "0xC04E", # TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256
    "0xC03E", # TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256
    "0xC04F", # TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384
    "0xC03F", # TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384
    "0xC034", # TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
    "0xC097", # TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
    "0xC098", # TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
    "0xC035", # TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
    "0xC040", # TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256
    "0xC099", # TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
    "0xC09A", # TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
    "0xC041", # TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384
    "0xC046", # TLS_DH_anon_WITH_ARIA_128_CBC_SHA256
    "0xC042", # TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256
    "0xC09B", # TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
    "0xC047", # TLS_DH_anon_WITH_ARIA_256_CBC_SHA384
    "0xC064", # TLS_PSK_WITH_ARIA_128_CBC_SHA256
    "0xC043", # TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384
    "0xC044", # TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256
    "0xC048", # TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256
    "0xC045", # TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384
    "0xC065", # TLS_PSK_WITH_ARIA_256_CBC_SHA384
    "0xC066", # TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256
    "0xC067", # TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384
    "0xC049", # TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384
    "0xC094", # TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
    "0xC04A", # TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256
    "0xC095", # TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
    "0xC096", # TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
    "0xC068", # TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256
    "0xC069", # TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384
    "0xC070", # TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256
    "0xC071", # TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384
    "0xC072", # TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
    "0xC073", # TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
  ]
}

variable "aead_cipher_suites" {
  type        = list(string)
  description = "A list of Authenticated Encryption with Additional Data (AEAD) cipher suites."
  default     = [
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "0x009e", # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    "0x009c", # TLS_RSA_WITH_AES_128_GCM_SHA256
    "0x00a0", # TLS_DH_RSA_WITH_AES_128_GCM_SHA256
    "0x00a2", # TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
    "0x00a4", # TLS_DH_DSS_WITH_AES_128_GCM_SHA256
    "0xc031", # TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    "0x00a6", # TLS_DH_anon_WITH_AES_128_GCM_SHA256
    "0x00aa", # TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
    "0x00ac", # TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
    "0x00a8", # TLS_PSK_WITH_AES_128_GCM_SHA256
    "0xd001", # TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
    "0xc0b0", # TLS_ECCPWD_WITH_AES_128_GCM_SHA256
    "0xc02d", # TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
    "0x00a3", # TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
    "0x00a1", # TLS_DH_RSA_WITH_AES_256_GCM_SHA384
    "0x009f", # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    "0x00a5", # TLS_DH_DSS_WITH_AES_256_GCM_SHA384
    "0x00a7", # TLS_DH_anon_WITH_AES_256_GCM_SHA384
    "0x00a9", # TLS_PSK_WITH_AES_256_GCM_SHA384
    "0xc032", # TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
    "0x00ab", # TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
    "0x00ad", # TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
    "0xc0b1", # TLS_ECCPWD_WITH_AES_256_GCM_SHA384
    "0xc02e", # TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    "0xd002", # TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"
    "0xccaa", # TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    "0xccab", # TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
    "0xccac", # TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    "0xccad", # TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    "0xccae", # TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
  ]
}

variable "rc4_cipher_suites" {
  type        = list(string)
  description = "A list of RC4 cipher suites."
  default     = [
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "0x0004", # TLS_RSA_WITH_RC4_128_MD5
    "0x0003", # TLS_RSA_EXPORT_WITH_RC4_40_MD5
    "0x0028", # TLS_KRB5_EXPORT_WITH_RC4_40_SHA
    "0x008e", # TLS_DHE_PSK_WITH_RC4_128_SHA
    "0x002b", # TLS_KRB5_EXPORT_WITH_RC4_40_MD5
    "0x0092", # TLS_RSA_PSK_WITH_RC4_128_SHA
    "0x008a", # TLS_PSK_WITH_RC4_128_SHA
    "0x0017", # TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
    "0x0018", # TLS_DH_anon_WITH_RC4_128_MD5
    "0x0024", # TLS_KRB5_WITH_RC4_128_MD5
    "0xc002", # TLS_ECDH_ECDSA_WITH_RC4_128_SHA
    "0x0020", # TLS_KRB5_WITH_RC4_128_SHA
    "0xc016", # TLS_ECDH_anon_WITH_RC4_128_SHA
    "0xc00c", # TLS_ECDH_RSA_WITH_RC4_128_SHA
    "0xc033" # TLS_ECDHE_PSK_WITH_RC4_128_SHA"
  ]
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
    control.ssl_certificate_check_for_reliable_ca,
    control.ssl_certificate_caa_record_configured,
    control.ssl_certificate_use_complete_certificate_chain,
    control.ssl_certificate_use_secure_protocol,
    control.ssl_certificate_use_secure_cipher_suite,
    control.ssl_certificate_use_perfect_forward_secrecy,
    control.ssl_certificate_use_strong_key_exchange,
    control.ssl_certificate_too_much_security,
    control.ssl_server_is_vulnerable_to_beast_attack,
    control.ssl_server_is_vulnerable_to_poodle_ssl_v3_attack,
    control.ssl_server_is_vulnerable_to_goldendoodle_attack,
    control.ssl_server_is_vulnerable_to_zombie_poodle_attack,
    control.ssl_server_is_vulnerable_to_sleeping_poodle_attack,
    control.ssl_server_openssl_0_length_check,
    #control.ssl_http_strict_transport_security_enabled,
    #control.ssl_content_security_policy_enabled
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

control "ssl_certificate_use_strong_key_exchange" {
  title       = "SSL certificate should use strong key exchange (i.e. ECDHE)"
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

control "ssl_certificate_too_much_security" {
  title       = "Too much security"
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
        ) then common_name || ' is using too big keys.'
        else common_name || ' is not using big keys.'
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

control "ssl_server_is_vulnerable_to_beast_attack" {
  title       = "SSL server should not be vulnerable to BEAST attack"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when (protocol = 'TLS v1.0' or protocol = 'SSL v3') and cipher_suite not in (select jsonb_array_elements_text(to_jsonb($2::text[]))) then 'alarm'
        else 'ok'
      end as status,
      case
        when (protocol = 'TLS v1.0' or protocol = 'SSL v3') and cipher_suite not in (select jsonb_array_elements_text(to_jsonb($2::text[]))) then common_name || ' is vulnerable to BEAST attack.'
        else common_name || ' is not vulnerable to BEAST attack.'
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

  param "rc4_cipher_suites" {
    description = "RC4 cipher suite list."
    default     = var.rc4_cipher_suites
  }
}

control "ssl_server_is_vulnerable_to_poodle_ssl_v3_attack" {
  title       = "SSL server should not be vulnerable to POODLE (SSLv3) attack"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when protocol = 'SSL v3' and cipher_suite in (select jsonb_array_elements_text(to_jsonb($2::text[]))) then 'alarm'
        else 'ok'
      end as status,
      case
        when protocol = 'SSL v3' and cipher_suite in (select jsonb_array_elements_text(to_jsonb($2::text[]))) then common_name || ' is vulnerable to POODLE (SSLv3) attack.'
        else common_name || ' is not vulnerable to POODLE (SSLv3) attack.'
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

  param "cbc_cipher_suites" {
    description = "CBC cipher suite list."
    default     = var.cbc_cipher_suites
  }
}

control "ssl_server_is_vulnerable_to_goldendoodle_attack" {
  title       = "SSL server should not be vulnerable to GOLDENDOODLE attack"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when protocol <> 'TLS v1.3' and cipher_suite in (select jsonb_array_elements_text(to_jsonb($2::text[]))) then 'alarm'
        else 'ok'
      end as status,
      case
        when protocol <> 'TLS v1.3' and  cipher_suite in (select jsonb_array_elements_text(to_jsonb($2::text[]))) then common_name || ' is vulnerable to GOLDENDOODLE attack.'
        else common_name || ' is not vulnerable to GOLDENDOODLE attack.'
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

  param "cbc_cipher_suites" {
    description = "CBC cipher suite list."
    default     = var.cbc_cipher_suites
  }
}

control "ssl_server_is_vulnerable_to_zombie_poodle_attack" {
  title       = "SSL server should not be vulnerable to Zombie POODLE attack"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when protocol <> 'TLS v1.3' and cipher_suite in (select jsonb_array_elements_text(to_jsonb($2::text[]))) then 'alarm'
        else 'ok'
      end as status,
      case
        when protocol <> 'TLS v1.3' and  cipher_suite in (select jsonb_array_elements_text(to_jsonb($2::text[]))) then common_name || ' is vulnerable to Zombie POODLE attack.'
        else common_name || ' is not vulnerable to Zombie POODLE attack.'
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

  param "cbc_cipher_suites" {
    description = "CBC cipher suite list."
    default     = var.cbc_cipher_suites
  }
}

control "ssl_server_is_vulnerable_to_sleeping_poodle_attack" {
  title       = "SSL server should not be vulnerable to Sleeping POODLE attack"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when protocol <> 'TLS v1.3' and cipher_suite in (select jsonb_array_elements_text(to_jsonb($2::text[]))) then 'alarm'
        else 'ok'
      end as status,
      case
        when protocol <> 'TLS v1.3' and cipher_suite in (select jsonb_array_elements_text(to_jsonb($2::text[]))) then common_name || ' is vulnerable to Sleeping POODLE attack.'
        else common_name || ' is not vulnerable to Sleeping POODLE attack.'
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

  param "cbc_cipher_suites" {
    description = "CBC cipher suite list."
    default     = var.cbc_cipher_suites
  }
}

control "ssl_server_openssl_0_length_check" {
  title       = "SSL server should not be vulnerable to openSSL 0-length (CVE-2019-1559 vulnerability)"
  description = ""

  sql = <<-EOT
    select
      common_name as resource,
      case
        when protocol <> 'TLS v1.3' and cipher_suite not in (select jsonb_array_elements_text(to_jsonb($2::text[]))) then 'alarm'
        else 'ok'
      end as status,
      case
        when protocol <> 'TLS v1.3' and  cipher_suite not in (select jsonb_array_elements_text(to_jsonb($2::text[]))) then common_name || ' is vulnerable to OpenSSL 0-length (CVE-2019-1559) vulnerability.'
        else common_name || ' is not vulnerable to OpenSSL 0-length (CVE-2019-1559) vulnerability.'
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

  param "aead_cipher_suites" {
    description = "AEAD cipher suite list."
    default     = var.aead_cipher_suites
  }
}

# TODO:: The following checks required updated `net_web_request` table.
# control "ssl_http_strict_transport_security_enabled" {
#   title       = "Websites should have HTTP Strict Transport Security (HSTS) enabled"
#   description = ""
# 
#   sql = <<-EOT
#     with available_headers as (
#       select
#         url,
#         array_agg(header.key)
#       from
#         net_web_request,
#         jsonb_each(response_headers) as header
#       where
#         url in (select concat('https://', jsonb_array_elements_text(to_jsonb($1::text[]))))
#       group by url
#     )
#     select
#       url as resource,
#       case
#         when array['Strict-Transport-Security'] <@ array_agg then 'ok'
#         else 'alarm'
#       end as status,
#       case
#         when array['Strict-Transport-Security'] <@ array_agg then url || ' contains required headers ''Strict-Transport-Security''.'
#         else url || ' has missing required headers ''Strict-Transport-Security''.'
#       end as reason
#     from
#       available_headers;
#   EOT
# 
#   param "dns_domain_names" {
#     description = "DNS domain names."
#     default     = var.dns_domain_names
#   }
# }
# 
# control "ssl_content_security_policy_enabled" {
#   title       = "Websites should have Content Security Policy (CSP) enabled"
#   description = ""
# 
#   sql = <<-EOT
#     with available_headers as (
#       select
#         url,
#         array_agg(header.key)
#       from
#         net_web_request,
#         jsonb_each(response_headers) as header
#       where
#         url in (select concat('https://', jsonb_array_elements_text(to_jsonb($1::text[]))))
#       group by url
#     )
#     select
#       url as resource,
#       case
#         when array['Content-Security-Policy'] <@ array_agg then 'ok'
#         else 'alarm'
#       end as status,
#       case
#         when array['Content-Security-Policy'] <@ array_agg then url || ' contains required headers ''Content-Security-Policy''.'
#         else url || ' has missing required headers ''Content-Security-Policy''.'
#       end as reason
#     from
#       available_headers;
#   EOT
# 
#   param "dns_domain_names" {
#     description = "DNS domain names."
#     default     = var.dns_domain_names
#   }
# }
