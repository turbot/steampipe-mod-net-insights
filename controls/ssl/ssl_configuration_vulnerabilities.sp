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

benchmark "ssl_configuration_vulnerabilities_check" {
  title       = "SSL Server Vulnerability Checks"
  description = ""

  children = [
    control.ssl_server_is_vulnerable_to_beast_attack,
    control.ssl_server_is_vulnerable_to_poodle_ssl_v3_attack,
    control.ssl_server_is_vulnerable_to_goldendoodle_attack,
    control.ssl_server_is_vulnerable_to_zombie_poodle_attack,
    control.ssl_server_is_vulnerable_to_sleeping_poodle_attack,
    control.ssl_server_openssl_0_length_check,
  ]
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