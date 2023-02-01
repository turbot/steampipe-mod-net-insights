node "domain_node" {
  category = category.domain_node

  sql = <<-EOQ
    select
      d as id,
      d as title
    from
      jsonb_array_elements_text($1) d
  EOQ

  param "domain_names" {}
}

node "ssl_certificate" {
  category = category.ssl_certificate

  sql = <<-EOQ
    select
      c ->> 'common_name' as id,
      c ->> 'common_name' as title,
      jsonb_build_object(
        'Valid From', TO_CHAR((c ->> 'not_before')::timestamp, 'Dy, DD Mon YYYY HH24:MI:SS TZ'),
        'Valid Until', TO_CHAR((c ->> 'not_after')::timestamp, 'Dy, DD Mon YYYY HH24:MI:SS TZ') || ' (expires in ' || date_trunc('day', age((c ->> 'not_after')::timestamp, now())) || ')',
        'Key', c ->> 'public_key_algorithm' || ' ' || (c ->> 'public_key_length')::text || ' bits',
        'Issuer', c ->> 'issuer_name',
        'Signature Algorithm', c ->> 'signature_algorithm'
      ) as properties
    from
      net_certificate,
      jsonb_array_elements(chain) as c,
      jsonb_array_elements_text($1) d
    where
      domain = d
  EOQ

  param "domain_names" {}
}

node "tls_version" {
  category = category.tls_version

  sql = <<-EOQ
    with supported_protocols as (
      select
        version
      from
        net_tls_connection,
        jsonb_array_elements_text($1) d
      where
        address = d || ':443'
        and handshake_completed
    )select
      version as id,
      version as title
    from
      supported_protocols
  EOQ

  param "domain_names" {}
}

node "dns_parent" {
  category = category.dns_parent

  sql = <<-EOQ
    with domain_list as (
      select 
        distinct domain, substring( domain from '^(?:[^/:]*:[^/@]*@)?(?:[^/:.]*\.)+([^:/]+)' ) as tld 
      from 
        net_dns_record,
        jsonb_array_elements_text($1) d
      where 
        domain = d
    ),
    domain_parent_server as (
      select l.domain, d.domain as tld, d.target as parent_server from net_dns_record as d inner join domain_list as l on d.domain = l.tld where d.type = 'SOA'
    ),
    domain_parent_server_ip as (
      select * from net_dns_record where domain in (select parent_server from domain_parent_server)
    ),
    domain_parent_server_with_ip as (
      select 
        domain_parent_server.domain,
        domain_parent_server.tld,
        domain_parent_server.parent_server,
        domain_parent_server_ip.ip
      from 
        domain_parent_server 
        inner join domain_parent_server_ip 
          on domain_parent_server.parent_server = domain_parent_server_ip.domain 
      where 
        domain_parent_server_ip.type = 'A' 
      order by 
        domain_parent_server.domain
    )
    select
      parent_server as id,
      parent_server as title,
      jsonb_build_object(
        'Top Level Domain (TLD)', tld,
        'IP Address', ip
      ) as properties
    from 
      domain_parent_server_with_ip;
  EOQ

  param "domain_names" {}
}

node "dns_ns" {
  category = category.dns_ns

  sql = <<-EOQ
    with domain_records as (
      select * from net_dns_record, jsonb_array_elements_text($1) d where domain = d and type = 'NS' order by domain
    ),
    ns_ips as (
      select domain, ip, type, target, host(ip) as ip_text from net_dns_record where domain in (select target from domain_records) and type = 'A' order by domain
    )
    select
      domain_records.target as id,
      domain_records.target as title,
      jsonb_build_object(
        'IP Address', ns_ips.ip,
        'TTL', domain_records.ttl,
        'Status', case
          when ns_ips.ip is null then 'Not Responding'
          when (select count(*) from net_dns_record, jsonb_array_elements_text($1) d where domain = d and dns_server = ns_ips.ip_text group by domain) is not null then 'Responding'
          else 'Not Responding'
        end,
        'Authoritative', case
          when ns_ips.ip is null then false
          else (select count(*) from net_dns_record, jsonb_array_elements_text($1) d where domain = d and dns_server = ns_ips.ip_text and type = 'SOA' group by domain) is not null
        end
      ) as properties
    from
      domain_records
      left join ns_ips on domain_records.target = ns_ips.domain and ns_ips.type = 'A'
    where
      domain_records.type = 'NS'
    order by domain_records.target
  EOQ

  param "domain_names" {}
}

node "dns_mx" {
  category = category.dns_mx

  sql = <<-EOQ
    with domain_records as (
      select * from net_dns_record, jsonb_array_elements_text($1) d where domain = d and type = 'MX'
    ),
    ns_ips as (
      select * from net_dns_record where domain in (select target from domain_records)
    )
    select
      domain_records.target id,
      domain_records.target title,
      jsonb_build_object(
        'Priority', domain_records.priority,
        'IP Address', ns_ips.ip,
        'TTL', ns_ips.ttl
      ) as properties
    from
      domain_records
      inner join ns_ips on domain_records.target = ns_ips.domain
    where
      ns_ips.type = 'A'
      and domain_records.type = 'MX'
  EOQ

  param "domain_names" {}
}