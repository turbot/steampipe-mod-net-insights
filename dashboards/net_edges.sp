edge "domain_to_ssl_certificate" {
  title = "certificate"

  sql = <<-EOQ
    select
      d as from_id,
      c ->> 'common_name' as to_id
    from
      net_certificate,
      jsonb_array_elements(chain) as c,
      jsonb_array_elements_text($1) d
    where
      domain = d
  EOQ

  param "domain_names" {}
}

edge "domain_to_tls_version" {
  title = "tls version"

  sql = <<-EOQ
    with supported_protocols as (
      select
        version,
        d as domain
      from
        net_tls_connection c,
        jsonb_array_elements_text($1) as d
      where
        c.address = d || ':443'
        and c.handshake_completed
    )select
      domain as from_id,
      version as to_id
    from
      supported_protocols
  EOQ

  param "domain_names" {}
}

edge "domain_to_dns_parent" {
  title = "domain"

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
      parent_server as from_id,
      domain as to_id
    from 
      domain_parent_server_with_ip;
  EOQ

  param "domain_names" {}
}

edge "domain_to_dns_ns" {
  title = "name server"

  sql = <<-EOQ
    with domain_records as (
      select * from net_dns_record, jsonb_array_elements_text($1) d where domain = d and type = 'NS' order by domain
    ),
    ns_ips as (
      select domain, ip, type, target, host(ip) as ip_text from net_dns_record where domain in (select target from domain_records) and type = 'A' order by domain
    )
    select
      domain_records.domain as from_id,
      domain_records.target to_id
    from
      domain_records
      left join ns_ips on domain_records.target = ns_ips.domain and ns_ips.type = 'A'
    where
      domain_records.type = 'NS'
    order by domain_records.target
  EOQ

  param "domain_names" {}
}

edge "domain_to_dns_mx" {
  title = "mail exchange"

  sql = <<-EOQ
    with domain_records as (
      select * from net_dns_record, jsonb_array_elements_text($1) d where domain = d and type = 'MX'
    ),
    ns_ips as (
      select * from net_dns_record where domain in (select target from domain_records)
    )
    select
      domain_records.domain from_id,
      domain_records.target to_id
    from
      domain_records
      inner join ns_ips on domain_records.target = ns_ips.domain
    where
      ns_ips.type = 'A'
      and domain_records.type = 'MX'
  EOQ

  param "domain_names" {}
}