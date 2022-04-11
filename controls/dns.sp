variable "domain_name" {
  type        = list(string)
  description = "The name of the domain."
  default     = [ "turbot.com", "steampipe.io" ]
}

locals {
  dns_check_common_tags = {
    plugin = "net"
  }
}

benchmark "dns_checks" {
  title         = "DNS Checks"
  description   = "DNS checks."
  documentation = file("./controls/docs/dns_overview.md")
  tags          = local.dns_check_common_tags
  children = [
    benchmark.parent_checks,
    benchmark.ns_checks,
    benchmark.soa_checks,
    benchmark.mx_checks
  ]
}

benchmark "parent_checks" {
  title         = "Parent"
  description   = "Parent checks."
  documentation = file("./controls/docs/dns_parent_overview.md")
  tags          = local.dns_check_common_tags
  children = [
    control.dns_record_found,
    control.dns_ns_listed_at_parent,
    control.dns_ns_all_with_type_a_record
  ]
}

control "dns_record_found" {
  title       = "DNS record must be present"
  description = "Domain Name System (DNS) is used to point any domain toward the IP address of the server. When you search for a domain, the DNS records searches for the IP address of the server and server the website. It is required to have valid records for your domain, so that it can be found when anyone searching for your domain."
  severity    = "low"

  sql = <<-EOT
    select
      domain as resource,
      case
        when count(*) = 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when count(*) = 0 then 'DNS record not found for ' || domain || '.'
        else 'DNS record found for ' || domain || '.'
      end as reason
    from
      net_dns_record
    where
      domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
    group by domain;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_ns_listed_at_parent" {
  title       = "DNS parent server should have name server information"
  description = "It is highly recommended that the parent server should have information for all your name server, so that if anyone want your domain information and does not know DNS server can ask parent server for information."
  severity    = "high"

  sql = <<-EOT
    with domain_list as (
      select distinct domain, substring( domain from '^(?:[^/:]*:[^/@]*@)?(?:[^/:.]*\.)+([^:/]+)' ) as tld from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
    ),
    domain_parent_server as (
      select l.domain, d.domain as tld, d.target as parent_server from net_dns_record as d inner join domain_list as l on d.domain = l.tld where d.type = 'SOA'
    ),
    domain_parent_server_ip as (
      select * from net_dns_record where domain in (select parent_server from domain_parent_server)
    ),
    domain_parent_server_with_ip as (
      select domain_parent_server.domain, host(domain_parent_server_ip.ip) as ip_text from domain_parent_server inner join domain_parent_server_ip on domain_parent_server.parent_server = domain_parent_server_ip.domain where domain_parent_server_ip.type = 'A' order by domain_parent_server.domain
    ),
    domain_parent_server_ns_list as (
      select net_dns_record.domain, string_agg(net_dns_record.target, ', ') as ns_records from net_dns_record inner join domain_parent_server_with_ip on net_dns_record.domain = domain_parent_server_with_ip.domain and net_dns_record.dns_server = domain_parent_server_with_ip.ip_text and net_dns_record.type = 'NS' group by net_dns_record.domain
    )
    select
      domain as resource,
      case
        when (select ns_records from domain_parent_server_ns_list where domain = domain_list.domain) is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when (select ns_records from domain_parent_server_ns_list where domain = domain_list.domain) is not null then domain || ' parent server has listed name servers.'
        else domain || ' parent server don''t have information for name servers.'
      end as reason
    from
      domain_list;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_ns_all_with_type_a_record" {
  title       = "Every name server listed must have A records"
  description = "The 'A' record is the most fundamental type of DNS record which indicates the IP address of a domain. An A record maps a domain to the physical IP address of the computer hosting that domain. Internet traffic uses the A record to find the computer hosting your domain's DNS settings. It is highly recommended that every name server listed at parent should have A record."
  severity    = "high"

  sql = <<-EOT
    with domain_list as (
      select distinct domain, substring( domain from '^(?:[^/:]*:[^/@]*@)?(?:[^/:.]*\.)+([^:/]+)' ) as tld from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
    ),
    domain_parent_server as (
      select l.domain, d.domain as tld, d.target as parent_server from net_dns_record as d inner join domain_list as l on d.domain = l.tld where d.type = 'SOA'
    ),
    domain_parent_server_ip as (
      select * from net_dns_record where domain in (select parent_server from domain_parent_server)
    ),
    domain_parent_server_with_ip as (
      select domain_parent_server.domain, host(domain_parent_server_ip.ip) as ip_text from domain_parent_server inner join domain_parent_server_ip on domain_parent_server.parent_server = domain_parent_server_ip.domain where domain_parent_server_ip.type = 'A' order by domain_parent_server.domain
    ),
    domain_parent_server_ns_list as (
      select net_dns_record.domain, net_dns_record.target from net_dns_record inner join domain_parent_server_with_ip on net_dns_record.domain = domain_parent_server_with_ip.domain and net_dns_record.dns_server = domain_parent_server_with_ip.ip_text and net_dns_record.type = 'NS' order by net_dns_record.domain
    ),
    ns_ips as (
      select domain, type, ip from net_dns_record where domain in (select target from domain_parent_server_ns_list) and type = 'A' order by domain
    ),
    ns_with_type_a_record as (
      select domain_parent_server_ns_list.domain, ns_ips.type, domain_parent_server_ns_list.target, ns_ips.ip from domain_parent_server_ns_list left join ns_ips on domain_parent_server_ns_list.target = ns_ips.domain
    )
    select
      domain as resource,
      case
        when (select target from ns_with_type_a_record where domain = domain_list.domain and type is null) is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when (select target from ns_with_type_a_record where domain = domain_list.domain and type is null) is not null then domain || ' has some name servers [' || (select string_agg(target, ', ') from ns_with_type_a_record where domain = domain_list.domain and type is null) || '] that do not have A records.'
        else 'Every name servers listed at ' || domain || ' parent server has A records.'
      end as reason
    from
      domain_list;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

benchmark "ns_checks" {
  title         = "Name Server (NS)"
  description   = "NS checks."
  documentation = file("./controls/docs/dns_ns_overview.md")
  tags          = local.dns_check_common_tags
  children = [
    control.dns_ns_name_valid,
    control.dns_ns_at_least_two,
    control.dns_ns_responded,
    control.dns_local_ns_matches_parent_ns_list,
    control.dns_no_cname_with_other_record,
    control.dns_ns_on_different_subnets,
    control.dns_ns_all_ip_public,
    control.dns_ns_different_autonomous_systems
  ]
}

control "dns_ns_name_valid" {
  title       = "DNS name server should have valid name"
  description = "It is recommended that all the name server should have valid name format. DNS names can contain only alphabetical characters (A-Z), numeric characters (0-9), the minus sign (-), and the period (.). Period characters are allowed only when they are used to delimit the components of domain style names."
  severity    = "low"

  sql = <<-EOT
    with invalid_ns_count as (
      select
        domain,
        count(*)
      from
        net_dns_record
      where
        domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
        and type = 'NS'
        and not target ~ '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\.?$'
      group by domain
    ),
    domain_list as (
      select distinct domain from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
    )
    select
      d.domain as resource,
      case
        when r.domain is null or r.count = 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when r.domain is null or r.count = 0 then d.domain || ' name servers have valid name format.'
        else d.domain || ' has at least one name server with invalid name format.'
      end as reason
    from
      domain_list as d
      left join invalid_ns_count as r on d.domain = r.domain;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_ns_at_least_two" {
  title       = "DNS should have at least 2 name servers"
  description = "Only having 1 name server leaves you vulnerable to that name server failing and taking down your website. It is recommended to have at least 2 name servers for your domain to provide failover capability/backup in the event one name server fails."
  severity    = "low"

  sql = <<-EOT
    select
      domain as resource,
      case
        when count(*) < 2 then 'alarm'
        else 'ok'
      end as status,
      domain || ' has ' || count(*) || ' name servers.' as reason
    from
      net_dns_record
    where
      domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      and type = 'NS'
    group by
      domain,
      type;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_ns_responded" {
  title       = "All name servers listed at the parent server should respond"
  description = "It is recommended that all name servers listed at parent server should respond individually and return same NS record as parent."
  severity    = "high"

  sql = <<-EOT
    with domain_ns_records as (
      select * from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[]))) and type = 'NS'
    ),
    ns_ips as (
      select * from net_dns_record where domain in (select target from domain_ns_records)
    ),
    ns_with_ip as (
      select domain_ns_records.domain, host(ns_ips.ip) as ip_text from domain_ns_records inner join ns_ips on domain_ns_records.target = ns_ips.domain where ns_ips.type = 'A' order by domain_ns_records.domain
    ),
    ns_individual_count as (
      select
        d.domain,
        count(*)
      from
        net_dns_record as d
        inner join ns_with_ip as i on d.domain = i.domain and d.dns_server = i.ip_text
      where
        d.type = 'NS'
      group by d.domain
    ),
    ns_count as (
      select domain, count(*) from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[]))) and type = 'NS' group by domain
    )
    select
      nc.domain as resource,
      case
        when nic.count = pow(nc.count, 2) then 'ok'
        else 'alarm'
      end as status,
      case
        when nic.count = pow(nc.count, 2) then nc.domain || ' name servers are responding.'
        else 'At least one name server in ' || nc.domain || ' failed to respond in a timely manner.'
      end as reason
    from
      ns_count as nc,
      ns_individual_count as nic
    where
      nc.domain = nic.domain
    group by nc.domain, nic.count, nc.count;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_local_ns_matches_parent_ns_list" {
  title       = "Local DNS name server list should match parent name server list"
  description = "It is recommended that local NS list should list same number of NS as parent NS."
  severity    = "low"

  sql = <<-EOT
    with domain_list as (
      select distinct domain, substring( domain from '^(?:[^/:]*:[^/@]*@)?(?:[^/:.]*\.)+([^:/]+)' ) as tld from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[]))) order by domain
    ),
    domain_parent_server as (
      select l.domain, d.domain as tld, d.target as parent_server from net_dns_record as d inner join domain_list as l on d.domain = l.tld where d.type = 'SOA' order by l.domain
    ),
    domain_parent_server_ip as (
      select * from net_dns_record where domain in (select parent_server from domain_parent_server) order by domain
    ),
    domain_parent_server_with_ip as (
      select domain_parent_server.domain, host(domain_parent_server_ip.ip) as ip_text from domain_parent_server inner join domain_parent_server_ip on domain_parent_server.parent_server = domain_parent_server_ip.domain where domain_parent_server_ip.type = 'A' order by domain_parent_server.domain
    ),
    domain_parent_server_ns_list as (
      select net_dns_record.domain, net_dns_record.target from net_dns_record inner join domain_parent_server_with_ip on net_dns_record.domain = domain_parent_server_with_ip.domain and net_dns_record.dns_server = domain_parent_server_with_ip.ip_text and net_dns_record.type = 'NS' order by net_dns_record.domain
    ),
    parent_server_ns_count_by_domain as (
      select net_dns_record.domain, count(net_dns_record.target) from net_dns_record inner join domain_parent_server_with_ip on net_dns_record.domain = domain_parent_server_with_ip.domain and net_dns_record.dns_server = domain_parent_server_with_ip.ip_text and net_dns_record.type = 'NS' group by net_dns_record.domain order by net_dns_record.domain
    ),
    ns_ips as (
      select domain, type, ip, host(ip) as ip_text from net_dns_record where domain in (select target from domain_parent_server_ns_list) and type = 'A' order by domain
    ),
    ns_with_name_server_record as (
      select
        domain_parent_server_ns_list.domain,
        domain_parent_server_ns_list.target,
        (select count as parent_server_ns_record_count from parent_server_ns_count_by_domain where domain = domain_parent_server_ns_list.domain),
        (select count(*) as name_server_record_count from net_dns_record where domain = domain_parent_server_ns_list.domain and dns_server = ns_ips.ip_text and type = 'NS' group by domain)
      from
        domain_parent_server_ns_list
        left join ns_ips on domain_parent_server_ns_list.target = ns_ips.domain
      where
        ns_ips.ip is not null
      order by domain_parent_server_ns_list.domain
    ),
    ns_with_different_ns_count as (
      select distinct domain from ns_with_name_server_record where parent_server_ns_record_count <> name_server_record_count
    )
    select
      domain_list.domain as resource,
      case
        when ns_with_different_ns_count.domain is null then 'ok'
        else 'alarm'
      end as status,
      case
        when ns_with_different_ns_count.domain is null then domain_list.domain || ' name server records returned by parent server is same as the one reported by your name servers.'
        else domain_list.domain || ' name server records returned by parent server doesn''t match with your name servers [' || (select string_agg(target, ', ') from ns_with_name_server_record where parent_server_ns_record_count <> name_server_record_count) || '].'
      end as reason
    from
      domain_list
      left join ns_with_different_ns_count on domain_list.domain = ns_with_different_ns_count.domain;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_no_cname_with_other_record" {
  title       = "DNS record should not contain CNAME record if an NS (or any other) record is present"
  description = "A CNAME record is not allowed to coexist with any other data. This is often attempted by inexperienced administrators as an obvious way to allow your domain name to also be a host. However, DNS servers like BIND will see the CNAME and refuse to add any other resources for that name. Since no other records are allowed to coexist with a CNAME, the NS entries are ignored."
  severity    = "low"

  sql = <<-EOT
    with domain_list as (
      select distinct domain from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[]))) order by domain
    ),
    dns_record_count as (
      select domain, count(*) from net_dns_record where domain in (select domain from domain_list) group by domain
    ),
    dns_cname_count as (
      select domain, count(*) from net_dns_record where domain in (select domain from domain_list) and type = 'CNAME' group by domain
    ),
    count_stats as (
      select
        domain,
        (select count from dns_record_count where domain = domain_list.domain) as all_record_count,
        (select count from dns_cname_count where domain = domain_list.domain) as cname_record_count
      from
        domain_list
    )
    select
      domain as resource,
      case
        when all_record_count > 0 and (cname_record_count is null or cname_record_count < 1) then 'ok'
        when cname_record_count > 0 and all_record_count = cname_record_count then 'ok'
        else 'alarm'
      end as status,
      case
        when all_record_count > 0 and (cname_record_count is null or cname_record_count < 1) then domain || ' has no CNAME record.'
        when cname_record_count > 0 and all_record_count = cname_record_count then domain || ' has CNAME record [' || (select string_agg(target, ', ') from net_dns_record where domain = count_stats.domain) || '].'
        else domain || ' has CNAME record along with NS (or any other) record.'
      end as reason
    from
      count_stats;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_ns_on_different_subnets" {
  title       = "DNS name servers should be on different subnets"
  description = "Having more than 1 name server in the same class C subnet is not recommended, as this increases the likelihood of a single failure disabling all of your name servers."
  severity    = "low"

  sql = <<-EOT
    with domain_records as (
      select
        *
      from
        net_dns_record
      where
        domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
    ),
    ns_ips as (
      select
        *
      from
        net_dns_record
      where
        domain in ( select target from domain_records where type = 'NS' )
    ),
    check_ips as (
      select
        distinct array_to_string(array_remove(string_to_array(text(ns_ips.ip), '.'), split_part(text(ns_ips.ip), '.', 4)), '.'),
        domain_records.domain as domain
      from
        domain_records
        inner join ns_ips on domain_records.target = ns_ips.domain
      where
        ns_ips.type = 'A'
        and domain_records.type = 'NS'
    )
    select
      domain as resource,
      case
        when count(*) = 1 then 'alarm'
        else 'ok'
      end as status,
      case
        when count(*) = 1 then domain || ' name servers are on the same subnet.'
        else domain || ' name servers appear to be dispersed.'
      end as reason
    from
      check_ips
    group by domain;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_ns_all_ip_public" {
  title       = "DNS NS records should use public IPs"
  description = "For a server to be accessible on the public internet, it needs a public DNS record, and its IP address needs to be reachable on the internet."
  severity    = "low"

  sql = <<-EOT
    with domain_list as (
      select distinct domain from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[]))) order by domain
    ),
    domain_ns_records as (
      select domain, target from net_dns_record where domain in (select domain from domain_list) and type = 'NS' order by domain
    ),
    ns_ips as (
      select * from net_dns_record where domain in (select target from domain_ns_records) and type = 'A'
    ),
    ns_record_with_ip as (
      select
        domain_ns_records.domain,
        domain_ns_records.target,
        ns_ips.ip,
        (ns_ips.ip << '10.0.0.0/8'::inet or ns_ips.ip << '100.64.0.0/10'::inet or ns_ips.ip << '172.16.0.0/12'::inet or ns_ips.ip << '192.0.0.0/24'::inet or ns_ips.ip << '192.168.0.0/16'::inet or ns_ips.ip << '198.18.0.0/15'::inet) as is_private
      from
        domain_ns_records
        inner join ns_ips on domain_ns_records.target = ns_ips.domain
    ),
    ns_record_with_private_ip as (
      select distinct domain from ns_record_with_ip where is_private
    )
    select
      domain_list.domain as resource,
      case
        when ns_record_with_private_ip.domain is null then 'ok'
        else 'alarm'
      end as status,
      case
        when ns_record_with_private_ip.domain is null then 'All NS records in ' || domain_list.domain || ' appear to use public IPs.'
        else domain_list.domain || ' has NS records using private IPs [' || (select host(ip) from ns_record_with_ip where domain = domain_list.domain and is_private) || '].'
      end as reason
    from
      domain_list
      left join ns_record_with_private_ip on domain_list.domain = ns_record_with_private_ip.domain;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_ns_different_autonomous_systems" {
  title       = "DNS name servers should locate in different locations"
  description = "Having more than 1 name server located in the same location is not recommended, as this increases the likelihood of a single failure disabling all of your name servers."
  severity    = "low"

  sql = <<-EOT
    with domain_records as (
      select
        *
      from
        net_dns_record
      where
        domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
    ),
    ns_ips as (
      select
        *
      from
        net_dns_record
      where
        domain in ( select target from domain_records where type = 'NS' )
    ),
    check_ips as (
      select
        distinct array_to_string(array_remove(string_to_array(text(ns_ips.ip), '.'), split_part(text(ns_ips.ip), '.', 4)), '.'),
        domain_records.domain as domain
      from
        domain_records
        inner join ns_ips on domain_records.target = ns_ips.domain
      where
        ns_ips.type = 'A'
        and domain_records.type = 'NS'
    )
    select
      domain as resource,
      case
        when count(*) = 1 then 'alarm'
        else 'ok'
      end as status,
      case
        when count(*) = 1 then domain || ' have name servers located in same location.'
        else domain || ' name servers are located in different locations.'
      end as reason
    from
      check_ips
    group by domain;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

benchmark "soa_checks" {
  title         = "Start of Authority (SOA)"
  description   = "SOA checks."
  documentation = file("./controls/docs/dns_soa_overview.md")
  #tags          = local.dns_check_common_tags
  children = [
    control.dns_ns_same_serial,
    control.dns_primary_ns_listed_at_parent,
    control.dns_soa_serial_check,
    control.dns_soa_refresh_value_check,
    control.dns_soa_retry_value_check,
    control.dns_soa_expire_value_check,
    control.dns_soa_min_ttl_value_check
  ]
}

control "dns_ns_same_serial" {
  title       = "All DNS NS records should have same SOA serial"
  description = "Sometimes serial numbers become out of sync when any record within a zone got updated and the changes are transferred from primary name server to other name servers. If the SOA serial number is not same for all NS record there might be a problem with the transfer."
  severity    = "low"

  sql = <<-EOT
    with domain_ns_records as (
      select * from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[]))) and type = 'NS' order by domain
    ),
    ns_ips as (
      select domain, ip, type, target, host(ip) as ip_text from net_dns_record where domain in (select target from domain_ns_records) and type = 'A' order by domain
    ),
    ns_records_with_ips as (
      select
        domain_ns_records.domain,
        host(ns_ips.ip) as ip_text
      from
        domain_ns_records
        inner join ns_ips on domain_ns_records.target = ns_ips.domain
      where
        ns_ips.type = 'A'
      order by domain_ns_records.domain
    ),
    unique_serial as (
      select
        distinct r.serial,
        r.domain
      from
        net_dns_record as r
        inner join ns_records_with_ips as i on r.domain = i.domain and r.dns_server = i.ip_text
      where
        r.type = 'SOA'
    ),
    domain_list as (
      select distinct domain from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
    )
    select
      d.domain as resource,
      case
        when (select count(*) from unique_serial where domain = d.domain) is null or (select count(*) from unique_serial where domain = d.domain) > 1 then 'alarm'
        else 'ok'
      end as status,
      case
        when (select count(*) from unique_serial where domain = d.domain) is null or (select count(*) from unique_serial where domain = d.domain) > 1
          then d.domain || ' has at least 1 name server with different SOA serial.'
        else 'All name servers listed in ' || d.domain || ' have same SOA serial.'
      end as reason
    from
      domain_list as d;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_primary_ns_listed_at_parent" {
  title       = "DNS primary name server should be listed at parent"
  description = "The Primary Name Server is the name server declared in your SOA file and is usually the name server that reads your records from zone files and is responsible for distributing that data to your secondary name servers. This problem is present when this primary name server is not included in the parent referrals and is almost always accompanied by a Local Parent Mismatch problem."
  severity    = "low"

  sql = <<-EOT
    with primary_ns_from_soa_record as (
      select
        domain as domain_add,
        target as primary_ns
      from
        net_dns_record
      where
        domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
        and type = 'SOA'
    ),
    all_ns as (
      select
        domain,
        target
      from
        net_dns_record
      where
        domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
        and type = 'NS'
    )
    select
      ans.domain as resource,
      case
        when count(*) = 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when count(*) = 0 then ans.domain || ' primary name server not listed at parent.'
        else ans.domain || ' primary name server listed at parent.'
      end as reason
    from
      all_ns as ans
      left join primary_ns_from_soa_record as pns on pns.domain_add = ans.domain and ans.target = pns.primary_ns
    group by ans.domain;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_soa_serial_check" {
  title       = "DNS SOA serial number should be between 1 and 4294967295"
  description = "SOA serial number is used as a version number for your DNS zone. For all name servers to be up to date with the current version of your zone, they must have the same SOA serial number. It is recommended that the format should be in YYYYMMDDnn format (per RFC1912 2.2)."
  severity    = "low"

  sql = <<-EOT
    select
      domain as resource,
      case
        when (select serial::text ~ '^\d{4}[0-1]{1}[0-9]{1}[0-3]{1}[0-9]{1}\d{2}$') then 'ok'
        else 'alarm'
      end as status,
      case
        when not (select serial::text ~ '^\d{4}[0-1]{1}[0-9]{1}[0-3]{1}[0-9]{1}\d{2}$') then domain || ' SOA serial number ' || serial || ' doesn''t match recommended format (per RFC1912 2.2) YYYYMMDDnn.'
        else domain || ' SOA serial number is ' || serial || '.'
      end as reason
    from
      net_dns_record
    where
      domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      and type = 'SOA';
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_soa_refresh_value_check" {
  title       = "DNS SOA refresh value should be between 20 minutes and 12 hours"
  description = "Number of seconds after which secondary name servers should query the master for the SOA record, to detect zone changes. It is recommended that the value should be between 20 minutes to 12 hours."
  severity    = "low"

  sql = <<-EOT
    select
      domain as resource,
      case
        when refresh < 1200 or refresh > 43200 then 'alarm'
        else 'ok'
      end as status,
      domain || ' SOA refresh value is ' || (refresh / 60) || ' minutes.' as reason
    from
      net_dns_record
    where
      domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      and type = 'SOA';
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_soa_retry_value_check" {
  title       = "DNS SOA retry value should be between 2 minutes and 2 hours"
  description = "Number of seconds after which secondary name servers should retry to request the serial number from the master if the master does not respond. It must be less than Refresh. It is recommended that the value should be between 2 minutes to 2 hours."
  severity    = "low"

  sql = <<-EOT
    select
      domain as resource,
      case
        when retry < 120 or retry > 7200 then 'alarm'
        else 'ok'
      end as status,
      domain || ' SOA retry value is ' || (retry / 60) || ' minutes.' as reason
    from
      net_dns_record
    where
      domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      and type = 'SOA';
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_soa_expire_value_check" {
  title       = "DNS SOA expire value should be between 2 weeks and 4 weeks"
  description = "Number of seconds after which secondary name servers should stop answering request for this zone if the master does not respond. This value must be bigger than the sum of Refresh and Retry. It is recommended that the value should be between 2 weeks to 4 weeks."
  severity    = "low"

  sql = <<-EOT
    select
      domain as resource,
      case
        when expire < 1209600 or expire > 2419200 then 'alarm'
        else 'ok'
      end as status,
      domain || ' SOA expire value is ' || expire || ' seconds.' as reason
    from
      net_dns_record
    where
      domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      and type = 'SOA';
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_soa_min_ttl_value_check" {
  title       = "DNS SOA minimum TTL value should be between 10 minutes to 24 hours"
  description = "Time To Live (TTL) is the sort of expiration date that is put on a DNS record. The TTL serves to tell the recursive server or local resolver how long it should keep said record in its cache. The longer the TTL, the longer the resolver holds that information in its cache."
  severity    = "low"

  sql = <<-EOT
    select
      domain as resource,
      case
        when min_ttl < 600 or min_ttl > 86400 then 'alarm'
        else 'ok'
      end as status,
      domain || ' SOA minimum TTL value is ' || (min_ttl / 60) || ' minutes.' as reason
    from
      net_dns_record
    where
      domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      and type = 'SOA';
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

benchmark "mx_checks" {
  title         = "Mail Exchange (MX)"
  description   = "MX checks."
  documentation = file("./controls/docs/dns_mx_overview.md")
  tags          = local.dns_check_common_tags
  children = [
    control.dns_mx_valid_hostname,
    control.dns_mx_all_ip_public,
    control.dns_mx_not_contain_ip,
    control.dns_mx_at_least_two,
    control.dns_mx_no_duplicate_a_record,
    control.dns_mx_reverse_a_record
  ]
}

control "dns_mx_valid_hostname" {
  title       = "DNS MX records should have valid hostname"
  description = "It is recommended that MX record should have a valid domain or sub domain name and the name not starts or ends with a dot(.)."
  severity    = "low"

  sql = <<-EOT
    with domain_list as (
      select distinct domain from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[]))) order by domain
    ),
    mx_records as (
      select domain, rtrim(target, '.') as target, rtrim(target, '.') ~ '^[^.].*[^-_.]$' as is_valid from net_dns_record where domain in (select domain from domain_list) and type = 'MX'
    )
    select
      domain as resource,
      case
        when (select count(*) from mx_records where domain = domain_list.domain and not is_valid) > 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when (select count(*) from mx_records where domain = domain_list.domain and not is_valid) > 0 then domain || ' has MX record(s) ' || (select string_agg(target, ', ') from mx_records where domain = domain_list.domain and not is_valid) || ' with invalid host name.'
        else domain || ' has no MX records with invalid host name.'
      end as reason
    from
      domain_list;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_mx_all_ip_public" {
  title       = "DNS MX records should use public IPs"
  description = "For a server to be accessible on the public internet, it needs a public DNS record, and its IP address needs to be reachable on the internet."
  severity    = "low"

  sql = <<-EOT
    with domain_list as (
      select distinct domain from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[]))) order by domain
    ),
    domain_mx_records as (
      select domain, target from net_dns_record where domain in (select domain from domain_list) and type = 'MX' order by domain
    ),
    mx_ips as (
      select * from net_dns_record where domain in (select target from domain_mx_records) and type = 'A'
    ),
    mx_record_with_ip as (
      select
        domain_mx_records.domain,
        domain_mx_records.target,
        mx_ips.ip,
        (mx_ips.ip << '10.0.0.0/8'::inet or mx_ips.ip << '100.64.0.0/10'::inet or mx_ips.ip << '172.16.0.0/12'::inet or mx_ips.ip << '192.0.0.0/24'::inet or mx_ips.ip << '192.168.0.0/16'::inet or mx_ips.ip << '198.18.0.0/15'::inet) as is_private
      from
        domain_mx_records
        inner join mx_ips on domain_mx_records.target = mx_ips.domain
    ),
    mx_record_with_private_ip as (
      select distinct domain from mx_record_with_ip where is_private
    )
    select
      domain_list.domain as resource,
      case
        when mx_record_with_private_ip.domain is null then 'ok'
        else 'alarm'
      end as status,
      case
        when mx_record_with_private_ip.domain is null then 'All MX records in ' || domain_list.domain || ' appear to use public IPs.'
        else domain_list.domain || ' has MX records using private IPs [' || (select host(ip) from mx_record_with_ip where domain = domain_list.domain and is_private) || '].'
      end as reason
    from
      domain_list
      left join mx_record_with_private_ip on domain_list.domain = mx_record_with_private_ip.domain;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_mx_not_contain_ip" {
  title       = "DNS MX records should not contain IP address"
  description = "As per RFC 1035, the MX record must point to a host which itself can be resolved in the DNS. An IP address could not be used as it would be interpreted as an unqualified domain name, which cannot be resolved."
  severity    = "low"

  sql = <<-EOT
    with mx_record_with_ip as (
      select
        domain,
        count(*)
      from
        net_dns_record
      where
        domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
        and type = 'MX'
        and (select target ~ '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
      group by domain
    ),
    domain_list as (
      select distinct domain from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
    )
    select
      d.domain as resource,
      case
        when i.domain is null then 'ok'
        else 'alarm'
      end as status,
      case
        when i.domain is null then d.domain || ' MX records doesn''t contain IP address.'
        else 'At least 1 MX record in ' || d.domain || ' contain IP address.'
      end as reason
    from
      domain_list as d
      left join mx_record_with_ip as i on d.domain = i.domain;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_mx_at_least_two" {
  title       = "DNS should have at least 2 MX records"
  description = "It is recommended to have at least 2 MX records for your domain to provide some load balancing by using multiple MX records with the same preference set, as well as provide a backup MX that can be used if the primary one is unavailable."
  severity    = "low"

  sql = <<-EOT
    select
      domain as resource,
      case
        when count(*) < 2 then 'alarm'
        else 'ok'
      end as status,
      domain || ' has ' || count(*) || ' MX record(s).' as reason
    from
      net_dns_record
    where
      domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      and type = 'MX'
    group by
      domain,
      type;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_mx_no_duplicate_a_record" {
  title       = "DNS MX records should not have duplicate A records"
  description = "It is recommended that MX records should not use same IPs, since if the server with IP x.x.x.x shuts down the MX service will still be able to work since it has another backup server."
  severity    = "low"

  sql = <<-EOT
    with domain_mx_records as (
      select * from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[]))) and type = 'MX'
    ),
    mx_count_by_domain as (
      select domain, count(*) from domain_mx_records group by domain
    ),
    mx_ips as (
      select * from net_dns_record where domain in (select target from domain_mx_records)
    ),
    mx_with_public_ips as (
      select
        domain_mx_records.domain,
        count(*) as ip_usage_count
      from
        domain_mx_records
        inner join mx_ips on domain_mx_records.target = mx_ips.domain
      where
        mx_ips.type = 'A'
      group by domain_mx_records.domain, mx_ips.ip
    ),
    mx_with_public_ips_count as (
      select domain, count(*) from mx_with_public_ips where ip_usage_count > 1 group by domain
    )
    select
      d.domain as resource,
      case
        when p.domain is null then 'ok'
        else 'alarm'
      end as status,
      case
        when p.domain is null then d.domain || ' MX records not using duplicate IPs.'
        else d.domain || ' MX records using duplicate IPs.'
      end as reason
    from
      mx_count_by_domain as d
      left join mx_with_public_ips_count as p on d.domain = p.domain;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

control "dns_mx_reverse_a_record" {
  title       = "DNS MX records should have reverse A record (PTR)"
  description = "A PTR record is reverse version of an A record. In general A record maps a domain name to an IP address, but PTR record maps IP address to a hostname. It is recommended to use PTR record when using both internal or external mail servers. It allows the receiving end to check the hostname of your IP address."
  severity    = "high"

  sql = <<-EOT
    with domain_list as (
      select distinct domain from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
    ),
    domain_mx_records as (
      select domain, target from net_dns_record where domain in (select domain from domain_list) and type = 'MX' order by domain
    ),
    mx_ips as (
      select * from net_dns_record where domain in (select target from domain_mx_records) and type = 'A'
    ),
    mx_record_with_ip as (
      select
        domain_mx_records.domain,
        domain_mx_records.target,
        mx_ips.ip,
        (mx_ips.ip << '10.0.0.0/8'::inet or mx_ips.ip << '100.64.0.0/10'::inet or mx_ips.ip << '172.16.0.0/12'::inet or mx_ips.ip << '192.0.0.0/24'::inet or mx_ips.ip << '192.168.0.0/16'::inet or mx_ips.ip << '198.18.0.0/15'::inet) as is_private
      from
        domain_mx_records
        inner join mx_ips on domain_mx_records.target = mx_ips.domain
    ),
    mx_with_reverse_add as (
      select
        domain,
        target,
        (
          select
            concat(
              array_to_string(array(
                select nums[i] from generate_subscripts(nums, 1) as indices(i) order by i desc
              ), '.'), '.in-addr.arpa'
            ) as reversed
          from (select string_to_array(host(ip), '.') as nums) as data
        ) as reverse
        from
          mx_record_with_ip
    ),
    mx_with_ptr_record_stats as (
      select
        domain,
        case
          when (select count(*) from net_dns_record where domain = mx_with_reverse_add.reverse and type = 'PTR' group by domain) is not null then true
          else false
        end as has_ptr_record,
        reverse as rev_add
      from
        mx_with_reverse_add
    )
    select
      domain as resource,
      case
        when (select count(*) from mx_with_ptr_record_stats where domain = domain_list.domain and not has_ptr_record group by domain) is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when (select count(*) from mx_with_ptr_record_stats where domain = domain_list.domain and not has_ptr_record group by domain) is not null
          then domain || ' has MX records [' || (select string_agg(rev_add, ', ') from mx_with_ptr_record_stats where domain = domain_list.domain and not has_ptr_record)
            || E'] \n with no reverse DNS (PTR) entries.'
        else domain || ' has PTR records for all MX records.'
      end as reason
    from
      domain_list;
  EOT

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}
