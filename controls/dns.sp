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
    control.ns_all_with_type_a_record
  ]
}

control "dns_record_found" {
  title       = "DNS record must be present"
  description = "The record must be present for a domain."
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

control "ns_all_with_type_a_record" {
  title       = "Every name server listed must have A records"
  description = "It is recommended that every name server listed in parent should have A record."
  severity    = "high"

  sql = <<-EOT
    with domain_ns_records as (
      select
        *
      from
        net_dns_record
      where
        domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
        and type = 'NS'
    ),
    ns_ips as (
      select
        *
      from
        net_dns_record
      where
        domain in (select target from domain_ns_records)
    ),
    ns_with_type_a_record as (
      select
        domain_ns_records.domain,
        ns_ips.type,
        domain_ns_records.target,
        ns_ips.ip
      from
        domain_ns_records
        left join ns_ips on domain_ns_records.target = ns_ips.domain
      where
        ns_ips.type = 'A'
    )
    select
      dn.domain as resource,
      case
        when nsa.ip is null then 'alarm'
        else 'ok'
      end as status,
      case
        when nsa.ip is null then dn.domain || ' Name Server ' || nsa.target || ' doesn''t have ''A'' record.'
        else dn.domain || ' Name Server ' || nsa.target || ' has ''A'' record.'
      end as reason
    from
      domain_ns_records as dn
      left join ns_with_type_a_record as nsa on dn.target = nsa.target;
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
    control.dns_ns_on_different_subnets
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
  severity    = "low"

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
        when nic.count = pow(nc.count, 2) then nc.domain || ' NS records are the same at the parent and at your name servers.'
        else nc.domain || ' has at least 1 name server that doesn''t return same records compared to parent record.'
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
    control.dns_mx_all_ip_public,
    control.dns_mx_not_contain_ip,
    control.dns_mx_at_least_two,
    control.dns_mx_no_duplicate_a_record
  ]
}

control "dns_mx_all_ip_public" {
  title       = "DNS MX records should use public IPs"
  description = "For a server to be accessible on the public internet, it needs a public DNS record, and its IP address needs to be reachable on the internet."
  severity    = "low"

  sql = <<-EOT
    with domain_mx_records as (
      select * from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[]))) and type = 'MX'
    ),
    domain_mx_count as (
      select domain, count(*) from net_dns_record where domain in (select jsonb_array_elements_text(to_jsonb($1::text[]))) and type = 'MX' group by domain
    ),
    mx_ips as (
      select * from net_dns_record where domain in (select target from domain_mx_records) and type = 'A'
    ),
    mx_with_public_ips as (
      select
        domain_mx_records.domain,
        domain_mx_records.target,
        count(*)
      from
        domain_mx_records
        inner join mx_ips on domain_mx_records.target = mx_ips.domain
      group by domain_mx_records.domain, domain_mx_records.target
    ),
    mx_with_public_ips_count as (
      select domain, count(*) from mx_with_public_ips where count > 0 group by domain
    )
    select
      d.domain as resource,
      case
        when d.count = p.count then 'ok'
        else 'alarm'
      end as status,
      case
        when d.count = p.count then 'All MX records in ' || d.domain || ' appear to use public IPs.'
        else 'All MX records in ' || d.domain || ' not using public IPs.'
      end as reason
    from
      domain_mx_count as d
      left join mx_with_public_ips_count as p on d.domain = p.domain;
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
