dashboard "dns_records_report" {

  title = "DNS Records Report"

  input "domain_name_input" {
    title = "Select a domain:"
    width = 4
    query = query.dns_domain_input
  }

  # NS
  container {
    
    title = "Name Server (NS)"

    table {
      width = 6
      query = query.dns_ns_record
      args  = {
        domain_name_input = self.input.domain_name_input.value
      }
    }

    table {
      width = 6
      query = query.dns_ns_report
      args  = {
        domain_name_input = self.input.domain_name_input.value
      }
      
      column "Result" {
        wrap = "all"
      }

      column "Recommendation" {
        wrap = "all"
      }
    }
  }

  # SOA
  container {
    
    title = "Start of Authority (SOA)"

    table {
      type  = "line"
      width = 6
      query = query.dns_soa_record
      args  = {
        domain_name_input = self.input.domain_name_input.value
      }
    }

    table {
      width = 6
      query = query.dns_soa_report
      args  = {
        domain_name_input = self.input.domain_name_input.value
      }
      
      column "Result" {
        wrap = "all"
      }

      column "Recommendation" {
        wrap = "all"
      }
    }
  }

  # MX
  container {

    title = "Mail Exchange (MX)"

    table {
      width = 6
      query = query.dns_mx_record
      args  = {
        domain_name_input = self.input.domain_name_input.value
      }
    }

    table {
      width = 6
      query = query.dns_mx_report
      args  = {
        domain_name_input = self.input.domain_name_input.value
      }
      
      column "Result" {
        wrap = "all"
      }

      column "Recommendation" {
        wrap = "all"
      }
    }
  }
}

query "dns_domain_input" {
  sql = <<-EOQ
    select
      domain as label,
      domain as value
    from
      jsonb_array_elements_text(to_jsonb($1::text[])) as domain
  EOQ

  param "domain_name" {
    description = "The website URL."
    default     = var.domain_name
  }
}

query "dns_ns_record" {
  sql = <<-EOQ
    with domain_records as (
      select * from net_dns_record where domain = $1 and type = 'NS' order by domain
    ),
    ns_ips as (
      select domain, ip, type, target, host(ip) as ip_text from net_dns_record where domain in (select target from domain_records) and type = 'A' order by domain
    )
    select
      domain_records.target as "Domain",
      ns_ips.ip as "IP Address",
      domain_records.ttl as "TTL",
      case
        when (select count(*) from net_dns_record where domain = $1 and dns_server = ns_ips.ip_text group by domain) is not null then 'Responding'
        else 'Not Responding'
      end as "Status", 
      (select count(*) from net_dns_record where domain = $1 and dns_server = ns_ips.ip_text and type = 'SOA' group by domain) is not null as "Authoritative"
    from
      domain_records
      inner join ns_ips on domain_records.target = ns_ips.domain
    where
      ns_ips.type = 'A'
      and domain_records.type = 'NS'
    order by domain_records.target;
  EOQ

  param "domain_name_input" {}
}

query "dns_soa_record" {
  sql = <<-EOQ
    select
      target as "Primary Name Server:",
      mbox as "	Responsible Email:",
      serial as "Serial Number:",
      refresh as "Refresh:",
      retry as "Retry:",
      expire as "Expire:",
      min_ttl as "Default TTL:"
    from
      net_dns_record
    where
      domain = $1
      and type = 'SOA'
    order by target;
  EOQ

  param "domain_name_input" {}
}

query "dns_mx_record" {
  sql = <<-EOQ
    with domain_records as (
      select * from net_dns_record where domain = $1 and type = 'MX'
    ),
    ns_ips as (
      select * from net_dns_record where domain in (select target from domain_records)
    )
    select
      domain_records.priority as "Priority",
      domain_records.target as "Domain",
      ns_ips.ip as "IP Address",
      ns_ips.ttl as "TTL"
    from
      domain_records
      inner join ns_ips on domain_records.target = ns_ips.domain
    where
      ns_ips.type = 'A'
      and domain_records.type = 'MX'
    order by domain_records.priority;
  EOQ

  param "domain_name_input" {}
}

query "dns_ns_report" {
  sql = <<-EOQ
    with domain_ns_count as (
      select count(*) from net_dns_record where domain = $1 and type = 'NS' group by domain
    ),
    domain_ns_records as (
      select * from net_dns_record where domain in ($1) and type = 'NS'
    ),
    ns_ips as (
      select * from net_dns_record where domain in (select target from domain_ns_records)
    ),
    ns_with_ip as (
      select domain_ns_records.domain, host(ns_ips.ip) as ip_text from domain_ns_records inner join ns_ips on domain_ns_records.target = ns_ips.domain where ns_ips.type = 'A' order by domain_ns_records.domain
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
      select domain, count(*) from net_dns_record where domain in ($1) and type = 'NS' group by domain
    ),
    invalid_ns_count as (
      select
        domain,
        count(*)
      from
        net_dns_record
      where
        domain in ($1)
        and type = 'NS'
        and not target ~ '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\.?$'
      group by domain
    ),
    domain_list as (
      select distinct domain from net_dns_record where domain in ($1)
    ),
    check_ips as (
      select
        distinct array_to_string(array_remove(string_to_array(text(ns_ips.ip), '.'), split_part(text(ns_ips.ip), '.', 4)), '.'),
        domain_ns_records.domain as domain
      from
        domain_ns_records
        inner join ns_ips on domain_ns_records.target = ns_ips.domain
      where
        ns_ips.type = 'A'
        and domain_ns_records.type = 'NS'
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
      'Multiple name servers' as "Recommendation",
      case
        when count < 2 then '❌'
        else '✅'
      end as "Status",
      count || ' NS record(s) found. As per RFC2182 section 5 domain record must have at least 3 name servers, and no more than 7.' as "Result"
    from
      domain_ns_count
    UNION
    select
      'Name of name servers are valid' as "Recommendation",
      case
        when r.domain is null or r.count = 0 then '✅'
        else '❌'
      end as "Status",
      case
        when r.domain is null or r.count = 0 then 'Name servers have valid name format.'
        else 'At least one name server with invalid name format.'
      end 
        || ' The names can contain only alphabetical characters (A-Z), numeric characters (0-9), the minus sign (-), and the period (.). Period characters are allowed only when they are used to delimit the components of domain style names.' as "Result"
    from
      domain_list as d
      left join invalid_ns_count as r on d.domain = r.domain
    UNION
    select
      'Missing name servers reported by parent' as "Recommendation",
      case
        when nic.count = pow(nc.count, 2) then '✅'
        else '❌'
      end as "Status",
      case
        when nic.count = pow(nc.count, 2) then 'NS records are the same at the parent and at your name servers.'
        else 'At least 1 name server doesn''t return same records compared to parent record.'
      end
        || ' Unmatched NS records can cause delays when resolving domain records, as it tries to contact a name server that is either non-existent or non-authoritative.' as "Result"
    from
      ns_count as nc,
      ns_individual_count as nic
    where
      nc.domain = nic.domain
    group by nc.domain, nic.count, nc.count
    UNION
    select
      'No CNAME record if an NS (or any other) record is present' as "Recommendation",
      case
        when all_record_count > 0 and (cname_record_count is null or cname_record_count < 1) then '✅'
        when cname_record_count > 0 and all_record_count = cname_record_count then '✅'
        else '❌'
      end as "Status",
      case
        when all_record_count > 0 and (cname_record_count is null or cname_record_count < 1) then 'No CNAME record found.'
        when cname_record_count > 0 and all_record_count = cname_record_count then 'CNAME record(s) [' || (select string_agg(target, ', ') from net_dns_record where domain = count_stats.domain) || '].'
        else domain || ' has CNAME record along with NS (or any other) record.'
      end
        || ' A CNAME record is not allowed to coexist with any other data. This is often attempted by inexperienced administrators as an obvious way to
          allow your domain name to also be a host. However, DNS servers like BIND will see the CNAME and refuse to add any other resources for that name.
          Since no other records are allowed to coexist with a CNAME, the NS entries are ignored.' as "Result"
    from
      count_stats
    UNION
    select
      'Different subnets' as "Recommendation",
      case
        when count(*) = 1 then '❌'
        else '✅'
      end as "Status",
      case
        when count(*) = 1 then 'Name servers are on the same subnet.'
        else 'Name servers appear to be dispersed.'
      end
        || ' As per RFC2182 section 3.1, it is recommended that the secondary servers must be placed at both topologically and
          geographically dispersed locations on the Internet, to minimize the likelihood of a single failure disabling all of them.' as "Result"
    from
      check_ips
    group by domain
    UNION
    select
      'IPs of name servers are public' as "Recommendation",
      case
        when ns_record_with_private_ip.domain is null then '✅'
        else '❌'
      end as "Status",
      case
        when ns_record_with_private_ip.domain is null then 'All NS records appear to use public IPs.'
        else domain_list.domain || ' has NS records using private IPs [' || (select host(ip) from ns_record_with_ip where domain = domain_list.domain and is_private) || '].'
      end
        || ' For a server to be accessible on the public internet, it needs a public DNS record, and its IP address needs to be reachable on the internet.' as "Result"
    from
      domain_list
      left join ns_record_with_private_ip on domain_list.domain = ns_record_with_private_ip.domain
    UNION
    select
      'Different autonomous systems' as "Recommendation",
      case
        when count(*) = 1 then '❌'
        else '✅'
      end as "Status",
      case
        when count(*) = 1 then 'Name servers are in same location.'
        else 'Name servers are located in different location.'
      end
        || ' As per RFC2182 section 3.1, it is recommended that the secondary servers must be placed at both topologically and
          geographically dispersed locations on the Internet, to minimize the likelihood of a single failure disabling all of them.' as "Result"
    from
      check_ips
    group by domain
  EOQ

  param "domain_name_input" {}
}

query "dns_soa_report" {
  sql = <<-EOQ
    with domain_list as (
      select distinct domain from net_dns_record where domain = $1 order by domain
    ),
    domain_ns_records as (
      select * from net_dns_record where domain in (select domain from domain_list) and type = 'NS' order by domain
    ),
    ns_ips as (
      select * from net_dns_record where domain in (select target from domain_ns_records) order by domain
    ),
    ns_with_ip as (
      select domain_ns_records.domain, host(ns_ips.ip) as ip_text from domain_ns_records inner join ns_ips on domain_ns_records.target = ns_ips.domain where ns_ips.type = 'A' order by domain_ns_records.domain
    ),
    unique_serial as (
      select
        distinct r.serial,
        r.domain
      from
        net_dns_record as r
        inner join ns_with_ip as i on r.domain = i.domain and r.dns_server = i.ip_text
      where
        r.type = 'SOA'
    )
    select
      'Name servers have same SOA serial' as "Recommendation",
      case
        when (select count(*) from unique_serial where domain = d.domain) is null or (select count(*) from unique_serial where domain = d.domain) > 1 then '❌'
        else '✅'
      end as "Status",
      case
        when (select count(*) from unique_serial where domain = d.domain) is null or (select count(*) from unique_serial where domain = d.domain) > 1
          then 'At least one name server has different SOA serial.'
        else 'All name servers have same SOA serial.'
      end
        || ' Sometimes serial numbers become out of sync when any record within a zone got updated and the changes are transferred from primary name server to other name servers. If the SOA serial number is not same for all NS record there might be a problem with the transfer.' as "Result"
    from
      domain_list as d
    UNION
    select
      'SOA serial number should be between 1 and 4294967295' as "Recommendation",
      case
        when (select serial::text ~ '^\d{4}[0-1]{1}[0-9]{1}[0-3]{1}[0-9]{1}\d{2}$') then '✅'
        else '❌'
      end as "Status",
      case
        when not (select serial::text ~ '^\d{4}[0-1]{1}[0-9]{1}[0-3]{1}[0-9]{1}\d{2}$') then domain || ' SOA serial number ' || serial || ' doesn''t match recommended format (per RFC1912 2.2) YYYYMMDDnn.'
        else domain || ' SOA serial number is ' || serial || '.'
      end as "Result"
    from
      net_dns_record
    where
      domain = $1
      and type = 'SOA'
    UNION
    select
      'SOA refresh value should be between 20 minutes and 12 hours' as "Recommendation",
      case
        when refresh < 1200 or refresh > 43200 then '❌'
        else '✅'
      end as "Status",
      'SOA Refresh interval is: ' || refresh || '. This value indicates how often a secondary will poll the primary server to see
          if the serial number for the zone has increased (so it knows
          to request a new copy of the data for the zone). As per RFC1912 section 2.2 value should be in between 20 mins to 2 hrs.' as "Result"
    from
      net_dns_record
    where
      domain = $1
      and type = 'SOA'
    UNION
    select
      'SOA retry value should be between 2 minutes and 2 hours' as "Recommendation",
      case
        when retry < 120 or retry > 7200 then '❌'
        else '✅'
      end as "Status",
      'SOA Retry value is: ' || retry || '. If a secondary was unable to contact the primary at the
          last refresh, wait the retry value before trying again. Recommended value is 2 minutes to 2 hours.' as "Result"
    from
      net_dns_record
    where
      domain = $1
      and type = 'SOA'
    UNION
    select
      'SOA expire value should be between 2 weeks and 4 weeks' as "Recommendation",
      case
        when expire < 1209600 or expire > 2419200 then '❌'
        else '✅'
      end as "Status",
      'SOA Expire value is: ' || expire || '. This value indicates how long a secondary will still treat its copy of the zone
          data as valid if it can''t contact the primary. As per RFC1912 section 2.2 value should be in between 2-4 weeks.' as "Result"
    from
      net_dns_record
    where
      domain = $1
      and type = 'SOA'
    UNION
    select
      'SOA minimum TTL value should be between 10 minutes to 24 hours' as "Recommendation",
      case
        when min_ttl < 600 or min_ttl > 86400 then '❌'
        else '✅'
      end as "Status",
      'SOA Minimum TTL is: ' || min_ttl || '. This value was used to serve as a default TTL for records without a given TTL value and now is
        used for negative caching (indicates how long a resolver may cache the negative answer). RFC2308 recommends a value of 1-3 hours.' as "Result"
    from
      net_dns_record
    where
      domain = $1
      and type = 'SOA'
  EOQ

  param "domain_name_input" {}
}

query "dns_mx_report" {
  sql = <<-EOQ
    with domain_mx_records as (
      select * from net_dns_record where domain = $1 and type = 'MX'
    ),
    domain_list as (
      select distinct domain from net_dns_record where domain in ($1)
    ),
    domain_mx_count as (
      select domain, count(*) from domain_mx_records where domain = $1 group by domain
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
    ),
    mx_record_with_ip_count as (
      select
        domain,
        count(*)
      from
        net_dns_record
      where
        domain = $1
        and type = 'MX'
        and (select target ~ '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
      group by domain
    ),
    mx_count_public_ips as (
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
    mx_public_ips_count_by_domain as (
      select domain, count(*) from mx_count_public_ips where ip_usage_count > 1 group by domain
    ),
    mx_records as (
      select domain, rtrim(target, '.') as target, rtrim(target, '.') ~ '^[^.].*[^-_.]$' as is_valid from net_dns_record where domain in (select domain from domain_list) and type = 'MX'
    )
    select
      'MX records valid hostname' as "Recommendation",
      case
        when (select count(*) from mx_records where domain = domain_list.domain and not is_valid) > 0 then '❌'
        else '✅'
      end as "Status",
      case
        when (select count(*) from mx_records where domain = domain_list.domain and not is_valid) > 0 then 'Invalid MX record hostname(s): ' || (select string_agg(target, ', ') from mx_records where domain = domain_list.domain and not is_valid) || '.'
        else 'No MX records have invalid hostname.'
      end
        || ' It is recommended that MX record should have a valid domain or sub domain name and the name not starts or ends with a dot(.).' as "Result"
    from
      domain_list
    UNION
    select
      'Multiple MX records' as "Recommendation",
      case
        when count(domain) < 2 then '❌'
        else '✅'
      end as "Status",
      count(domain) || ' MX record(s) found. It is recommended to use at least 2 MX records so that backup server can receive mail when one server goes down.' as "Result"
    from
      net_dns_record
    where
      domain = $1
      and type = 'MX'
    UNION
    select
      'MX IPs are public' as "Recommendation",
      case
        when mx_record_with_private_ip.domain is null then '✅'
        else '❌'
      end as "Status",
      case
        when mx_record_with_private_ip.domain is null then 'All MX records appear to use public IPs.'
        else domain_list.domain || ' has MX records using private IPs [' || (select host(ip) from mx_record_with_ip where domain = domain_list.domain and is_private) || '].'
      end
        || ' For a server to be accessible on the public internet, it needs a public DNS record, and its IP address needs to be reachable on the internet.' as "Result"
    from
      domain_list
      left join mx_record_with_private_ip on domain_list.domain = mx_record_with_private_ip.domain
    UNION
    select
      'MX is not IP' as "Recommendation",
      case
        when i.domain is null then '✅'
        else '❌'
      end as "Status",
      case
        when i.domain is null then 'MX records doesn''t contain IP address.'
        else 'At least one MX record contains IP address.'
      end
        || ' As per RFC1035 MX record domain name must point to a host which itself can be resolved in the DNS.
          An IP address could not be used as it would be interpreted as an unqualified domain name, which cannot be resolved.' as "Result"
    from
      domain_list as d
      left join mx_record_with_ip_count as i on d.domain = i.domain
    UNION
    select
      'No duplicate MX A records' as "Recommendation",
      case
        when p.domain is null then '✅'
        else '❌'
      end as "Status",
      case
        when p.domain is null then 'MX records not using duplicate IPs.'
        else 'MX records using duplicate IPs.'
      end
        || ' It is recommended to use different IPs for records so that if server goes down, other server can receive mail.' as "Result"
    from
      domain_mx_count as d
      left join mx_public_ips_count_by_domain as p on d.domain = p.domain
  EOQ

  param "domain_name_input" {}
}
