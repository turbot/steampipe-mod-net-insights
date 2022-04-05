dashboard "dns_report" {

  title = "DNS Report"

  input "domain_name" {
    title = "Select a domain:"
    width = 4
    option "turbot.com" {}
    option "datadog.com" {}
    option "steampipe.io" {}
  }

  container {
    title = "Report"

    table {
      title = "Recommendations"
      width = 8
      query = query.ns_recommendations
      args  = {
        domain_name = self.input.domain_name.value
      }
    }
  }
  
  container {

    title = "Overview"

    table {
      title = "Name Server (NS)"
      width = 6
      query = query.dns_ns_record
      args  = {
        domain_name = self.input.domain_name.value
      }
    }

    table {
      title = "Mail Exchange (MX)"
      width = 6
      query = query.dns_mx_record
      args  = {
        domain_name = self.input.domain_name.value
      }
    }

    table {
      title = "Start of Authority (SOA)"
      type  = "line"
      width = 6
      query = query.dns_soa_record
      args  = {
        domain_name = self.input.domain_name.value
      }
    }
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
      domain_records.type as "Type",
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

  param "domain_name" {}
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

  param "domain_name" {}
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
      domain_records.type as "Type",
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
    order by domain_records.target;
  EOQ

  param "domain_name" {}
}

query "ns_recommendations" {
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
    domain_mx_records as (
      select * from net_dns_record where domain = $1 and type = 'MX'
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
    mx_with_public_ips_count as (
      select domain, count(*) from mx_with_public_ips where count > 0 group by domain
    ),
    mx_record_with_ip as (
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
    )
    select
      'NS' as "Type",
      'Multiple Nameservers' as "Recommendation",
      case
        when count < 2 then 'Failed'
        else 'Passed'
      end as "Status",
      count || ' NS record(s) found.' as "Result"
    from
      domain_ns_count
    UNION
    select
      'NS' as "Type",
      'Name of nameservers are valid' as "Recommendation",
      case
        when r.domain is null or r.count = 0 then 'Passed'
        else 'Failed'
      end as "Status",
      case
        when r.domain is null or r.count = 0 then 'Name servers have valid name format.'
        else 'At least one name server with invalid name format.'
      end as "Result"
    from
      domain_list as d
      left join invalid_ns_count as r on d.domain = r.domain
    UNION
    select
      'NS' as "Type",
      'Missing nameservers reported by parent' as "Recommendation",
      case
        when nic.count = pow(nc.count, 2) then 'Passed'
        else 'Failed'
      end as "Status",
      case
        when nic.count = pow(nc.count, 2) then 'NS records are the same at the parent and at your nameservers.'
        else 'Local NS list does not match parent NS list.'
      end as "Result"
    from
      ns_count as nc,
      ns_individual_count as nic
    where
      nc.domain = nic.domain
    group by nc.domain, nic.count, nc.count
    UNION
    select
      'NS' as "Type",
      'Different subnets' as "Recommendation",
      case
        when count(*) = 1 then 'Failed'
        else 'Passed'
      end as "Status",
      case
        when count(*) = 1 then 'Name servers are on the same subnet.'
        else 'Name servers appear to be dispersed.'
      end as "Result"
    from
      check_ips
    group by domain
    UNION
    select
      'SOA' as "Type",
      'SOA Serial' as "Recommendation",
      case
        when (select serial::text ~ '^\d{4}[0-1]{1}[0-9]{1}[0-3]{1}[0-9]{1}\d{2}$') then 'Passed'
        when serial > 1 or refresh < 4294967295 and not (select serial::text ~ '^\d{4}[0-1]{1}[0-9]{1}[0-3]{1}[0-9]{1}\d{2}$') then 'info'
        else 'Failed'
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
      'SOA' as "Type",
      'SOA Refresh' as "Recommendation",
      case
        when refresh < 1200 or refresh > 43200 then 'Failed'
        else 'Passed'
      end as "Status",
      'SOA Refresh interval is: ' || refresh || '.' as "Result"
    from
      net_dns_record
    where
      domain = $1
      and type = 'SOA'
    UNION
    select
      'SOA' as "Type",
      'SOA Retry' as "Recommendation",
      case
        when retry < 120 or retry > 7200 then 'Failed'
        else 'Passed'
      end as "Status",
      'SOA Retry value is: ' || retry || '.' as "Result"
    from
      net_dns_record
    where
      domain = $1
      and type = 'SOA'
    UNION
    select
      'SOA' as "Type",
      'SOA Expire' as "Recommendation",
      case
        when expire < 1209600 or expire > 2419200 then 'Failed'
        else 'Passed'
      end as "Status",
      'SOA Expire value is: ' || expire || '.' as "Result"
    from
      net_dns_record
    where
      domain = $1
      and type = 'SOA'
    UNION
    select
      'SOA' as "Type",
      'SOA Minimum TTL' as "Recommendation",
      case
        when min_ttl < 600 or min_ttl > 86400 then 'Failed'
        else 'Passed'
      end as "Status",
      'SOA Minimum TTL is: ' || min_ttl || '.' as "Result"
    from
      net_dns_record
    where
      domain = $1
      and type = 'SOA'
    UNION
    select
      'MX' as "Type",
      'Number of MX records' as "Recommendation",
      case
        when count(domain) < 2 then 'Failed'
        else 'Passed'
      end as "Status",
      count(domain) || ' MX record(s) found.' as "Result"
    from
      net_dns_record
    where
      domain = $1
      and type = 'MX'
    UNION
    select
      'MX' as "Type",
      'MX IPs are public' as "Recommendation",
      case
        when d.count = p.count then 'Passed'
        else 'Failed'
      end as "Status",
      case
        when d.count = p.count then 'All MX records appear to use public IPs.'
        else 'At least one MX record not using public IPs.'
      end as "Result"
    from
      domain_mx_count as d
      left join mx_with_public_ips_count as p on d.domain = p.domain
    UNION
    select
      'MX' as "Type",
      'MX is not IP' as "Recommendation",
      case
        when i.domain is null then 'Passed'
        else 'Failed'
      end as "Status",
      case
        when i.domain is null then 'MX records doesn''t contain IP address.'
        else 'At least one MX record contains IP address.'
      end as "Result"
    from
      domain_list as d
      left join mx_record_with_ip as i on d.domain = i.domain
    UNION
    select
      'MX' as "Type",
      'Duplicate MX A records' as "Recommendation",
      case
        when p.domain is null then 'Passed'
        else 'Failed'
      end as "Status",
      case
        when p.domain is null then 'MX records not using duplicate IPs.'
        else 'MX records using duplicate IPs.'
      end as "Result"
    from
      domain_mx_count as d
      left join mx_public_ips_count_by_domain as p on d.domain = p.domain
  EOQ

  param "domain_name" {}
}
