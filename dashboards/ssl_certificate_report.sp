locals {
  ssl_common_tags = {
    service = "Net/SSL"
  }
}

dashboard "ssl_certificate_report" {

  title         = "SSL Certificate Report"
  documentation = file("./dashboards/docs/ssl_certificate_report.md")

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

  # Server Certificate
  container {

    title = "Server Key and Certificate"
    width = 12

    container {

      width = 6

      table {
        type  = "line"
        query = query.ssl_certificate_record
        args  = {
          domain_input = self.input.domain_input.value
        }

        column "Alternative Names" {
          wrap = "all"
        }
      }
    }

    container {

      width = 6

      table {
        query = query.ssl_certificate_report
        args  = {
          domain_input = self.input.domain_input.value
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

  # Chains
  container {

    title = "Additional Certificates"
    width = 12

    container {
      width = 12
      table {
        query = query.ssl_additional_certificate_record
        args  = {
          domain_input = self.input.domain_input.value
        }
      }
    }
  }
}

query "ssl_certificate_record" {
  sql = <<-EOQ
    select
      common_name as "Common Name",
      (select string_agg(alt_name, ', ') from jsonb_array_elements_text(dns_names) as alt_name) as "Alternative Names",
      serial_number as "Serial Number",
      TO_CHAR(not_before, 'Dy, DD Mon YYYY HH24:MI:SS TZ') as "Valid From",
      TO_CHAR(not_after, 'Dy, DD Mon YYYY HH24:MI:SS TZ') || ' (expires in ' || date_trunc('day', age(not_after, now())) || ')' as "Valid Until",
      public_key_algorithm || ' ' || public_key_length || ' bits' as "Key",
      issuer_name as "Issuer",
      signature_algorithm as "Signature Algorithm",
      case
        when revoked then 'Revoked'
        else 'Not Revoked'
      end as "Revocation Status",
      case (select count(*) from net_dns_record where domain = $1 and type = 'CAA')
        when null then 'No'
        when 0 then 'No'
        else 'Yes'
      end as "DNS CAA"
    from
      net_certificate
    where
      domain = $1;
  EOQ

  param "domain_input" {}
}

query "ssl_additional_certificate_record" {
  sql = <<-EOQ
    select
      c ->> 'common_name' as "Common Name",
      TO_CHAR((c ->> 'not_before')::timestamp, 'Dy, DD Mon YYYY HH24:MI:SS TZ') as "Valid From",
      TO_CHAR((c ->> 'not_after')::timestamp, 'Dy, DD Mon YYYY HH24:MI:SS TZ') || ' (expires in ' || date_trunc('day', age((c ->> 'not_after')::timestamp, now())) || ')' as "Valid Until",
      c ->> 'public_key_algorithm' || ' ' || (c ->> 'public_key_length')::text || ' bits' as "Key",
      c ->> 'issuer_name' as "Issuer",
      c ->> 'signature_algorithm' as "Signature Algorithm"
    from
      net_certificate,
      jsonb_array_elements(chain) as c
    where
      domain = $1
    order by domain;
  EOQ

  param "domain_input" {}
}

query "ssl_certificate_report" {
  sql = <<-EOQ
  with domain_list as (
    select distinct domain from net_dns_record where domain in ($1) order by domain
  )
  select
    'SSL certificate should be valid' as "Recommendation",
    case
      when now() < not_before then '❌'
      else '✅'
    end as "Status",
    case
      when now() < not_before then 'Certificate is not yet valid.'
      else 'Certificate is valid.'
    end  || ' It is recommended that the certificate is not being used before the time when the certificate is valid from.' as "Result"
  from
    net_certificate
  where
    domain = $1
  UNION
  select
    'SSL certificate should not be expired' as "Recommendation",
    case
      when now() > not_after then '❌'
      else '✅'
    end as "Status",
    case
      when now() > not_after then 'Certificate is expired.'
      else 'Certificate is yet to expire in ' || date_trunc('day', age(not_after, now())) || '.'
    end  || ' SSL certificates ensure secure connections between a server and other web entities and provide validation that a browser is indeed communicating with a validated website server. Once it expires, your website is no longer recognized on the web as safe and secure and it is vulnerable to cyber-attacks.' as "Result"
  from
    net_certificate
  where
    domain = $1
  UNION
  select
    'SSL certificate should not be self-signed' as "Recommendation",
    case
      when common_name = issuer_name then '❌'
      else '✅'
    end as "Status",
    case
      when common_name = issuer_name then 'Certificate is self-signed.'
      else 'Certificate is not self-signed.'
    end  || ' Self-signed certificates contain private and public keys within the same entity, and they cannot be revoked, thus making it difficult to detect security compromises. It is recommended not to use self-signed certificate since it encourage dangerous public browsing behavior.' as "Result"
  from
    net_certificate
  where
    domain = $1
  UNION
  select
    'SSL certificate should not be revoked' as "Recommendation",
    case
      when revoked then '❌'
      else '✅'
    end as "Status",
    case
      when revoked then 'Certificate was revoked.'
      else 'Certificate is not revoked.'
    end  || ' Check for certificate revocation on a server describes if the certificate being used has been revoked by the certificate authority before it was set to expire. It is recommended not to use revoked certificate since they are no longer trustworthy.' as "Result"
  from
    net_certificate
  where
    domain = $1
  UNION
  select
    'SSL certificate should not use insecure certificate algorithms (e.g., MD2, MD5, SHA1)' as "Recommendation",
    case
      when signature_algorithm like any (array['%SHA1%', '%MD2%', '%MD5%']) then '❌'
      else '✅'
    end as "Status",
    'Certificate uses ' || signature_algorithm || ' signature algorithm(s). MD2 and MD5 are part of the Message Digest Algorithm family which was created to verify the integrity of any message or file that is hashed. It has been cryptographically broken which means they are vulnerable to collision attacks and hence considered insecure. Also SHA1 is considered cryptographically weak. It is recommended not to use these insecure signatures.' as "Result"
  from
    net_certificate
  where
    domain = $1
  UNION
  select
    'SSL server should have CAA record for certificate' as "Recommendation",
    case (select count(*) from net_dns_record where domain = $1 and type = 'CAA')
      when null then '❌'
      when 0 then '❌'
      else '✅'
    end as "Status",
    case (select count(*) from net_dns_record where domain = $1 and type = 'CAA')
      when null then 'CAA record not found.'
      when 0 then 'CAA record not found.'
      else 'CAA record found.'
    end
      || ' The CAA record is a type of DNS record used to provide additional confirmation for the Certification Authority (CA) when validating an SSL certificate. With CAA in place, the attack surface for fraudulent certificates is reduced, effectively making sites more secure.' as "Result"
  from
    domain_list
  EOQ

  param "domain_input" {}
}
