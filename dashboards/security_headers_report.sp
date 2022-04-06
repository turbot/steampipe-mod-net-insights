# TODO::Use same variable name as default spvars
variable "url_input" {
  type        = list(string)
  description = "The website URL."
  default     = ["https://microsoft.com", "https://turbot.com", "https://steampipe.io"]
}

dashboard "security_headers_report" {

  title = "Security Headers Report"

  input "site_url" {
    title = "Select an address:"
    width = 4
    query = query.security_headers_url_input
  }

  container {
    width = 12

    card {
      width = 2

      query = query.security_headers_x_content_type_options_check
      args = {
        site_url = self.input.site_url.value
      }
    }

    card {
      width = 2

      query = query.security_headers_strict_transport_security_check
      args = {
        site_url = self.input.site_url.value
      }
    }

    card {
      width = 2

      query = query.security_headers_x_frame_options_check
      args = {
        site_url = self.input.site_url.value
      }
    }

    card {
      width = 2

      query = query.security_headers_permissions_policy_check
      args = {
        site_url = self.input.site_url.value
      }
    }

    card {
      width = 2

      query = query.security_headers_content_security_policy_check
      args = {
        site_url = self.input.site_url.value
      }
    }

    card {
      width = 2

      query = query.security_headers_referrer_policy_check
      args = {
        site_url = self.input.site_url.value
      }
    }
  }

  container {

    table {
      title = "Raw Headers"
      width = 6
      query = query.security_headers_raw_header_list
      args  = {
        site_url = self.input.site_url.value
      }
    }

    table {
      title = "Missing Headers"
      width = 6
      query = query.security_headers_missing_headers
      args  = {
        site_url = self.input.site_url.value
      }

      column "Description" {
        wrap = "all"
      }
    }
  }
}

query "security_headers_url_input" {
  sql = <<-EOQ
    select
      url as label,
      url as value
    from
      jsonb_array_elements_text(to_jsonb($1::text[])) as url
  EOQ

  param "url_input" {
    description = "The website URL."
    default     = var.url_input
  }
}

# Raw headers
query "security_headers_raw_header_list" {
  sql = <<-EOQ
    select
      header.key as "Header",
      (select string_agg(val, ',') from jsonb_array_elements_text(header.value) as val) as "Value"
    from
      net_web_request,
      jsonb_each(response_headers) as header
    where
      url = $1;
  EOQ

  param "site_url" {}
}

# Missing headers
query "security_headers_missing_headers" {
  sql = <<-EOQ
    with available_headers as (
      select
        array_agg(header.key)
      from
        net_web_request,
        jsonb_each(response_headers) as header
      where
        url = $1
    ),
    missing_headers as (
      select
        element
      from (
        select unnest(array['Strict-Transport-Security','Content-Security-Policy','X-Frame-Options','X-Content-Type-Options','Referrer-Policy','Permissions-Policy'])
        except
        select unnest(array_agg) from available_headers
      ) t (element)
    )
    select
      element as "Header",
      case
        when element = 'X-Content-Type-Options' then 'X-Content-Type-Options stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. The only valid value for this header is "X-Content-Type-Options: nosniff".'
        when element = 'Strict-Transport-Security' then 'HTTP Strict Transport Security is an excellent feature to support on your site and strengthens your implementation of TLS by getting the User Agent to enforce the use of HTTPS. Recommended value "Strict-Transport-Security: max-age=31536000; includeSubDomains".'
        when element = 'X-Frame-Options' then 'X-Frame-Options tells the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking. Recommended value "X-Frame-Options: SAMEORIGIN".'
        when element = 'Permissions-Policy' then 'Permissions Policy is a new header that allows a site to control which features and APIs can be used in the browser.'
        when element = 'Content-Security-Policy' then 'Content Security Policy is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets.'
        when element = 'Referrer-Policy' then 'Referrer Policy is a new header that allows a site to control how much information the browser includes with navigations away from a document and should be set by all sites.'
      end as "Description"
    from
      missing_headers;
  EOQ

  param "site_url" {}
}

# Cards
query "security_headers_strict_transport_security_check" {
  sql = <<-EOQ
    select
      case
        when response_headers -> 'Strict-Transport-Security' is not null then 'Present'
        else 'Missing'
      end as value,
      case
        when response_headers -> 'Strict-Transport-Security' is not null then 'ok'
        else 'alert'
      end as type,
      'Strict-Transport-Security' as label
    from
      net_web_request
    where
      url = $1;
  EOQ

  param "site_url" {}
}

query "security_headers_content_security_policy_check" {
  sql = <<-EOQ
    select
      case
        when response_headers -> 'Content-Security-Policy' is not null then 'Present'
        else 'Missing'
      end as value,
      case
        when response_headers -> 'Content-Security-Policy' is not null then 'ok'
        else 'alert'
      end as type,
      'Content-Security-Policy' as label
    from
      net_web_request
    where
      url = $1;
  EOQ

  param "site_url" {}
}

query "security_headers_x_frame_options_check" {
  sql = <<-EOQ
    select
      case
        when response_headers -> 'X-Frame-Options' is not null then 'Present'
        else 'Missing'
      end as value,
      case
        when response_headers -> 'X-Frame-Options' is not null then 'ok'
        else 'alert'
      end as type,
      'X-Frame-Options' as label
    from
      net_web_request
    where
      url = $1;
  EOQ

  param "site_url" {}
}

query "security_headers_x_content_type_options_check" {
  sql = <<-EOQ
    select
      case
        when response_headers -> 'X-Content-Type-Options' is not null then 'Present'
        else 'Missing'
      end as value,
      case
        when response_headers -> 'X-Content-Type-Options' is not null then 'ok'
        else 'alert'
      end as type,
      'X-Content-Type-Options' as label
    from
      net_web_request
    where
      url = $1;
  EOQ

  param "site_url" {}
}

query "security_headers_referrer_policy_check" {
  sql = <<-EOQ
    select
      case
        when response_headers -> 'Referrer-Policy' is not null then 'Present'
        else 'Missing'
      end as value,
      case
        when response_headers -> 'Referrer-Policy' is not null then 'ok'
        else 'alert'
      end as type,
      'Referrer-Policy' as label
    from
      net_web_request
    where
      url = $1;
  EOQ

  param "site_url" {}
}

query "security_headers_permissions_policy_check" {
  sql = <<-EOQ
    select
      case
        when response_headers -> 'Permissions-Policy' is not null then 'Present'
        else 'Missing'
      end as value,
      case
        when response_headers -> 'Permissions-Policy' is not null then 'ok'
        else 'alert'
      end as type,
      'Permissions-Policy' as label
    from
      net_web_request
    where
      url = $1;
  EOQ

  param "site_url" {}
}
