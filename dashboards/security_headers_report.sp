dashboard "security_headers_report" {

  title = "Security Headers Report"

  input "site_url_input" {
    title       = "Enter an address:"
    width       = 4
    type        = "text"
    placeholder = "https://example.com"
  }

  container {
    width = 12

    card {
      width = 2

      query = query.security_headers_x_content_type_options_check
      args = {
        site_url_input = self.input.site_url_input.value
      }
    }

    card {
      width = 2

      query = query.security_headers_strict_transport_security_check
      args = {
        site_url_input = self.input.site_url_input.value
      }
    }

    card {
      width = 2

      query = query.security_headers_x_frame_options_check
      args = {
        site_url_input = self.input.site_url_input.value
      }
    }

    card {
      width = 2

      query = query.security_headers_permissions_policy_check
      args = {
        site_url_input = self.input.site_url_input.value
      }
    }

    card {
      width = 2

      query = query.security_headers_content_security_policy_check
      args = {
        site_url_input = self.input.site_url_input.value
      }
    }

    card {
      width = 2

      query = query.security_headers_referrer_policy_check
      args = {
        site_url_input = self.input.site_url_input.value
      }
    }
  }

  container {

    table {
      title = "Raw Headers"
      width = 6
      query = query.security_headers_raw_header_list
      args  = {
        site_url_input = self.input.site_url_input.value
      }

      column "Value" {
        wrap = "all"
      }
    }

    table {
      title = "Missing Headers"
      width = 6
      query = query.security_headers_missing_headers
      args  = {
        site_url_input = self.input.site_url_input.value
      }

      column "Description" {
        wrap = "all"
      }
    }
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

  param "site_url_input" {}
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
        when element = 'X-Content-Type-Options' then 'X-Content-Type-Options header with the ''nosniff'' value helps protect against mime type sniffing. Mime type sniffing attacks are only effective in specific scenarios where they cause the browser to interpret text or binary content as HTML. For example, if a user uploads an avatar file named xss.html and the web application does not set a Content-type header when serving the image, the browser will try to determine the content type and will likely treat xss.html as an HTML file. The attacker can then direct users to xss.html and conduct a Cross-Site Scripting attack.'
        when element = 'Strict-Transport-Security' then 'The HTTP Strict-Transport-Security (HSTS) response header helps to strengthens your TLS implementation by informing the browser that the site should only be accessed using HTTPS, nd any further attempts to access the site using HTTP should automatically redirect to HTTPS. Recommended value "Strict-Transport-Security: max-age=31536000; includeSubDomains".'
        when element = 'X-Frame-Options' then 'X-Frame-Options header helps to prevent Clickjacking attacks. The Deep Security Manager enforces the SAMEORIGIN value for this header, only allowing it to be embedded in web applications that are hosted on the same domain. Recommended value "X-Frame-Options: SAMEORIGIN".'
        when element = 'Permissions-Policy' then 'The Permissions Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Permissions Policy provides a set of standard HTTP headers that allow website owners to limit which features of browsers can be used by the page such as camera, microphone, location, full screen etc.'
        when element = 'Content-Security-Policy' then 'Content Security Policy is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets.'
        when element = 'Referrer-Policy' then 'The Referrer Policy HTTP header sets the parameter for amount of information sent along with Referrer Header while making a request. Referrer policy is used to maintain the security and privacy of source account while fetching resources or performing navigation. This is done by modifying the algorithm used to populate Referrer Header.'
      end as "Description"
    from
      missing_headers;
  EOQ

  param "site_url_input" {}
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

  param "site_url_input" {}
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

  param "site_url_input" {}
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

  param "site_url_input" {}
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

  param "site_url_input" {}
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

  param "site_url_input" {}
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

  param "site_url_input" {}
}
