locals {
  security_headers_best_practices_common_tags = merge(local.net_insights_common_tags, {
    service = "Net/HTTP"
  })
}

benchmark "security_headers_best_practices" {
  title         = "Security Headers Best Practices"
  description   = "Best practices to check for various HTTP response headers that help to protect your website from some common attacks."
  documentation = file("./controls/docs/security_headers_overview.md")

  children = [
    control.security_headers_strict_transport_security,
    control.security_headers_content_security_policy,
    control.security_headers_x_frame_options,
    control.security_headers_x_content_type_options,
    control.security_headers_referrer_policy,
    control.security_headers_permissions_policy
  ]

  tags = merge(local.security_headers_best_practices_common_tags, {
    type = "Benchmark"
  })
}

control "security_headers_strict_transport_security" {
  title         = "Site headers must contain Strict-Transport-Security"
  description   = "The HTTP Strict-Transport-Security (HSTS) response header helps to strengthens your TLS implementation by informing the browser that the site should only be accessed using HTTPS, and any further attempts to access the site using HTTP should automatically redirect to HTTPS. These countermeasures help prevent Man-in-the-middle attacks as well as other attacks such as Session Hijacking."

  sql = <<-EOT
    with available_headers as (
      select
        url,
        array_agg(header.key)
      from
        net_http_request,
        jsonb_each(response_headers) as header
      where
        url in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      group by url
    )
    select
      url as resource,
      case
        when array['Strict-Transport-Security'] <@ array_agg then 'ok'
        else 'alarm'
      end as status,
      case
        when array['Strict-Transport-Security'] <@ array_agg then url || ' contains required headers ''Strict-Transport-Security''.'
        else url || ' missing required headers ''Strict-Transport-Security''.'
      end as reason
    from
      available_headers;
  EOT

  param "website_urls" {
    description = "Website URLs."
    default     = var.website_urls
  }
}

control "security_headers_content_security_policy" {
  title       = "Site headers must contain Content-Security-Policy"
  description = "The Content Security Policy (CSP) response header includes a comprehensive set of directives that help prevent client-side attacks, such as Cross-Site Scripting and Clickjacking, by restricting the type of content the browser is allowed to include or execute."

  sql = <<-EOT
    with available_headers as (
      select
        url,
        array_agg(header.key)
      from
        net_http_request,
        jsonb_each(response_headers) as header
      where
        url in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      group by url
    )
    select
      url as resource,
      case
        when array['Content-Security-Policy'] <@ array_agg then 'ok'
        else 'alarm'
      end as status,
      case
        when array['Content-Security-Policy'] <@ array_agg then url || ' contains required headers ''Content-Security-Policy''.'
        else url || ' missing required headers ''Content-Security-Policy''.'
      end as reason
    from
      available_headers;
  EOT

  param "website_urls" {
    description = "Website URLs."
    default     = var.website_urls
  }
}

control "security_headers_x_frame_options" {
  title       = "Site headers must contain X-Frame-Options"
  description = "X-Frame-Options header helps to prevent Clickjacking attacks. The Deep Security Manager enforces the SAMEORIGIN value for this header, only allowing it to be embedded in web applications that are hosted on the same domain."

  sql = <<-EOT
    with available_headers as (
      select
        url,
        array_agg(header.key)
      from
        net_http_request,
        jsonb_each(response_headers) as header
      where
        url in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      group by url
    )
    select
      url as resource,
      case
        when array['X-Frame-Options'] <@ array_agg then 'ok'
        else 'alarm'
      end as status,
      case
        when array['X-Frame-Options'] <@ array_agg then url || ' contains required headers ''X-Frame-Options''.'
        else url || ' missing required headers ''X-Frame-Options''.'
      end as reason
    from
      available_headers;
  EOT

  param "website_urls" {
    description = "Website URLs."
    default     = var.website_urls
  }
}

control "security_headers_x_content_type_options" {
  title       = "Site headers must contain X-Content-Type-Options"
  description = "X-Content-Type-Options header with the 'nosniff' value helps protect against mime type sniffing. Mime type sniffing attacks are only effective in specific scenarios where they cause the browser to interpret text or binary content as HTML. For example, if a user uploads an avatar file named xss.html and the web application does not set a Content-type header when serving the image, the browser will try to determine the content type and will likely treat xss.html as an HTML file. The attacker can then direct users to xss.html and conduct a Cross-Site Scripting attack."

  sql = <<-EOT
    with available_headers as (
      select
        url,
        array_agg(header.key)
      from
        net_http_request,
        jsonb_each(response_headers) as header
      where
        url in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      group by url
    )
    select
      url as resource,
      case
        when array['X-Content-Type-Options'] <@ array_agg then 'ok'
        else 'alarm'
      end as status,
      case
        when array['X-Content-Type-Options'] <@ array_agg then url || ' contains required headers ''X-Content-Type-Options''.'
        else url || ' missing required headers ''X-Content-Type-Options''.'
      end as reason
    from
      available_headers;
  EOT

  param "website_urls" {
    description = "Website URLs."
    default     = var.website_urls
  }
}

control "security_headers_referrer_policy" {
  title       = "Site headers must contain Referrer-Policy"
  description = "The Referrer Policy HTTP header sets the parameter for amount of information sent along with Referrer Header while making a request. Referrer policy is used to maintain the security and privacy of source account while fetching resources or performing navigation. This is done by modifying the algorithm used to populate Referrer Header."

  sql = <<-EOT
    with available_headers as (
      select
        url,
        array_agg(header.key)
      from
        net_http_request,
        jsonb_each(response_headers) as header
      where
        url in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      group by url
    )
    select
      url as resource,
      case
        when array['Referrer-Policy'] <@ array_agg then 'ok'
        else 'alarm'
      end as status,
      case
        when array['Referrer-Policy'] <@ array_agg then url || ' contains required headers ''Referrer-Policy''.'
        else url || ' missing required headers ''Referrer-Policy''.'
      end as reason
    from
      available_headers;
  EOT

  param "website_urls" {
    description = "Website URLs."
    default     = var.website_urls
  }
}

control "security_headers_permissions_policy" {
  title       = "Site headers must contain Permissions-Policy"
  description = "The Permissions Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Permissions Policy provides a set of standard HTTP headers that allow website owners to limit which features of browsers can be used by the page such as camera, microphone, location, full screen etc."

  sql = <<-EOT
    with available_headers as (
      select
        url,
        array_agg(header.key)
      from
        net_http_request,
        jsonb_each(response_headers) as header
      where
        url in (select jsonb_array_elements_text(to_jsonb($1::text[])))
      group by url
    )
    select
      url as resource,
      case
        when array['Permissions-Policy'] <@ array_agg then 'ok'
        else 'alarm'
      end as status,
      case
        when array['Permissions-Policy'] <@ array_agg then url || ' contains required headers ''Permissions-Policy''.'
        else url || ' missing required headers ''Permissions-Policy''.'
      end as reason
    from
      available_headers;
  EOT

  param "website_urls" {
    description = "Website URLs."
    default     = var.website_urls
  }
}
