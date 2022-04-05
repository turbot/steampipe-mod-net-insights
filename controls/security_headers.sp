variable "site_url" {
  type        = list(string)
  description = "The website URL."
  default     = [ "https://steampipe.io/", "https://turbot.com" ]
}

locals {
  security_headers_common_tags = {
    plugin = "net"
  }
}

benchmark "security_headers" {
  title         = "Security Headers Checks"
  description   = "Security headers are directives used by web applications to configure security defenses in web browsers. Based on these directives, browsers can make it harder to exploit client-side vulnerabilities such as Cross-Site Scripting or Clickjacking."
  documentation = file("./controls/docs/security_headers_overview.md")
  tags          = local.security_headers_common_tags
  children = [
    control.security_headers_strict_transport_security,
    control.security_headers_content_security_policy,
    control.security_headers_x_frame_options,
    control.security_headers_x_content_type_options,
    control.security_headers_referrer_policy,
    control.security_headers_permissions_policy
  ]
}

control "security_headers_strict_transport_security" {
  title         = "Site headers must contain Strict-Transport-Security"
  description   = "HTTP Strict Transport Security is an excellent feature to support on your site and strengthens your implementation of TLS by getting the User Agent to enforce the use of HTTPS."
  documentation = file("./controls/docs/security_headers_strict_transport_security.md")
  severity      = "low"

  sql = <<-EOT
    with available_headers as (
      select
        url,
        array_agg(header.key)
      from
        net_request,
        jsonb_each(headers) as header
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
        else url || ' has missing required headers ''Strict-Transport-Security''.'
      end as reason
    from
      available_headers;
  EOT

  param "site_url" {
    description = "The website URL."
    default     = var.site_url
  }
}

control "security_headers_content_security_policy" {
  title         = "Site headers must contain Content-Security-Policy"
  description   = "Content Security Policy is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets. Analyse this policy in more detail. You can sign up for a free account on Report URI to collect reports about problems on your site."
  documentation = file("./controls/docs/security_headers_content_security_policy.md")
  severity      = "low"

  sql = <<-EOT
    with available_headers as (
      select
        url,
        array_agg(header.key)
      from
        net_request,
        jsonb_each(headers) as header
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
        else url || ' has missing required headers ''Content-Security-Policy''.' 
      end as reason
    from
      available_headers;
  EOT

  param "site_url" {
    description = "The website URL."
    default     = var.site_url
  }
}

control "security_headers_x_frame_options" {
  title         = "Site headers must contain X-Frame-Options"
  description   = "X-Frame-Options tells the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking."
  documentation = file("./controls/docs/security_headers_x_frame_options.md")
  severity      = "low"

  sql = <<-EOT
    with available_headers as (
      select
        url,
        array_agg(header.key)
      from
        net_request,
        jsonb_each(headers) as header
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
        else url || ' has missing required headers ''X-Frame-Options''.'
      end as reason
    from
      available_headers;
  EOT

  param "site_url" {
    description = "The website URL."
    default     = var.site_url
  }
}

control "security_headers_x_content_type_options" {
  title         = "Site headers must contain X-Content-Type-Options"
  description   = "X-Content-Type-Options stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. The only valid value for this header is \"X-Content-Type-Options: nosniff\"."
  documentation = file("./controls/docs/security_headers_x_content_type_options.md")
  severity      = "low"

  sql = <<-EOT
    with available_headers as (
      select
        url,
        array_agg(header.key)
      from
        net_request,
        jsonb_each(headers) as header
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
        else url || ' has missing required headers ''X-Content-Type-Options''.'
      end as reason
    from
      available_headers;
  EOT

  param "site_url" {
    description = "The website URL."
    default     = var.site_url
  }
}

control "security_headers_referrer_policy" {
  title         = "Site headers must contain Referrer-Policy"
  description   = "Referrer Policy is a new header that allows a site to control how much information the browser includes with navigations away from a document and should be set by all sites."
  documentation = file("./controls/docs/security_headers_referrer_policy.md")
  severity      = "low"

  sql = <<-EOT
    with available_headers as (
      select
        url,
        array_agg(header.key)
      from
        net_request,
        jsonb_each(headers) as header
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
        else url || ' has missing required headers ''Referrer-Policy''.'
      end as reason
    from
      available_headers;
  EOT

  param "site_url" {
    description = "The website URL."
    default     = var.site_url
  }
}

control "security_headers_permissions_policy" {
  title         = "Site headers must contain Permissions-Policy"
  description   = "Permissions Policy is a new header that allows a site to control which features and APIs can be used in the browser."
  documentation = file("./controls/docs/security_headers_permissions_policy.md")
  severity      = "low"

  sql = <<-EOT
    with available_headers as (
      select
        url,
        array_agg(header.key)
      from
        net_request,
        jsonb_each(headers) as header
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
        else url || ' has missing required headers ''Permissions-Policy''.'
      end as reason
    from
      available_headers;
  EOT

  param "site_url" {
    description = "The website URL."
    default     = var.site_url
  }
}
