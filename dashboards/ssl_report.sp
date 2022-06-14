# This is created to check the dashboard with combined details of certificates and server configuration
dashboard "ssl_report" {

  title = "SSL Report"

  tags = merge(local.ssl_common_tags, {
    type     = "Report"
    category = "Networking"
  })

  input "domain_name_input" {
    title       = "Enter a domain:"
    width       = 4
    type        = "text"
    placeholder = "example.com"
  }

  # Cards
  container {

    width = 12

    card {
      
      width = 3
      query = query.ssl_server_supported_protocols
      args  = {
        domain_name_input = self.input.domain_name_input.value
      }
    }

    card {
      
      width = 3
      query = query.ssl_server_insecure_cipher_count
      args  = {
        domain_name_input = self.input.domain_name_input.value
      }
    }

    card {
      
      width = 3
      query = query.ssl_server_rc4_cipher_count
      args  = {
        domain_name_input = self.input.domain_name_input.value
      }
    }

    card {
      
      width = 3
      query = query.ssl_server_cbc_cipher_count
      args  = {
        domain_name_input = self.input.domain_name_input.value
      }
    }
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
          domain_name_input = self.input.domain_name_input.value
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

  # Chains
  container {
    title = "Additional Certificates"
    width = 12

    container {
      width = 12
      table {
        #type  = "line"
        query = query.ssl_additional_certificate_record
        args  = {
          domain_name_input = self.input.domain_name_input.value
        }
      }
    }
  }


  # Protocols and Cipher Suites
  container {
    title = "Protocols and Cipher Suites"

    table {

      width = 6
      query = query.ssl_server_supported_cipher_suites

      column "Cipher Suites" {
        wrap = "all"
      }
    }

    table {

      width = 6
      query = query.ssl_server_configuration_checks
        args  = {
        domain_name_input = self.input.domain_name_input.value
      }

      column "Recommendation" {
        wrap = "all"
      }

      column "Result" {
        wrap = "all"
      }
    }
  }
}