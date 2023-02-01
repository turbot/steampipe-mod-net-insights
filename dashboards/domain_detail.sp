locals {
  domain_common_tags = {
    service = "Net/Domain"
  }
}

dashboard "domain_detail" {

  title         = "Domain Detail"
  documentation = file("./dashboards/docs/domain_detail.md")

  tags = merge(local.domain_common_tags, {
    type     = "Detail"
    category = "Networking"
  })

  input "domain_input" {
    title       = "Enter a domain:"
    width       = 4
    type        = "text"
    placeholder = "example.com"
  }

  container {

    graph {
      title = "Relationships"
      type  = "graph"

      node {
        base = node.domain_node
        args = {
          domain_names = [self.input.domain_input.value]
        }
      }

      node {
        base = node.ssl_certificate
        args = {
          domain_names = [self.input.domain_input.value]
        }
      }

      node {
        base = node.tls_version
        args = {
          domain_names = [self.input.domain_input.value]
        }
      }

      node {
        base = node.dns_parent
        args = {
          domain_names = [self.input.domain_input.value]
        }
      }

      node {
        base = node.dns_ns
        args = {
          domain_names = [self.input.domain_input.value]
        }
      }

      node {
        base = node.dns_mx
        args = {
          domain_names = [self.input.domain_input.value]
        }
      }

      edge {
        base = edge.domain_to_ssl_certificate
        args = {
          domain_names = [self.input.domain_input.value]
        }
      }

      edge {
        base = edge.domain_to_tls_version
        args = {
          domain_names = [self.input.domain_input.value]
        }
      }

      edge {
        base = edge.domain_to_dns_parent
        args = {
          domain_names = [self.input.domain_input.value]
        }
      }

      edge {
        base = edge.domain_to_dns_ns
        args = {
          domain_names = [self.input.domain_input.value]
        }
      }

      edge {
        base = edge.domain_to_dns_mx
        args = {
          domain_names = [self.input.domain_input.value]
        }
      }
    }
  }

}

