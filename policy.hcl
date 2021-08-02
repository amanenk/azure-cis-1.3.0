policy "cis-v1.30" {
  description = "Azure CIS V1.30 Policy"
  configuration {
    provider "azure" {
      version = ">= 0.2.4"
    }
  }

  policy "aws-cis-section-1" {
    description = "Azure CIS Section 1"

  }

  policy "aws-cis-section-2" {
    description = "Azure CIS Section 2"

  }

  policy "aws-cis-section-3" {
    description = "Azure CIS Section 3"

  }

  policy "aws-cis-section-4" {
    description = "Azure CIS Section 4"

  }

  policy "aws-cis-section-5" {
    description = "Azure CIS Section 5"

  }

  policy "aws-cis-section-6" {
    description = "Azure CIS Section 6"

    view "azure_nsg_rules" {
      description = "Azure network security groups rules with parsed ports"
      query "azure_nsg_rules_query" {
        query = file("queries/nsg_rules_ports.sql")
      }
    }

    query "6.1" {
      description = "Azure CIS 6.1 Ensure that RDP access is restricted from the internet (Automated)"
      query = <<EOF
      SELECT *
      FROM azure_nsg_rules
      WHERE (source_address_prefix = '*'
          OR source_address_prefix = '0.0.0.0'
          OR source_address_prefix = '<nw>/0'
          OR source_address_prefix = '/0'
          OR source_address_prefix = 'internet'
          OR source_address_prefix = 'any')
      AND (single_port = '3389'
          OR 3389 BETWEEN range_start AND range_end)
      AND protocol = 'Tcp'
      AND "access" = 'Allow'
      AND direction = 'Inbound'
    EOF
    }


    query "6.2" {
      description = "Azure CIS 6.2 Ensure that SSH access is restricted from the internet (Automated)"
      query = <<EOF
      SELECT *
      FROM azure_nsg_rules
      WHERE (source_address_prefix = '*'
          OR source_address_prefix = '0.0.0.0'
          OR source_address_prefix = '<nw>/0'
          OR source_address_prefix = '/0'
          OR source_address_prefix = 'internet'
          OR source_address_prefix = 'any')
      AND protocol = 'Udp'
      AND "access" = 'Allow'
      AND direction = 'Inbound'
      AND (single_port = '22'
          OR 22 BETWEEN range_start AND range_end)
    EOF
    }

    query "6.3" {
      description = "Azure CIS 6.3 Ensure no SQL Databases allow ingress 0.0.0.0/0 (ANY IP) (Automated)"
      //todo think about "other combinations which allows access to wider public IP ranges including Windows Azure IP ranges."
      query = <<EOF
      SELECT ass.id AS server_id, ass."name" AS server_name
      FROM azure_sql_servers ass
      LEFT JOIN
       azure_sql_server_firewall_rules assfr ON
      ass.cq_id = assfr.server_cq_id
      WHERE assfr.start_ip_address = '0.0.0.0'
      OR ( assfr.start_ip_address = '255.255.255.255'
          AND assfr.end_ip_address = '0.0.0.0' );
    EOF
    }

    query "6.4" {
      description = "Azure CIS 6.4 Ensure that Network Security Group Flow Log retention period is 'greater than 90 days' (Automated)"
      query = <<EOF
      SELECT ansg."name" AS nsg_name, ansg.id AS nsg_name, ansgfl.retention_policy_enabled, ansgfl.retention_policy_days
      FROM azure_network_security_groups ansg
      LEFT JOIN azure_network_security_group_flow_logs ansgfl ON
      ansg.cq_id = ansgfl.security_group_cq_id
      WHERE ansgfl.retention_policy_enabled != TRUE
      OR ansgfl.retention_policy_enabled IS NULL
      OR ansgfl.retention_policy_days < 90
      OR ansgfl.retention_policy_days IS NULL;
    EOF
    }

    query "6.5" {
      description = "Azure CIS 6.5 Ensure that Network Watcher is 'Enabled' (Manual)"
      query = file("queries/manual.sql")
    }

    query "6.6" {
      description = "Azure CIS 6.6 Ensure that UDP Services are restricted from the Internet (Automated)"
      query = <<EOF
      SELECT *
      FROM azure_nsg_rules
      WHERE (source_address_prefix = '*'
          OR source_address_prefix = '0.0.0.0'
          OR source_address_prefix = '<nw>/0'
          OR source_address_prefix = '/0'
          OR source_address_prefix = 'internet'
          OR source_address_prefix = 'any')
      AND protocol = 'Udp'
      AND "access" = 'Allow'
      AND direction = 'Inbound'
      AND ((single_port = '53'
          OR 53 BETWEEN range_start AND range_end)
      OR (single_port = '123'
          OR 123 BETWEEN range_start AND range_end)
      OR (single_port = '161'
          OR 161 BETWEEN range_start AND range_end)
      OR (single_port = '389'
          OR 389 BETWEEN range_start AND range_end));
    EOF
    }
  }

  policy "aws-cis-section-7" {
    description = "Azure CIS Section 7"

  }

  policy "aws-cis-section-8" {
    description = "Azure CIS Section 8"

  }


  policy "aws-cis-section-9" {
    description = "Azure CIS Section 9"

  }
}