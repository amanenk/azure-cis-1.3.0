policy "cis-v1.30" {
  description = "Azure CIS V1.30 Policy"
  configuration {
    provider "azure" {
      version = ">= 0.2.4"
    }
  }

  policy "azure-cis-section-1" {
    description = "Azure CIS Section 1"

  }

  policy "azure-cis-section-2" {
    description = "Azure CIS Section 2"

  }

  policy "azure-cis-section-3" {
    description = "Azure CIS Section 3"

  }

  policy "azure-cis-section-4" {
    description = "Azure CIS Section 4"

    query "4.1.1" {
      description = "Azure CIS 4.1.1 Ensure that 'Auditing' is set to 'On' (Automated)"
      expect_output = true
      query = <<EOF
        SELECT s.subscription_id , s.id AS server_id, s."name" AS server_name, assdbap.state AS auditing_state
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_db_blob_auditing_policies assdbap ON
        s.cq_id = assdbap.server_cq_id
        WHERE assdbap.state != 'Enabled';
    EOF
    }

    query "4.1.2" {
      description = "Azure CIS 4.1.2 Ensure that 'Data encryption' is set to 'On' on a SQL Database (Automated)"
      query = <<EOF
        SELECT s.subscription_id , asd.id AS database_id, asd.transparent_data_encryption -> 'properties' ->> 'status' AS encryption_status
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_databases asd ON
        s.cq_id = asd.server_cq_id
        WHERE asd.transparent_data_encryption -> 'properties' ->> 'status' != 'Enabled';
    EOF
    }

    query "4.1.3" {
      description = "Azure CIS 4.1.3 Ensure that 'Auditing' Retention is 'greater than 90 days' (Automated)"
      query = <<EOF
        SELECT s.subscription_id , s.id AS server_id, s."name" AS server_name, assdbap.retention_days AS auditing_retention_days
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_db_blob_auditing_policies assdbap ON
                s.cq_id = assdbap.server_cq_id
        WHERE assdbap.retention_days < 90;
    EOF
    }

    query "4.2.1" {
      description = "Azure CIS 4.2.1 Ensure that Advanced Threat Protection (ATP) on a SQL server is set to 'Enabled' (Automated)"
      query = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, d."name" AS database_name, p.state AS policy_state
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_databases d ON
        s.cq_id = d.server_cq_id
        LEFT JOIN azure_sql_database_db_threat_detection_policies p ON
        d.cq_id = p.database_cq_id
        WHERE p.state != 'Enabled';
    EOF
    }

    query "4.2.2" {
      description = "Azure CIS 4.2.2 Ensure that Vulnerability Assessment (VA) is enabled on a SQL server by setting a Storage Account (Automated)"
      //experimentally checked and storage_container_path becomes NULL when i disable storage account in assesment policy
      query = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name , a."name" AS assesment_id
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments a ON
        s.cq_id = a.server_cq_id
        WHERE a.storage_container_path IS NULL OR a.storage_container_path = ''
    EOF
    }


    query "4.2.3" {
      description = "Azure CIS 4.2.3 Ensure that VA setting Periodic Recurring Scans is enabled on a SQL server (Automated)"
      query = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name , a."name" AS assesment_id
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments a ON
        s.cq_id = a.server_cq_id
        WHERE a.recurring_scans_is_enabled IS NULL
        OR a.recurring_scans_is_enabled != TRUE;
    EOF
    }

    query "4.2.4" {
      description = "Azure CIS 4.2.4 Ensure that VA setting Send scan reports to is configured for a SQL server (Automated)"
      query = <<EOF
        WITH vulnerability_emails AS (SELECT id, UNNEST(recurring_scans_emails) AS emails
        FROM azure_sql_server_vulnerability_assessments v), emails_count AS (SELECT id, count(emails) AS emails_number
        FROM vulnerability_emails
        GROUP BY id) SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, sv."name" AS assesment_name, c.emails_number AS emails
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments sv ON
        s.cq_id = sv.server_cq_id
        LEFT JOIN emails_count c ON
        sv.id = c.id
        WHERE c.emails_number = 0
        OR c.emails_number IS NULL;
    EOF
    }

    query "4.2.5" {
      description = "Azure CIS 4.2.5 Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server (Automated)"
      query = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name , a."name" AS assesment_id
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments a ON
        s.cq_id = a.server_cq_id
        WHERE a.recurring_scans_email_subscription_admins IS NULL
        OR a.recurring_scans_email_subscription_admins != TRUE;
    EOF
    }

    query "4.3.1" {
      description = "Azure CIS 4.3.1 Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server (Automated)"
      query = <<EOF
        SELECT subscription_id, id AS server_id, "name", ssl_enforcement AS server_name
        FROM azure_postgresql_servers aps
        WHERE ssl_enforcement != 'Enabled'
        OR ssl_enforcement IS NULL;
    EOF
    }

    query "4.3.2" {
      description = "Azure CIS 4.3.2 Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server (Automated)"
      query = <<EOF
        SELECT subscription_id, id AS server_id, "name" AS server_name, ssl_enforcement
        FROM azure_mysql_servers ams
        WHERE ssl_enforcement != 'Enabled'
        OR ssl_enforcement IS NULL;
    EOF
    }

    //todo check if parameter exists
    query "4.3.3" {
      description = "Azure CIS 4.3.3 Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server (Automated)"
      expect_output = true
      query = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'log_checkpoints') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'log_checkpoints' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
        s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value != 'on';
    EOF
    }

    query "4.3.4" {
      description = "Azure CIS 4.3.4 Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server (Automated)"
      expect_output = true
      query = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'log_connections') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'log_connections' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
        s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value != 'on';
    EOF
    }

    query "4.3.5" {
      description = "Azure CIS 4.3.5 Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server (Automated)"
      expect_output = true
      query = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'log_disconnections') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'log_disconnections' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
        s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value != 'on';
    EOF
    }

    query "4.3.6" {
      description = "Azure CIS 4.3.6 Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server (Automated)"
      expect_output = true
      query = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'connection_throttling') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'connection_throttling' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
        s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value != 'on';
    EOF
    }

    query "4.3.7" {
      description = "Azure CIS 4.3.7 Ensure server parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server (Automated)"
      expect_output = true
      query = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                        aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'log_retention_days') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'log_retention_days' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
                s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value::INTEGER < 3;
    EOF
    }

    query "4.3.8" {
      description = "Azure CIS 4.3.8 Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled (Manual)"
      expect_output = true
      //todo it follows the cis but public access can be described in different ways
      query = <<EOF
        SELECT aps.subscription_id, aps.id AS server_id, aps."name" AS server_name, apsfr."name" AS rule_name, apsfr.start_ip_address, apsfr.end_ip_address
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_firewall_rules apsfr ON
        aps.cq_id = apsfr.server_cq_id
        WHERE apsfr."name" = 'AllowAllAzureIps'
        OR (apsfr.start_ip_address = '0.0.0.0'
        AND apsfr.end_ip_address = '0.0.0.0')
    EOF
    }

    query "4.4" {
      description = "Azure CIS 4.4 Ensure that Azure Active Directory Admin is configured (Automated)"
      expect_output = true
      query = <<EOF
        WITH ad_admins_count AS( SELECT ass.cq_id, count(*) AS admins_count
        FROM azure_sql_servers ass
        LEFT JOIN azure_sql_server_admins assa  ON
        ass.cq_id = assa.server_cq_id WHERE assa.administrator_type = 'ActiveDirectory' GROUP BY ass.cq_id,
        assa.administrator_type ) SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, a.admins_count AS "ad_admins_count"
        FROM azure_sql_servers s
        LEFT JOIN ad_admins_count a ON
                s.cq_id = a.cq_id
        WHERE a.admins_count IS NULL
        OR a.admins_count = 0;
    EOF
    }

    query "4.5" {
      description = "Azure CIS 4.5 Ensure SQL server's TDE protector is encrypted with Customer-managed key (Automated)"
      expect_output = true
      query = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, p.kind AS protector_kind
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_encryption_protectors p ON
        s.cq_id = p.server_cq_id
        WHERE p.kind != 'azurekeyvault'
        OR p.server_key_type != 'AzureKeyVault'
        OR uri IS NULL;
    EOF
    }
  }

  policy "azure-cis-section-5" {
    description = "Azure CIS Section 5"

  }

  policy "azure-cis-section-6" {
    description = "Azure CIS Section 6"

  }

  policy "azure-cis-section-7" {
    description = "Azure CIS Section 7"

  }

  policy "azure-cis-section-8" {
    description = "Azure CIS Section 8"

  }


  policy "azure-cis-section-9" {
    description = "Azure CIS Section 9"

  }
}