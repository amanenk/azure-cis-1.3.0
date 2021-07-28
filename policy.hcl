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

//    view "azure_security_policy_parameters" {
//      description = "GCP Log Metric Filter and Alarm"
//      query "azure_security_policy_parameters" {
//        query = file("policy_assignment_parameters.sql")
//      }
//    }

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
        SELECT subscription_id , id AS database_id, transparent_data_encryption -> 'properties' ->> 'status' AS encryption_status
        FROM azure_sql_databases asd
        WHERE transparent_data_encryption -> 'properties' ->> 'status' != 'Enabled';
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
        SELECT s.id AS server_id, s."name" AS server_name, d."name" AS database_name, p.state AS policy_state
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
        SELECT s.id AS server_id, s."name" AS server_name , a."name" AS assesment_id
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments a ON
        s.cq_id = a.server_cq_id
        WHERE a.storage_container_path IS NULL OR a.storage_container_path = ''
    EOF
    }


    query "4.2.3" {
      description = "Azure CIS 4.2.3 Ensure that VA setting Periodic Recurring Scans is enabled on a SQL server (Automated)"
      query = <<EOF
        SELECT s.id AS server_id, s."name" AS server_name , a."name" AS assesment_id
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
        GROUP BY id) SELECT s.id AS server_id, s."name" AS server_name, sv."name" AS assesment_name, c.emails_number AS emails
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
        SELECT s.id AS server_id, s."name" AS server_name , a."name" AS assesment_id
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments a ON
        s.cq_id = a.server_cq_id
        WHERE a.recurring_scans_email_subscription_admins IS NULL
        OR a.recurring_scans_email_subscription_admins != TRUE;
    EOF
    }


  }

  policy "aws-cis-section-5" {
    description = "Azure CIS Section 5"

  }

  policy "aws-cis-section-6" {
    description = "Azure CIS Section 6"

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