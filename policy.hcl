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

    view "azure_security_policy_parameters" {
      description = "GCP Log Metric Filter and Alarm"
      query "azure_security_policy_parameters" {
        query = file("queries/policy_assignment_parameters.sql")
      }
    }

    query "2.1" {
      description = "Azure CIS 2.1 Ensure that Azure Defender is set to On for Servers (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'VirtualMachines'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.2" {
      description = "Azure CIS 2.2 Ensure that Azure Defender is set to On for App Service (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'AppServices'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.3" {
      description = "Azure CIS 2.3 Ensure that Azure Defender is set to On for Azure SQL database servers (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'SqlServers'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.4" {
      description = "Azure CIS 2.4 Ensure that Azure Defender is set to On for SQL servers on machines (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'SqlserverVirtualMachines'
        AND pricing_properties_tier = 'Standard';
    EOF
    }


    query "2.5" {
      description = "Azure CIS 2.5 Ensure that Azure Defender is set to On for Storage (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'StorageAccounts'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.6" {
      description = "Azure CIS 2.6 Ensure that Azure Defender is set to On for Kubernetes (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'KubernetesService'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.7" {
      description = "Azure CIS 2.7 Ensure that Azure Defender is set to On for Container Registries (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'ContainerRegistry'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.8" {
      description = "Azure CIS 2.8 Ensure that Azure Defender is set to On for Key Vault (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'KeyVaults'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.9" {
      description = "Azure CIS 2.9 Ensure that Windows Defender ATP (WDATP) integration with Security Center is selected (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", enabled
        FROM azure_security_settings ass
        WHERE "name" = 'WDATP'
        AND enabled = TRUE;
    EOF
    }

    query "2.10" {
      description = "Azure CIS 2.10 Ensure that Microsoft Cloud App Security (MCAS) integration with Security Center is selected (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", enabled
        FROM azure_security_settings ass
        WHERE "name" = 'MCAS'
        AND enabled = TRUE;
    EOF
    }

    query "2.11" {
      description = "Azure CIS 2.11 Ensure that 'Automatic provisioning of monitoring agent' is set to 'On' (Automated)"
      expect_output = true
      query = <<EOF
        SELECT id, "name"
        FROM azure_security_auto_provisioning_settings asaps
        WHERE "name" = 'default'
        AND auto_provision = 'On';
    EOF
    }

    query "2.11" {
      description = "Azure CIS 2.11 Ensure that 'Automatic provisioning of monitoring agent' is set to 'On' (Automated)"
      expect_output = true
      query = <<EOF
        SELECT id, "name"
        FROM azure_security_auto_provisioning_settings asaps
        WHERE "name" = 'default'
        AND auto_provision = 'On';
    EOF
    }

    query "2.12" {
      description = "Azure CIS 2.12 Ensure any of the ASC Default policy setting is not set to \"Disabled\" (Manual)"
      query = <<EOF
        SELECT *
        FROM azure_security_policy_parameters
        WHERE value = 'Disabled';
    EOF
    }

    query "2.13" {
      description = "Azure CIS 2.13 Ensure 'Additional email addresses' is configured with a security contact email (Automated)"
      //email should be valid so if there is even not valid email it will pass
      expect_output = true
      query = <<EOF
        SELECT subscription_id, id, email
        FROM azure_security_contacts
        WHERE email IS NOT NULL
        AND email != '';
    EOF
    }

    query "2.14" {
      description = "Azure CIS 2.14 Ensure that 'Notify about alerts with the following severity' is set to 'High' (Automated)"
      expect_output = true
      query = <<EOF
        SELECT  subscription_id, id, email
        FROM azure_security_contacts
        WHERE email IS NOT NULL
        AND email != '' AND alert_notifications = 'On';
    EOF
    }

    query "2.15" {
      description = "Azure CIS 2.15 Ensure that 'All users with the following roles' is set to 'Owner' (Automated)"
      expect_output = true
      query = <<EOF
        SELECT  subscription_id, id, email
        FROM azure_security_contacts
        WHERE email IS NOT NULL
        AND email != '' AND alerts_to_admins = 'On';
    EOF
    }
  }

  policy "azure-cis-section-3" {
    description = "Azure CIS Section 3"

  }

  policy "azure-cis-section-4" {
    description = "Azure CIS Section 4"

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