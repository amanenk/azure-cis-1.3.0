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

//    policies that have not been modified will not be listed in this output
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