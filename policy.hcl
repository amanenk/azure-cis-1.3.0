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

  }

  policy "aws-cis-section-7" {
    description = "Azure CIS Section 7"

  }

  policy "aws-cis-section-8" {
    description = "Azure CIS Section 8"

    query "8.1" {
      description = "Azure CIS 8.1 Ensure that the expiration date is set on all keys (Automated)"
      query = <<EOF
      SELECT akv.id AS vault_id, akv."name" AS vault_name, akvk.kid AS key_id
      FROM azure_keyvault_vaults akv
      LEFT JOIN
            azure_keyvault_vault_keys akvk ON
            akv.cq_id = akvk.vault_cq_id
      WHERE akvk.kid IS NULL
      OR enabled != TRUE
      OR expires IS NULL;
    EOF
    }

    query "8.2" {
      description = "Azure CIS 8.2 Ensure that the expiration date is set on all Secrets (Automated)"
      query = <<EOF
      SELECT akv.id AS vault_id, akv."name" AS vault_name, akvs.id AS key_id
      FROM azure_keyvault_vaults akv
      LEFT JOIN
            azure_keyvault_vault_secrets akvs ON
            akv.cq_id = akvs.vault_cq_id
      WHERE enabled != TRUE
      OR expires IS NULL;
    EOF
    }

    query "8.3" {
      description = "Azure CIS 8.3 Ensure that Resource Locks are set for mission critical Azure resources (Manual)"
      query = file("queries/manual.sql")
    }

    query "8.4" {
      description = "Azure CIS 8.4 Ensure the key vault is recoverable (Automated)"
      query = <<EOF
      SELECT id, "name",
      FROM azure_keyvault_vaults akv
      WHERE enable_soft_delete != TRUE
      OR enable_purge_protection != TRUE;
    EOF
    }

    query "8.5" {
      description = "Azure CIS 8.5 Enable role-based access control (RBAC) within Azure Kubernetes Services (Automated)"
      query = <<EOF
      SELECT id, "name", enable_rbac
      FROM azure_container_managed_clusters acmc
      WHERE enable_rbac != TRUE;
    EOF
    }
  }


  policy "aws-cis-section-9" {
    description = "Azure CIS Section 9"

  }
}