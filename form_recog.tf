locals {

form_recognizer_outputs = { for k, v in local.form_recognizer_instances :
	k => {
		endpoint = local.credentials_rotating ? lookup(data.azurerm_cognitive_account.form_injections, k, { endpoint = "dummy" }).endpoint : azurerm_cognitive_account.form[k].endpoint
		primary_access_key = local.credentials_rotating ? lookup(data.azurerm_cognitive_account.form_injections, k, { primary_access_key = "dummy" }).primary_access_key : azurerm_cognitive_account.form[k].primary_access_key
		secondary_access_key = local.credentials_rotating ? lookup(data.azurerm_cognitive_account.form_injections, k, { secondary_access_key = "dummy" }).secondary_access_key : azurerm_cognitive_account.form[k].secondary_access_key
	
	}
}

form_recognizer_injections_iterator = { for k, v in flatten(
	[ for instance_key, instance_value in local.form_recognizer_instances :
		[ for inject_key, inject_value in lookup(instance_value, "injections", {}) :
			{
				instance_key = instance_key
				inject_key = inject_key
				inject_value = inject_value
				use_kv = contains(keys(inject_value), "kv_name")
				use_app_config = contains(keys(inject_value), "app_config_name")
			}
		]
	]
) : "form_${v.instance_key}_${v.inject_key}" => v }

form_recognizer_injections = { for k, v in local.form_recognizer_injections_iterator :
	k => {
		kv_name = lookup(v.inject_value, "kv_name", null)
		kv_ref = lookup(v.inject_value, "kv_ref", null)
		kv_value = v.use_kv ? local.form_recognizer_outputs[v.instance_key][v.inject_value.attr] : null
		app_config_name = lookup(v.inject_value, "app_config_name", null)
		app_config_ref = lookup(v.inject_value, "app_config_ref", null)
		# If app config is specified, assume precense of kv_name means itll be a key vault reference, otherwise its a direct injection
		app_config_value = v.use_app_config ? (v.use_kv ? "kv_ref" : local.form_recognizer_outputs[v.instance_key][v.inject_value.attr]) : null
	}
}
    
}

#------ Create Form Recognizer
resource "azurerm_cognitive_account" "form" {
    for_each = local.form_recognizer_instances  
    name = lower("form-${each.value.name}-${local.basic["local"].env_short}-${local.basic["local"].region_short}-${each.value.numeric}")
    resource_group_name = azurerm_resource_group.env[each.value.rg_ref].name
    location = azurerm_resource_group.env[each.value.rg_ref].location
    kind = "FormRecognizer"

    custom_subdomain_name = lower("form-${each.value.name}-${local.basic["local"].env_short}-${local.basic["local"].region_short}-${each.value.numeric}")

    sku_name = "S0"

    public_network_access_enabled = true
    
    dynamic "network_acls" {
		for_each = contains(keys(each.value), "network_acls") ? { "default" = "default" } : {}
		
		content {
			default_action = each.value.network_acls.default_action
		
			ip_rules = [ for v in each.value.network_acls.ips : trimsuffix(v, "/32") ]
			dynamic "virtual_network_rules" {
				for_each = each.value.network_acls.subnet_ids
				
				content {
					subnet_id = virtual_network_rules.value
					ignore_missing_vnet_service_endpoint = false
				}
			}
			
			dynamic "virtual_network_rules" {
				for_each = each.value.network_acls.subnet_id_refs
				
				content {
					subnet_id = azurerm_subnet.env[virtual_network_rules.value].id	
					ignore_missing_vnet_service_endpoint = false
				}
			}
		}
	}

	identity {
		type = "SystemAssigned, UserAssigned"
		identity_ids = [
			azurerm_user_assigned_identity.formrecognizer_uai[each.key].id
		]
	}
	
	
	depends_on = [
		azurerm_key_vault_access_policy.env
	]
	
    tags = local.tags
	lifecycle {
		ignore_changes = [
			tags,
			customer_managed_key,
			network_acls
		]
	}
}

# Store initial keeper value to avoid rotation on fresh creates
resource "null_resource" "form_recognizer_initial_keeper" {
  for_each = local.form_recognizer_instances

  triggers = {
    initial_keeper = local.my_env.keepers.credentials
  }

  lifecycle {
    ignore_changes = [triggers]
  }
}

#----- Rotate the Cognitive account connection keys
#----- Rotate the Cognitive account connection keys
resource "null_resource" "form_recognizer_connection_key_rotation" {
  for_each = local.form_recognizer_instances

  triggers = {
    credentials_keeper = local.my_env.keepers.credentials != null_resource.form_recognizer_initial_keeper[each.key].triggers.initial_keeper ? local.my_env.keepers.credentials : null
  }

  provisioner "local-exec" {
    command = <<EOT
      set -euo pipefail

      /usr/bin/az cognitiveservices account keys regenerate \
        --key-name Key1 \
        --name "$NAME" \
        --resource-group "$RG_NAME" \
        --only-show-errors
    EOT

    environment = {
      NAME    = azurerm_cognitive_account.form[each.key].name
      RG_NAME = azurerm_cognitive_account.form[each.key].resource_group_name
    }
  }

  depends_on = [
    azurerm_cognitive_account.form,
    azapi_update_resource.configure_form_recognizer_cmk,
    azapi_update_resource.configure_form_recognizer_network_acls,
    null_resource.form_recognizer_initial_keeper,
  ]
}

data "azurerm_cognitive_account" "form_injections" {
	for_each = local.form_recognizer_instances
	
	name = azurerm_cognitive_account.form[each.key].name
	resource_group_name = azurerm_cognitive_account.form[each.key].resource_group_name
	
	depends_on = [ null_resource.form_recognizer_connection_key_rotation ]
}

#----- Create identities for new Form Recognizer
resource "azurerm_user_assigned_identity" "formrecognizer_uai" {
	for_each = local.form_recognizer_instances

	name = lower("form-${each.value.name}-${local.basic["local"].env_short}-${local.basic["local"].region_short}-${each.value.numeric}")
	resource_group_name = azurerm_resource_group.env[each.value.rg_ref].name
	location = azurerm_resource_group.env[each.value.rg_ref].location
	
	tags = local.common_tags
	lifecycle {
		ignore_changes = [
			tags,
		]
	}
}

#----- Create the CMK used to encrypt existing Form Recognizer
resource "azurerm_key_vault_key" "formrecognizer_cmk" {
		for_each = { for k, v in (flatten(
		[ for form_recognizer_key, form_recognizer_value in local.form_recognizer_instances :
			[ for suffix in local.my_env.keepers.encryption_key_suffixes :
				{
					form_recognizer_key = form_recognizer_key
					suffix = suffix
					instance_name = lower("form-${form_recognizer_value.name}-${local.basic["local"].env_short}-${local.basic["local"].region_short}-${form_recognizer_value.numeric}")
				}
			]
		]
	)) : "${v.form_recognizer_key}_${v.suffix}" => v }

	provider = azurerm.common
	
	name = "${each.value.instance_name}--${each.value.suffix}"
	key_vault_id = azurerm_key_vault.common["enc"].id
	key_type = "RSA-HSM"
	key_size = 2048
	
	key_opts = [ "encrypt", "decrypt", "sign", "verify", "unwrapKey", "wrapKey" ]
}

resource "azapi_update_resource" "configure_form_recognizer_cmk" {
	for_each = local.form_recognizer_instances  
	type = "Microsoft.CognitiveServices/accounts@2023-05-01"
	resource_id = azurerm_cognitive_account.form[each.key].id
	body = jsonencode({
		properties = {
			encryption = {
				keySource = "Microsoft.KeyVault"
				keyVaultProperties = {
					keyVaultUri = azurerm_key_vault.common["enc"].vault_uri
					keyName = azurerm_key_vault_key.formrecognizer_cmk["${each.key}_${local.my_env.keepers.encryption_key_use}"].name
					keyVersion = azurerm_key_vault_key.formrecognizer_cmk["${each.key}_${local.my_env.keepers.encryption_key_use}"].version
				}
			}
		}
  })
}

resource "azapi_update_resource" "configure_form_recognizer_network_acls" {
	for_each = local.form_recognizer_instances  
	type = "Microsoft.CognitiveServices/accounts@2023-05-01"
	ignore_casing = true
	resource_id = azurerm_cognitive_account.form[each.key].id
	body = jsonencode({
		properties = {
			networkAcls = {
				defaultAction = each.value.network_acls.default_action
				ipRules = [ for v in each.value.network_acls.ips : {
					value = trimsuffix(v, "/32")
				} ]
				virtualNetworkRules = concat([
					for vnetRules in each.value.network_acls.subnet_ids : {
						id = vnetRules
						ignoreMissingVnetServiceEndpoint = false
					}
				],[
					for vnetRules in each.value.network_acls.subnet_id_refs : {
						id = azurerm_subnet.env[vnetRules].id
						ignoreMissingVnetServiceEndpoint = false
					}
				])
			}
		}
	})
	depends_on = [
		azapi_update_resource.configure_form_recognizer_cmk,
		azurerm_cognitive_account.form,
		azurerm_subnet.env
	]
}      
