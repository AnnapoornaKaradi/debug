locals {

key_vaults_common_to_deploy_iterator = { for k,v in local.key_vaults_common_to_deploy : k => v if ! ((try(v.skip_secondary_site_type, false) == true) && (local.site_type == "secondary")) }

key_vault_outputs = {
	common = { for k, v in local.key_vaults_common_to_deploy_iterator :
		k => {
			uri = azurerm_key_vault.common[k].vault_uri
		}
	}
	env = { for k, v in local.key_vaults_env :
		k => {
			uri = azurerm_key_vault.env[k].vault_uri
		}
	}
}

key_vault_common_injections_iterator = { for k, v in flatten(
	[ for instance_key, instance_value in local.key_vaults_common_to_deploy_iterator :
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
) : "key_vaults_common_${v.instance_key}_${v.inject_key}" => v }

key_vault_common_injections = { for k, v in local.key_vault_common_injections_iterator :
	k => {
		kv_name = lookup(v.inject_value, "kv_name", null)
		kv_ref = lookup(v.inject_value, "kv_ref", null)
		kv_value = v.use_kv ? local.key_vault_outputs.common[v.instance_key][v.inject_value.attr] : null
		app_config_name = lookup(v.inject_value, "app_config_name", null)
		app_config_ref = lookup(v.inject_value, "app_config_ref", null)
		# If app config is specified, assume precense of kv_name means itll be a key vault reference, otherwise its a direct injection
		app_config_value = v.use_app_config ? (v.use_kv ? "kv_ref" : local.key_vault_outputs.common[v.instance_key][v.inject_value.attr]) : null
	}
}

key_vault_env_injections_iterator = { for k, v in flatten(
	[ for instance_key, instance_value in local.key_vaults_env :
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
) : "key_vaults_env_${v.instance_key}_${v.inject_key}" => v }

key_vault_env_injections = { for k, v in local.key_vault_env_injections_iterator :
	k => {
		kv_name = lookup(v.inject_value, "kv_name", null)
		kv_ref = lookup(v.inject_value, "kv_ref", null)
		kv_value = v.use_kv ? local.key_vault_outputs.env[v.instance_key][v.inject_value.attr] : null
		app_config_name = lookup(v.inject_value, "app_config_name", null)
		app_config_ref = lookup(v.inject_value, "app_config_ref", null)
		# If app config is specified, assume precense of kv_name means itll be a key vault reference, otherwise its a direct injection
		app_config_value = v.use_app_config ? (v.use_kv ? "kv_ref" : local.key_vault_outputs.env[v.instance_key][v.inject_value.attr]) : null
	}
}

key_vault_pass_mi_access_policies = merge(
	{ adf = { for k, v in local.data_factory_instances : k => azurerm_data_factory.env[k].identity[0].principal_id }},
	{ apim = { for k, v in local.apim_instances_to_install : k => azurerm_api_management.env[k].identity[0].principal_id }},
)

}

#----- Create the vaults that reside in SL-EXOS-ReleaseMGMT-01
resource "azurerm_key_vault" "common" {
	for_each = local.key_vaults_common_to_deploy_iterator

	provider = azurerm.common

	name = (local.envs_to_exceptions["${var.env_ref}_sandbox_name_shrink"] ?
		"kv-${each.value.name}-sand-${lookup(each.value,"region_short",local.basic["local"].region_short)}-${each.value.numeric}"
		:
		"kv-${each.value.name}-${local.basic["local"].env_short}-${lookup(each.value,"region_short",local.basic["local"].region_short)}-${each.value.numeric}"
	)
	#!!!!! Move these in the future to an environment specific resource group
	#resource_group_name = azurerm_resource_group.terraform_state.name
	#location = azurerm_resource_group.terraform_state.location
	resource_group_name = data.terraform_remote_state.common.outputs.resource_groups["${each.value.rg_ref}_${lookup(each.value,"region_short",local.basic["local"].region_short)}"].name
	location = lookup(each.value,"region",data.terraform_remote_state.common.outputs.resource_groups["${each.value.rg_ref}_${local.basic["local"].region_short}"].location)
	tenant_id = var.tenant_id
	
	purge_protection_enabled = (local.envs_to_exceptions["${var.env_ref}_key_vault_no_purge_protection"] ? false : true)
	enabled_for_disk_encryption = lookup(each.value, "enable_disk_encryption", false)
	
	sku_name = "premium"
	
	dynamic "access_policy" {
		for_each = each.value.access_policies
		iterator = each

		content {
			tenant_id = var.tenant_id
			object_id = each.value.object_id
			key_permissions = each.value.key_permissions
			secret_permissions = each.value.secret_permissions
			certificate_permissions = each.value.certificate_permissions
		}
	}
		
	dynamic "access_policy" {
		for_each = lookup(each.value, "access_policy_refs", {})
		iterator = each
		
		content {
			application_id = ""
			object_id = (
				each.value.type == "storage_accounts_uai" ? azurerm_user_assigned_identity.storage_uai[each.value.instance_key].principal_id :
				each.value.type == "az_sql_sai" ? local.az_sql_system_mi_ids["${local.basic["local"].env_short}_${local.basic["local"].region_short}"] :
				each.value.type == "app_config" ? azurerm_user_assigned_identity.appconfig_uai[each.value.instance_key].principal_id :
				each.value.type == "form_recognizer_sai" ? azurerm_cognitive_account.form[each.value.instance_key].identity[0].principal_id :
				each.value.type == "form_recognizer" ? azurerm_user_assigned_identity.formrecognizer_uai[each.value.instance_key].principal_id :
				each.value.type == "ssrs_spn" ? azuread_service_principal.ssrs["default"].object_id : 
				each.value.type == "az_sql_uai" ? azurerm_user_assigned_identity.az_sql[each.value.instance_key].principal_id : 
				each.value.type == "cognitive_account" ? azurerm_user_assigned_identity.cognitive_account_uai[each.value.instance_key].principal_id : null
			)
			tenant_id = var.tenant_id
			
			certificate_permissions = each.value.certificate_permissions
			key_permissions = each.value.key_permissions
			secret_permissions = each.value.secret_permissions
			storage_permissions = []
		}
	}
	

	dynamic "access_policy" {
		for_each = lookup(each.value, "windows_uai_access_policies", null) != null ? each.value.windows_uai_access_policies : {}
		
		content {
			tenant_id = var.tenant_id
			object_id = azurerm_user_assigned_identity.windows[access_policy.value.uai_ref].principal_id
			key_permissions = access_policy.value.key_permissions
			secret_permissions = access_policy.value.secret_permissions
			certificate_permissions = access_policy.value.certificate_permissions
		}
	}
		
	dynamic "network_acls" {
		for_each = { "default" = each.value.network_acls } 
		iterator = each
		
		content {
			default_action = each.value.default_action
			bypass = each.value.bypass
			
			ip_rules = [ for value in each.value.ips : substr(value, -3, 1) == "/" ? value : "${value}/32" ]
			virtual_network_subnet_ids = distinct(concat(
				each.value.subnet_ids,
				[ for v in lookup(each.value, "subnet_id_refs", []) : azurerm_subnet.env[v].id ]
			))
		}
	}
	
	tags = merge(
		local.tags,
		local.resource_tags["key_vault"],
	)
	lifecycle {
		ignore_changes = [
			tags,
		]
	}
}

#----- Create the vaults for this environment
resource "azurerm_key_vault" "env" {
	for_each = local.key_vaults_env
	
	name = "kv-${each.value.name}-${local.basic["local"].env_short}-${local.basic["local"].region_short}-${each.value.numeric}"
	resource_group_name = azurerm_resource_group.env[each.value.rg_ref].name
	location = azurerm_resource_group.env[each.value.rg_ref].location
	tenant_id = var.tenant_id
	
	purge_protection_enabled = (local.envs_to_exceptions["${var.env_ref}_key_vault_no_purge_protection"] ? false : true)
	enabled_for_disk_encryption = lookup(each.value, "enable_disk_encryption", false)
	
	sku_name = "premium"
	
	dynamic "access_policy" {
		for_each = lookup(each.value, "skip_declarative_perms", false) ? {} : each.value.access_policies

		content {
			tenant_id = var.tenant_id
			object_id = access_policy.value.object_id
			key_permissions = access_policy.value.key_permissions
			secret_permissions = access_policy.value.secret_permissions
			certificate_permissions = access_policy.value.certificate_permissions
		}
	}
	
	dynamic "access_policy" {
		for_each = lookup(each.value, "exos_services_uai_access_policies", null) != null ? each.value.exos_services_uai_access_policies : {}
		
		content {
			tenant_id = var.tenant_id
			object_id = azurerm_user_assigned_identity.exos_services[access_policy.value.uai_ref].principal_id
			key_permissions = access_policy.value.key_permissions
			secret_permissions = access_policy.value.secret_permissions
			certificate_permissions = access_policy.value.certificate_permissions
		}
	}
	
	dynamic "access_policy" {
		for_each = lookup(each.value, "pass_mi_access_policies", {})
		iterator = each
		
		content {
			tenant_id = var.tenant_id
			object_id = local.key_vault_pass_mi_access_policies[each.value.resource_ref][each.value.instance_ref]
			key_permissions = each.value.key_permissions
			secret_permissions = each.value.secret_permissions
			certificate_permissions = each.value.certificate_permissions
		}
	}
	
	dynamic "access_policy" {
		for_each = lookup(each.value, "windows_uai_access_policies", null) != null ? each.value.windows_uai_access_policies : {}
		
		content {
			tenant_id = var.tenant_id
			object_id = azurerm_user_assigned_identity.windows[access_policy.value.uai_ref].principal_id
			key_permissions = access_policy.value.key_permissions
			secret_permissions = access_policy.value.secret_permissions
			certificate_permissions = access_policy.value.certificate_permissions
		}
	}
		
	dynamic "network_acls" {
		for_each = { "default" = each.value.network_acls } 
		iterator = each
		
		content {
			default_action = each.value.default_action
			bypass = each.value.bypass
			
			ip_rules = [ for value in each.value.ips : substr(value, -3, 1) == "/" ? value : "${value}/32" ]
			virtual_network_subnet_ids = distinct(concat(
				each.value.subnet_ids,
				[ for v in lookup(each.value, "subnet_id_refs", []) : azurerm_subnet.env[v].id ]
			))
		}
	}
	
	tags = merge(
		local.tags,
		local.resource_tags["key_vault"],
	)
	lifecycle {
		ignore_changes = [
			tags,
			network_acls,
		]
	}
}

#----- Define non-declarative access policies
resource "azurerm_key_vault_access_policy" "env" {
	for_each = { for k, v in (flatten(
		[ for vault_key, vault_value in local.key_vaults_env :
			[ for policy_key, policy_value in vault_value.access_policies :
				{
					vault_key = vault_key
					policy_key = policy_key
					object_id = policy_value.object_id
					key_permissions = policy_value.key_permissions
					secret_permissions = policy_value.secret_permissions
					certificate_permissions = policy_value.certificate_permissions
					skip_declarative_perms = lookup(vault_value, "skip_declarative_perms", false)
				}
			]
		]
	)) : "${v.vault_key}_${v.policy_key}" => v if v.skip_declarative_perms }
	
	key_vault_id = azurerm_key_vault.env[each.value.vault_key].id
	tenant_id = var.tenant_id
	object_id = each.value.object_id
	
	key_permissions = each.value.key_permissions
	secret_permissions = each.value.secret_permissions
	certificate_permissions = each.value.certificate_permissions
}

#----- Define access policies for the SSE vault which have to be separate due to cyclical redundancies with the identity creation
resource "azurerm_key_vault_access_policy" "sse" {
	key_vault_id = azurerm_key_vault.env["sse"].id
	tenant_id = var.tenant_id
	object_id = azurerm_disk_encryption_set.env.identity.0.principal_id
	
	key_permissions = [	"Get", "Decrypt", "Encrypt", "Sign", "UnwrapKey", "Verify", "WrapKey" ]
	secret_permissions = []
	certificate_permissions = []
}

#---------- Diagnostic Logging ----------
# Enable on the vaults in SL-EXOS-ReleaseMGMT-01
# This is done here because the catch-all in the next step only targets this environments subscription
data "azurerm_monitor_diagnostic_categories" "key_vault_common" {
	resource_id = azurerm_key_vault.common[keys(local.key_vaults_common_to_deploy_iterator)[0]].id
}

resource "azurerm_monitor_diagnostic_setting" "key_vault_common" {
	for_each = local.key_vaults_common_to_deploy_iterator

	provider = azurerm.common
	
	name = "log_all"
	target_resource_id = azurerm_key_vault.common[each.key].id
	
	log_analytics_workspace_id = data.terraform_remote_state.common.outputs.log_analytics["default"].id
	
	dynamic "enabled_log" {
		for_each = data.azurerm_monitor_diagnostic_categories.key_vault_common.logs
		
		content {
			category = enabled_log.value
		}
	}
	
	dynamic "metric" {
		for_each = data.azurerm_monitor_diagnostic_categories.key_vault_common.metrics
		
		content {
			category = metric.value
			enabled = true
		}
	}
}

resource "azapi_update_resource" "configure_keyvault_env_network_acls" {
	for_each = local.key_vaults_env  
	type = "Microsoft.KeyVault/vaults@2023-07-01"
	ignore_casing = true
	resource_id = azurerm_key_vault.env[each.key].id
	body = jsonencode({
		properties = {
			networkAcls = {
				defaultAction = each.value.network_acls.default_action
				bypass = each.value.network_acls.bypass
				ipRules = [ for v in each.value.network_acls.ips : {
					value = substr(v, -3, 1) == "/" ? v : "${v}/32"
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
		azurerm_key_vault.env,
		azurerm_key_vault_access_policy.env,
		azurerm_key_vault_access_policy.sse,
		azurerm_subnet.env
	]
}
