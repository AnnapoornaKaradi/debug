locals {

form_recognizer_instances = {
	app = {
		name      = "app"
		numeric   = "01"
		rg_ref    = "data"
		injections = {
			endpoint = {
				attr = "endpoint"
				app_config_name = "ExosMacro:EXOS:AzureFormRecognizerUrl"
				app_config_ref = "app"
			}
			primary_access_key = {
				attr = "primary_access_key"
				kv_name = "ExosMacro--EXOS--AzureFormRecognizerKey"
				kv_ref = "app"
				app_config_name = "ExosMacro:EXOS:AzureFormRecognizerKey"
				app_config_ref = "app"
			}
			secondary_access_key = {
				attr = "secondary_access_key"
				kv_name = "ExosMacro--EXOS--AzureFormRecognizerKeySecondary"
				kv_ref = "app"
				app_config_name = "ExosMacro:EXOS:AzureFormRecognizerKeySecondary"
				app_config_ref = "app"
			}
		}
		network_acls = {
			default_action = "Deny"
			bypass = "None"
			ips = local.resource_firewall_with_services.ips
			subnet_ids = local.my_env_short == "dev2" ? distinct(concat(local.resource_firewall_with_services.subnet_ids, local.build_agents_subnets)) : local.resource_firewall_with_services.subnet_ids
			subnet_id_refs = local.resource_firewall_with_services.subnet_id_refs
		}
	}
	app-plantexpn = {
		name      = "app-plantexpn"
		numeric   = "01"
		rg_ref    = "data"
		injections = {
			endpoint = {
				attr = "endpoint"
				app_config_name = "ExosMacro:EXOS:AzureFormRecognizerUrlPlantExpn"
				app_config_ref = "app"
			}
			primary_access_key = {
				attr = "primary_access_key"
				kv_name = "ExosMacro--EXOS--AzureFormRecognizerKeyPlantExpn"
				kv_ref = "app"
				app_config_name = "ExosMacro:EXOS:AzureFormRecognizerKeyPlantExpn"
				app_config_ref = "app"
			}
			secondary_access_key = {
				attr = "secondary_access_key"
				kv_name = "ExosMacro--EXOS--AzureFormRecognizerKeySecondaryPlantExpn"
				kv_ref = "app"
				app_config_name = "ExosMacro:EXOS:AzureFormRecognizerKeySecondaryPlantExpn"
				app_config_ref = "app"
			}
		}
		network_acls = {
			default_action = "Deny"
			bypass = "None"
			ips = local.resource_firewall_with_services.ips
			subnet_ids = local.my_env_short == "dev2" ? distinct(concat(local.resource_firewall_with_services.subnet_ids, local.build_agents_subnets)) : local.resource_firewall_with_services.subnet_ids
			subnet_id_refs = local.resource_firewall_with_services.subnet_id_refs
		}
	}
}
	
}
