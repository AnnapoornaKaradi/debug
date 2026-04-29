locals {
	key_vault_access_policy_permission_sets = {
		keys = {
			all = [ "Backup", "Create", "Decrypt", "Delete", "Encrypt", "Get", "Import", "List", "Purge", "Recover", "Restore", "Sign", "UnwrapKey", "Update", "Verify", "WrapKey", "Release", "Rotate", "GetRotationPolicy", "SetRotationPolicy" ],
		}
		secrets = {
			all = [ "Backup", "Delete", "Get", "List", "Purge", "Recover", "Restore", "Set" ],
		}
		certificates = {
			all = [ "Backup", "Create", "Delete", "DeleteIssuers", "Get", "GetIssuers", "Import", "List", "ListIssuers", "ManageContacts", "ManageIssuers", "Purge", "Recover", "Restore", "SetIssuers", "Update" ]
		}
	}

	key_vaults_enc_network_acls = {
		default_action = "Deny"
		bypass = "AzureServices"
		ips = local.envs_to_exceptions["${var.env_ref}_network_refactor_local_testing"] ? local.firewall_enterprise_trusted_list.ips : []
		subnet_ids = distinct(compact(concat(
			[
				(var.tf_step != "common" ? data.terraform_remote_state.common.outputs.build_servers[local.my_env_region_ref].subnet_id : ""),
			],
			# Add the partner regions build pool for key syncs (like Azure SQL TDE)
			(local.i_am_active_geo ? [ data.terraform_remote_state.common.outputs.build_servers[local.partner_env_region_ref].subnet_id ] : [])

		)))
	}

	key_vaults_env_network_acls_standard = {
		default_action = "Deny"
		bypass = "None"
		ips = local.resource_firewall_standard.ips
		# Exclude subnets from SL-EXOS-All
		subnet_ids = [ for v in local.resource_firewall_standard.subnet_ids : v if replace(v, "97aeb7a6-ff38-40b1-9fc8-a4111cf894c2", "") == v ]
		subnet_id_refs = local.resource_firewall_standard.subnet_id_refs
	}
	
	key_vaults_env_network_acls_with_services = {
		default_action = "Deny"
		bypass = "None"
		ips = local.resource_firewall_with_services.ips
		# Exclude subnets from SL-EXOS-All
		subnet_ids = [ for v in local.resource_firewall_with_services.subnet_ids : v if replace(v, "97aeb7a6-ff38-40b1-9fc8-a4111cf894c2", "") == v ]
		subnet_id_refs = local.resource_firewall_with_services.subnet_id_refs
	}
	
	key_vaults_env_network_acls_with_services_with_geo_build = {
		default_action = "Deny"
		bypass = "None"
		ips = local.resource_firewall_with_services.ips
		# Exclude subnets from SL-EXOS-All
		subnet_ids = distinct(compact(concat(
			[ for v in local.resource_firewall_with_services.subnet_ids : v if replace(v, "97aeb7a6-ff38-40b1-9fc8-a4111cf894c2", "") == v ],
			# Add the partner regions build pool for key syncs
			(local.i_am_active_geo ? [ data.terraform_remote_state.common.outputs.build_servers[local.partner_env_region_ref].subnet_id ] : []),
		)))
		subnet_id_refs = local.resource_firewall_with_services.subnet_id_refs
	}
	
	key_vaults_common_to_deploy = { for k, v in local.key_vaults_common : k => v
		if ! contains(keys(v), "deploy_in")
		|| (
			contains(keys(v), "deploy_in")
			&& contains(lookup(lookup(v, "deploy_in", {}), "applications", [ var.app_ref ]), var.app_ref)
			&& (
				(lookup(lookup(v, "deploy_in", {}), "mgs", null) == null && lookup(lookup(v, "deploy_in", {}), "envs", null) == null)
				|| contains(lookup(lookup(v, "deploy_in", {}), "mgs", []), local.my_mg_ref)
				|| contains(lookup(lookup(v, "deploy_in", {}), "envs", []), local.my_env_short)
			)
		)
	}
	key_vaults_common = {
		enc = {
			name = "enc"
			numeric = "01"
			rg_ref = "infra"
			access_policies = merge(
				local.kv_access_policies.devops,
				# vvvvv This is a template for performing a data migration between environments
				# Add the temporary SQL logical server identity to the vault if the exception is in place
				#(local.envs_to_exceptions["${var.env_ref}_prod_to_uat4_migration"] ?
				#	{ (local.exceptions["prod_to_uat4_migration"].temp_sql_policy_name) = {
				#		object_id = local.exceptions["prod_to_uat4_migration"].temp_sql_mi_object_id
				#		key_permissions = [ "Get", "UnwrapKey", "WrapKey" ]
				#		secret_permissions = []
				#		certificate_permissions = []
				#	}}
				#	:
				#	null
				#),
				# Add the non-prod material owners group to the vault if the excpetion is in place
				(local.envs_to_exceptions["${var.env_ref}_network_refactor_local_testing"] ?
					{ network_refactor_local_testing = {
						object_id = local.my_mg.rbac.kv_material_owner_group_oid
						key_permissions = [ "Get", "List" ]
						secret_permissions = [ "Get", "List" ]
						certificate_permissions = []
					}}
					:
					null
				),
				# KV Access to destination for AZ_SQL_Migration
				# Not needed if performing migration manually 
				( contains( keys( local.exceptions), "${var.env_ref}_data_migration" ) ?
					{ (local.exceptions["${var.env_ref}_data_migration"].temp_sql_policy_name) = {
						object_id = local.exceptions["${var.env_ref}_data_migration"].temp_sql_mi_object_id
						key_permissions = [ "Get", "UnwrapKey", "WrapKey" ]
						secret_permissions = []
						certificate_permissions = []
					}}
					:
					null
				),
			)
			access_policy_refs = merge(
				# Add all of the storage account user identities
				{ for k, v in local.storage_accounts : "storage_accounts_uai_${k}" => {
					instance_key = k
					type = "storage_accounts_uai"
					key_permissions = [ "Get", "UnwrapKey", "WrapKey" ]
					secret_permissions = []
					certificate_permissions = []
				}},
				# Add the App Config identities
				{ for k, v in local.app_config_instances : "app_config_${k}" => {
					instance_key = k
					type = "app_config"
					key_permissions = [ "Get", "UnwrapKey", "WrapKey" ]
					secret_permissions = []
					certificate_permissions = []
				}},
				# Add the Form Recognizer system identities
				{ for k, v in local.form_recognizer_instances : "form_recognizer_sai_${k}" => {
					instance_key = k
					type = "form_recognizer_sai"
					key_permissions = [ "Get", "UnwrapKey", "WrapKey" ]
					secret_permissions = []
					certificate_permissions = []
				}},
				# Add the Form Recognizer identities
				{ for k, v in local.app_config_instances : "form_recognizer_${k}" => {
					instance_key = k
					type = "form_recognizer"
					key_permissions = [ "Get", "UnwrapKey", "WrapKey" ]
					secret_permissions = []
					certificate_permissions = []
				}},
				# Add the Azure SQL user assigned managed identities
				{ for k, v in local.az_sql_instances : "az_sql_uai_${k}" => {
					instance_key = k
					type = "az_sql_uai"
					key_permissions = [ "Get", "UnwrapKey", "WrapKey" ]
					secret_permissions = []
					certificate_permissions = []
				}},
				# Add the Cognitive Account identities
				{ for k, v in local.cognitive_instances : "cognitive_account_${k}" => {
					instance_key = k
					type = "cognitive_account"
					key_permissions = [ "Get", "UnwrapKey", "WrapKey" ]
					secret_permissions = []
					certificate_permissions = []
				}},
			)
			network_acls = local.key_vaults_enc_network_acls
		}
		enc_rpt = {
			name = "enc-rpt"
			numeric = "01"
			rg_ref = "infra"
			access_policies = merge(
				local.kv_access_policies.devops,
				# Add the non-prod material owners group to the vault if the excpetion is in place
				(local.envs_to_exceptions["${var.env_ref}_network_refactor_local_testing"] ?
					{ network_refactor_local_testing = {
						object_id = local.my_mg.rbac.kv_material_owner_group_oid
						key_permissions = [ "Get", "List" ]
						secret_permissions = [ "Get", "List" ]
						certificate_permissions = []
					}}
					:
					null
				),
			)
			access_policy_refs = merge(
				# Add the SSRS CMK SPN
				(contains(keys(local.windows_instances_to_install), "ssrs") ? { ssrs_spn = {
					type = "ssrs_spn"
					key_permissions = [ "Get", "List", "UnwrapKey", "WrapKey", "Verify", "Sign" ]
					secret_permissions = [ "Get", "List" ]
					certificate_permissions = []
				}} : {}),
			)
			windows_uai_access_policies = merge(
				# Add ssrs windows uai policy only if enabled for ENV
				length({ for k, v in local.windows_instances_to_install: k => v if k == "ssrs" }) == 0 ? {} : { 
					ssrs_vm_identity = {
						uai_ref = "ssrs"
						key_permissions = []
						secret_permissions = [ "Get", "List" ]
						certificate_permissions = []
					}
				},
			)
			network_acls = {
				default_action = local.key_vaults_enc_network_acls.default_action
				bypass = local.key_vaults_enc_network_acls.bypass
				ips = local.key_vaults_enc_network_acls.ips
				subnet_ids = local.key_vaults_enc_network_acls.subnet_ids
				subnet_id_refs = distinct(concat(
					# Add the ssrs subnet to network acl only if enabled for ENV
					length({ for k, v in local.windows_instances_to_install: k => v if k == "ssrs" }) == 0 ? [] : [ "win_ssrs", ]
				))
			}
		}
		enc_powerbi = {
			name = "enc-pwbi"
			numeric = "01"
			rg_ref = "infra"
			access_policies = merge(
				local.kv_access_policies.devops,
				{ for k,v in distinct([ for fab_k, fab_v in local.fabric_capacity_instances_to_install : {
					object_id = lookup(lookup(fab_v.spn,"env_override",{}), local.my_env_short, null) != null ? fab_v.spn.env_override[local.my_env_short] : lookup(fab_v.spn, "default", null)
					key_permissions = [ "Get", "UnwrapKey", "WrapKey" ]
					secret_permissions = []
					certificate_permissions = []
				}]): "fabric_capacity_spn${v.object_id}" => v },				
			)
			network_acls = {
				default_action = local.key_vaults_enc_network_acls.default_action
				bypass = local.key_vaults_enc_network_acls.bypass
				ips = local.key_vaults_enc_network_acls.ips
				subnet_ids = local.key_vaults_enc_network_acls.subnet_ids
				subnet_id_refs = distinct(concat(
					# Add the ssrs subnet to network acl only if enabled for ENV
					length({ for k, v in local.windows_instances_to_install: k => v if k == "ssrs" }) == 0 ? [] : [ "win_ssrs", ]
				))
			}
			deploy_in = {
				envs = [ "dev2","uat2","prod" ]
			}
		}
		enc_oai = {
			name = "enc-oai"
			numeric = "02"
			rg_ref = "infra"
			region = "northcentralus"
			region_short = "ncus"
			access_policies = local.kv_access_policies.devops
			skip_secondary_site_type = true
			access_policy_refs = merge(
				# Add the Cognitive Account identities
				{ for k, v in merge(local.cognitive_instances) : "cognitive_account_${k}" => {
					instance_key = k
					type = "cognitive_account"
					key_permissions = [ "Get", "UnwrapKey", "WrapKey" ]
					secret_permissions = []
					certificate_permissions = []
				}},
			)
			network_acls = local.key_vaults_enc_network_acls
			deploy_in = {
				envs = ["sandbox", "dev2", "uat2", "perf", "stage", "prod"]
			}
		}
	}
	key_vaults_env_base_access_policies = {
		devops_spn = {
			object_id = local.my_mg.rbac.devops_spn_oid
			key_permissions = [ "Backup", "Create", "Decrypt", "Delete", "Encrypt", "Get", "Import", "List", "Purge", "Recover", "Restore", "Sign", "UnwrapKey", "Update", "Verify", "WrapKey", "GetRotationPolicy" ]
			secret_permissions = [ "Backup", "Delete", "Get", "List", "Purge", "Recover", "Restore", "Set" ]
			certificate_permissions = [ "Backup", "Create", "Delete", "DeleteIssuers", "Get", "GetIssuers", "Import", "List", "ListIssuers", "ManageContacts", "ManageIssuers", "Purge", "Recover", "Restore", "SetIssuers", "Update" ]
		}
		material_owner_group = {
			object_id = local.my_mg.rbac.kv_material_owner_group_oid
			key_permissions = [ "Backup", "Create", "Decrypt", "Delete", "Encrypt", "Get", "Import", "List", "Purge", "Recover", "Restore", "Sign", "UnwrapKey", "Update", "Verify", "WrapKey","GetRotationPolicy",  ]
			secret_permissions = [ "Backup", "Delete", "Get", "List", "Purge", "Recover", "Restore", "Set" ]
			certificate_permissions = [ "Backup", "Create", "Delete", "DeleteIssuers", "Get", "GetIssuers", "Import", "List", "ListIssuers", "ManageContacts", "ManageIssuers", "Purge", "Recover", "Restore", "SetIssuers", "Update" ]
		}
	}

	key_vaults_env = merge(
		(length(keys(local.apim_instances_to_install)) > 0 ? 
			{ apim = {
				name = "apim"
				numeric = "01"
				rg_ref = "app"
				access_policies = merge(
					local.key_vaults_env_base_access_policies,
					{
						material_user_group = {
							object_id = local.my_mg.rbac.kv_infra_material_user_group_oid
							key_permissions = [ "Get", "List", "Sign", "Verify" ],
							secret_permissions = [ "Get", "List" ],
							certificate_permissions = []
						}
					}
				)
				pass_mi_access_policies = merge(
					{ apim_mi = {
						resource_ref = "apim"
						instance_ref = "app2"
						key_permissions = []
						secret_permissions = [ "Get", "List" ]
						certificate_permissions = []
					}},
				)
				network_acls = {
					default_action = local.key_vaults_env_network_acls_standard.default_action
					bypass = "AzureServices"
					ips = local.key_vaults_env_network_acls_standard.ips
					subnet_ids = local.key_vaults_env_network_acls_standard.subnet_ids
					subnet_id_refs = local.key_vaults_env_network_acls_standard.subnet_id_refs
				}
			}} : {}
		),
		{adl = {
			name = "adl"
			numeric = "01"
			rg_ref = "app"
			skip_declarative_perms = local.envs_to_exceptions["${var.env_ref}_kv_non_declarative_perms"]
			access_policies = merge(
				local.key_vaults_env_base_access_policies,
				{
					material_user_group = {
						object_id = local.my_mg.rbac.kv_material_user_group_oid
						key_permissions = [ "Get", "List", "Sign", "Verify" ],
						secret_permissions = [ "Get", "List" ],
						certificate_permissions = []
					}
					adl_service_account = {
						object_id = local.environments[var.env_ref].adl_service_account.object_id
						key_permissions = [ "Get", "List", "Sign", "Verify" ],
						secret_permissions = [ "Get", "List" ],
						certificate_permissions = []
					}
					adf_service_account = {
						object_id = local.environments[var.env_ref].onelake_service_account.object_id
						key_permissions = [],
						secret_permissions = [ "Get", "List" ],
						certificate_permissions = []
					}
					adf_app = {
						object_id = lookup(local.environments[var.env_ref].adf_app_object_id, local.my_region_short, "")
						key_permissions = []
						secret_permissions = [ "Get", "List" ]
						certificate_permissions = []
					}
				}
			)
			network_acls = {
                default_action = local.key_vaults_env_network_acls_standard.default_action
                bypass = "AzureServices"
                ips = local.key_vaults_env_network_acls_standard.ips
                subnet_ids = local.key_vaults_env_network_acls_standard.subnet_ids
                subnet_id_refs = distinct(concat(
                        local.key_vaults_env_network_acls_standard.subnet_id_refs,
                        [
                            "aks_default_nodepool",
                            "aks_appdefault_nodepool",
							"aks_exos3_nodepool",
                        ]
                ))
            }
			env_managed_private_endpoints_override = {
				dev2 = [ "9f709920-b690-4f6c-baf7-d938ab4931da.MPE_DataLake-KeyVault-conn" ]
				uat2 = [ "c4cc7564-e9c0-4f28-a734-e41cc99715c9.MPE_DataLake-KeyVault-conn" ]
				stage = [ "6667e81d-cf85-4d1d-9302-641367d14e4a.MPE_DataLake-KeyVault-conn" ]
				prod = [ "7e3784b4-4894-488a-b9c6-046ea2a19bbf.MPE_DataLake-KeyVault-conn" ]
			}
		}
	    adf = {
			name = "adf"
			numeric = "01"
			rg_ref = "app"
			access_policies = merge(
				local.key_vaults_env_base_access_policies,
				{
					material_user_group = {
						object_id = local.my_mg.rbac.kv_infra_material_user_group_oid
						key_permissions = [ "Get", "List", "Sign", "Verify" ],
						secret_permissions = [ "Get", "List" ],
						certificate_permissions = []
					}
				}
			)
			pass_mi_access_policies = merge(
				{ data_factory_mi = {
					resource_ref = "adf"
					instance_ref = "app"
					key_permissions = []
					secret_permissions = [ "Get", "List" ]
					certificate_permissions = []
				}},
			)
			network_acls = {
				default_action = local.key_vaults_env_network_acls_standard.default_action
				bypass = "AzureServices"
				ips = local.key_vaults_env_network_acls_standard.ips
				subnet_ids = local.key_vaults_env_network_acls_standard.subnet_ids
				subnet_id_refs = local.key_vaults_env_network_acls_standard.subnet_id_refs
			}
		}
		app = {
			name = "app"
			numeric = "02"
			rg_ref = "app"
			skip_declarative_perms = local.envs_to_exceptions["${var.env_ref}_kv_non_declarative_perms"]
			access_policies = merge(
				local.key_vaults_env_base_access_policies,
				{ material_user_group = {
					object_id = local.my_mg.rbac.kv_material_user_group_oid
					key_permissions = [ "Get", "List", "Sign", "Verify" ],
					secret_permissions = [ "Get", "List" ],
					certificate_permissions = []
				}}
			)
			network_acls = local.key_vaults_env_network_acls_with_services_with_geo_build
			injections = {
				uri = {
					attr = "uri"
					app_config_name = "ExosMacro:KeyVaultEndpoint"
					app_config_ref = "app"
				}
			}
		}
		dba = {
			name = "dba"
			numeric = "01"
			rg_ref = "infra"
			access_policies = merge(
				local.key_vaults_env_base_access_policies,
				{ material_user_group = {
					object_id = local.my_mg.rbac.kv_dba_material_user_group_oid
					key_permissions = [ "Get", "List", "Sign", "Verify" ],
					secret_permissions = [ "Get", "List" ],
					certificate_permissions = []
				}}
			)
			network_acls = local.key_vaults_env_network_acls_standard
		}
		infra = {
			name = "infra"
			numeric = "02"
			rg_ref = "infra"
			access_policies = merge(
				local.key_vaults_env_base_access_policies,
				{ material_user_group = {
					object_id = local.my_mg.rbac.kv_infra_material_user_group_oid
					key_permissions = [ "Get", "List", "Sign", "Verify" ],
					secret_permissions = [ "Get", "List" ],
					certificate_permissions = []
				}}
			)
			network_acls = local.key_vaults_env_network_acls_standard
		}
		print = {
			name = "print"
			numeric = "01"
			rg_ref = "app"
			access_policies = merge(
				local.key_vaults_env_base_access_policies,
				{ material_user_group = {
					object_id = local.my_mg.rbac.kv_material_user_group_oid
					key_permissions = [ "Get", "List", "Sign", "Verify" ]
					secret_permissions = [ "Get", "List" ]
					certificate_permissions = []
				}},
			)
			exos_services_uai_access_policies = merge(
				{ printproxysvc = {
					uai_ref = "printproxysvc"
					key_permissions = []
					secret_permissions = [ "Get", "List" ]
					certificate_permissions = []
				}},
			)
			windows_uai_access_policies = merge(
				(contains(keys(local.windows_instances_to_install), "print") ? { print_vm_identity = {
					uai_ref = "print"
					key_permissions = []
					secret_permissions = [ "Get", "List" ]
					certificate_permissions = []
				}} : {}),
			)
			network_acls = {
				default_action = local.key_vaults_env_network_acls_standard.default_action
				bypass = local.key_vaults_env_network_acls_standard.bypass
				ips = local.key_vaults_env_network_acls_standard.ips
				subnet_ids = local.key_vaults_env_network_acls_standard.subnet_ids
				subnet_id_refs = distinct(concat(
					local.key_vaults_env_network_acls_standard.subnet_id_refs,
					# Add the subnet where the print proxy Windows VMs will reside
					[
						"win_print",
					]
				))
			}
		}
		ssrs = {
			name = "ssrs"
			numeric = "01"
			rg_ref = "app"
			access_policies = merge(
				local.key_vaults_env_base_access_policies,
				{ material_user_group = {
					object_id = local.my_mg.rbac.kv_infra_material_user_group_oid
					key_permissions = [ "Get", "List", "Sign", "Verify" ]
					secret_permissions = [ "Get", "List" ]
					certificate_permissions = []
				}},
			)
			windows_uai_access_policies = merge(
				(contains(keys(local.windows_instances_to_install), "ssrs") ? { ssrs_vm_identity = {
					uai_ref = "ssrs"
					key_permissions = []
					secret_permissions = [ "Get", "List" ]
					certificate_permissions = []
				}} : {}),
			)
			network_acls = {
				default_action = local.key_vaults_env_network_acls_standard.default_action
				bypass = local.key_vaults_env_network_acls_standard.bypass
				ips = local.key_vaults_env_network_acls_standard.ips
				subnet_ids = local.key_vaults_env_network_acls_standard.subnet_ids
				subnet_id_refs = distinct(concat(
					local.key_vaults_env_network_acls_standard.subnet_id_refs,
					# Add the subnet where the print ssrs Windows VMs will reside
					[
						"win_ssrs",
					]
				))
			}
		}
		sftp = {
			name = "sftp"
			numeric = "01"
			rg_ref = "app"
			skip_declarative_perms = local.envs_to_exceptions["${var.env_ref}_kv_non_declarative_perms"]
			access_policies = merge(
				local.key_vaults_env_base_access_policies,
				{ material_user_group = {
					object_id = local.my_mg.rbac.kv_material_user_group_oid
					key_permissions = [ "Get", "List", "Sign", "Verify" ]
					secret_permissions = [ "Get", "List" ]
					certificate_permissions = []
				}}
			)
			network_acls = local.key_vaults_env_network_acls_with_services
			injections = {
				uri = {
					attr = "uri"
					app_config_name = "ExosMacro:Encryption:PgpKeyVault"
					app_config_ref = "app"
				}
			}
		}
		sse = {
			name = "sse"
			numeric = "01"
			rg_ref = "infra"
			enable_disk_encryption = true
			skip_declarative_perms = true	# This vault cannot be declarative as there is currently a cyclical redundancy on the DES identity
			# Unfortunately, the cyclical redundancy introduced means that this vault's access policies can't be defined here.
			# Instead it is defined as a different local and merged into the non-declarative block
			access_policies = local.key_vaults_env_base_access_policies
			network_acls = {
				default_action = local.key_vaults_env_network_acls_standard.default_action
				bypass = "AzureServices"
				ips = local.key_vaults_env_network_acls_standard.ips
				subnet_ids = local.key_vaults_env_network_acls_standard.subnet_ids
				subnet_id_refs = local.key_vaults_env_network_acls_standard.subnet_id_refs
			}
		}
		user = {
			name = "user"
			numeric = "01"
			rg_ref = "app"
			skip_declarative_perms = local.envs_to_exceptions["${var.env_ref}_kv_non_declarative_perms"]
			access_policies = merge(
				local.key_vaults_env_base_access_policies,
				{ material_user_group = {
					object_id = local.my_mg.rbac.kv_material_user_group_oid
					key_permissions = [ "Get", "List", "Sign", "Verify" ],
					secret_permissions = [ "Get", "List" ],
					certificate_permissions = []
				}},
			)
			network_acls = local.key_vaults_env_network_acls_with_services
		} 
		automation = {
			name = "auto"
			numeric = "01"
			rg_ref = "app"
			skip_declarative_perms = local.envs_to_exceptions["${var.env_ref}_kv_non_declarative_perms"]
			access_policies = merge(
				local.key_vaults_env_base_access_policies,
				{ material_user_group = {
					object_id = local.my_mg.rbac.kv_material_user_group_oid
					key_permissions = [ "Get", "List", "Sign", "Verify" ],
					secret_permissions = [ "Get", "List" ],
					certificate_permissions = []
				}},
			)
			network_acls = local.key_vaults_env_network_acls_with_services
		} }
	)
}