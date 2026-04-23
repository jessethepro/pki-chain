mod common;

use pki_chain::{
    configs::{AdminCADefaults, AppConfig, Blockchains, KeyExports, RootCADefaults, ServerConfig},
    storage,
};

fn get_required_string(table: &toml::Value, section: &str, key: &str) -> String {
    table[section][key]
        .as_str()
        .unwrap_or_else(|| panic!("missing or invalid string for {}.{}", section, key))
        .to_string()
}

fn get_required_u32(table: &toml::Value, section: &str, key: &str) -> u32 {
    table[section][key]
        .as_integer()
        .unwrap_or_else(|| panic!("missing or invalid integer for {}.{}", section, key)) as u32
}

#[test]
fn get_state_with_ephemeral_storage_prints_results() {
    let generated =
        common::create_ephemeral_test_config().expect("failed to generate ephemeral test config");

    let generated_toml = std::fs::read_to_string(&generated.config_path)
        .expect("failed to read generated tests_config.toml");
    let generated_value: toml::Value =
        toml::from_str(&generated_toml).expect("generated tests_config.toml is invalid TOML");

    let base_toml = std::fs::read_to_string("config.toml").expect("failed to read config.toml");
    let base_value: toml::Value = toml::from_str(&base_toml).expect("config.toml is invalid TOML");

    let admin_defaults = base_value
        .get("admin_ca_defaults")
        .and_then(toml::Value::as_table)
        .expect("missing admin_ca_defaults section in config.toml");
    let admin_ca_organization = admin_defaults
        .get("admin_ca_organization")
        .and_then(toml::Value::as_str)
        .or_else(|| {
            admin_defaults
                .get("admin_ca_orgaination")
                .and_then(toml::Value::as_str)
        })
        .expect("missing admin_ca_defaults.admin_ca_organization/admin_ca_orgaination")
        .to_string();

    let app_config = AppConfig {
        blockchains: Blockchains {
            certificate_path: get_required_string(
                &generated_value,
                "blockchains",
                "certificate_path",
            )
            .into(),
            private_key_path: get_required_string(
                &generated_value,
                "blockchains",
                "private_key_path",
            )
            .into(),
            crl_path: get_required_string(&generated_value, "blockchains", "crl_path").into(),
        },
        key_exports: KeyExports {
            app_key_path: get_required_string(&generated_value, "key_exports", "app_key_path")
                .into(),
            app_cert_path: get_required_string(&generated_value, "key_exports", "app_cert_path")
                .into(),
        },
        server: ServerConfig {
            comm_sock: get_required_string(&generated_value, "server", "comm_sock").into(),
            setup_sock: get_required_string(&generated_value, "server", "setup_sock").into(),
        },
        root_ca_defaults: RootCADefaults {
            root_ca_common_name: get_required_string(
                &base_value,
                "root_ca_defaults",
                "root_ca_common_name",
            ),
            root_ca_organization: get_required_string(
                &base_value,
                "root_ca_defaults",
                "root_ca_organization",
            ),
            root_ca_organizational_unit: get_required_string(
                &base_value,
                "root_ca_defaults",
                "root_ca_organizational_unit",
            ),
            root_ca_locality: get_required_string(
                &base_value,
                "root_ca_defaults",
                "root_ca_locality",
            ),
            root_ca_state: get_required_string(&base_value, "root_ca_defaults", "root_ca_state"),
            root_ca_country: get_required_string(
                &base_value,
                "root_ca_defaults",
                "root_ca_country",
            ),
            root_ca_validity_days: get_required_u32(
                &base_value,
                "root_ca_defaults",
                "root_ca_validity_days",
            ),
        },
        admin_ca_defaults: AdminCADefaults {
            admin_ca_common_name: get_required_string(
                &base_value,
                "admin_ca_defaults",
                "admin_ca_common_name",
            ),
            admin_ca_organization,
            admin_ca_organizational_unit: get_required_string(
                &base_value,
                "admin_ca_defaults",
                "admin_ca_organizational_unit",
            ),
            admin_ca_locality: get_required_string(
                &base_value,
                "admin_ca_defaults",
                "admin_ca_locality",
            ),
            admin_ca_state: get_required_string(&base_value, "admin_ca_defaults", "admin_ca_state"),
            admin_ca_country: get_required_string(
                &base_value,
                "admin_ca_defaults",
                "admin_ca_country",
            ),
            admin_ca_validity_days: get_required_u32(
                &base_value,
                "admin_ca_defaults",
                "admin_ca_validity_days",
            ),
        },
    };

    let state = storage::get_state(&app_config);
    println!("storage::get_state result: {:#?}", state);
}
