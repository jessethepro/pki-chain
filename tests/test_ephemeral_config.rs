mod common;

#[test]
fn creates_ephemeral_test_config_with_temp_paths() {
    let generated =
        common::create_ephemeral_test_config().expect("failed to generate ephemeral test config");

    let generated_toml = std::fs::read_to_string(&generated.config_path)
        .expect("failed to read generated tests_config.toml");
    let generated_value: toml::Value =
        toml::from_str(&generated_toml).expect("generated tests_config.toml is invalid TOML");
    let original_toml = std::fs::read_to_string("config.toml").expect("failed to read config.toml");
    let original_value: toml::Value =
        toml::from_str(&original_toml).expect("config.toml is invalid TOML");

    let temp_root = generated.temp_dir.path().to_string_lossy().into_owned();

    for key in ["certificate_path", "private_key_path", "crl_path"] {
        let path = generated_value["blockchains"][key]
            .as_str()
            .expect("blockchains path should be a string");
        assert!(
            path.starts_with(&temp_root),
            "expected blockchains.{} to live under temp root {} but got {}",
            key,
            temp_root,
            path
        );
    }

    for key in ["app_key_path", "app_cert_path"] {
        let path = generated_value["key_exports"][key]
            .as_str()
            .expect("key_exports path should be a string");
        assert!(
            path.starts_with(&temp_root),
            "expected key_exports.{} to live under temp root {} but got {}",
            key,
            temp_root,
            path
        );
    }

    assert_eq!(generated_value["server"], original_value["server"]);
    assert_eq!(
        generated_value["root_ca_defaults"],
        original_value["root_ca_defaults"]
    );
}
