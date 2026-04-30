mod common;

use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    thread,
    time::Duration,
};

use pki_chain::{
    comm_protocol,
    configs::{AdminCADefaults, AppConfig, Blockchains, KeyExports, RootCADefaults, ServerConfig},
    storage,
};

const PROTOCOL_VERSION1: u32 = 1;

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

fn send_framed_json(stream: &mut UnixStream, payload: &serde_json::Value) {
    let payload_bytes = serde_json::to_vec(payload).expect("failed to serialize JSON payload");
    stream
        .write_all(&PROTOCOL_VERSION1.to_le_bytes())
        .expect("failed to write protocol version");
    stream
        .write_all(&(payload_bytes.len() as u32).to_le_bytes())
        .expect("failed to write payload length");
    stream
        .write_all(&payload_bytes)
        .expect("failed to write payload bytes");
}

fn recv_framed_json(stream: &mut UnixStream) -> serde_json::Value {
    let mut version_buf = [0u8; 4];
    let mut length_buf = [0u8; 4];

    stream
        .read_exact(&mut version_buf)
        .expect("failed to read protocol version from response");
    let response_version = u32::from_le_bytes(version_buf);
    assert_eq!(response_version, PROTOCOL_VERSION1);

    stream
        .read_exact(&mut length_buf)
        .expect("failed to read payload length from response");
    let payload_len = u32::from_le_bytes(length_buf) as usize;

    let mut payload_buf = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload_buf)
        .expect("failed to read payload data from response");

    serde_json::from_slice(&payload_buf).expect("failed to parse response JSON")
}

fn connect_with_retry(path: &Path) -> UnixStream {
    for _ in 0..50 {
        if let Ok(stream) = UnixStream::connect(path) {
            return stream;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("failed to connect to setup socket at {}", path.display());
}

fn send_setup_request(
    setup_socket: &Path,
    response_socket: &Path,
    request: serde_json::Value,
) -> serde_json::Value {
    let _ = std::fs::remove_file(response_socket);
    let response_listener =
        UnixListener::bind(response_socket).expect("failed to bind response socket listener");

    let mut setup_stream = connect_with_retry(setup_socket);
    let request_json = serde_json::json!({
        "request": {
            "response_socket": response_socket.to_string_lossy(),
            "request_type": request["request_type"].clone(),
            "create_new_storage": request["create_new_storage"].clone(),
            "admin_certificate_data": request["admin_certificate_data"].clone(),
        }
    });

    send_framed_json(&mut setup_stream, &request_json);

    let (mut response_stream, _) = response_listener
        .accept()
        .expect("failed to accept setup response connection");
    recv_framed_json(&mut response_stream)
}

#[test]
fn start_setup_server_handles_get_state_after_initial_get_state_call() {
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

    let mut app_config = AppConfig {
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

    app_config.server.comm_sock = generated.temp_dir.path().join("comm.sock");
    app_config.server.setup_sock = generated.temp_dir.path().join("setup.sock");

    let initial_status = storage::get_state(&app_config);
    assert_eq!(initial_status.storage_state, storage::StorageState::Empty);

    let server_config = app_config.clone();
    let server_initial_status = initial_status.clone();
    let setup_server_thread = thread::spawn(move || {
        comm_protocol::start_setup_server(&server_config, server_initial_status)
    });

    let get_state_response = send_setup_request(
        &app_config.server.setup_sock,
        &generated
            .temp_dir
            .path()
            .join("setup-response-get-state.sock"),
        serde_json::json!({
            "request_type": "GetState"
        }),
    );

    assert_eq!(
        get_state_response["response"]["status"],
        serde_json::Value::String("success".to_string())
    );

    let create_and_initialize_response = send_setup_request(
        &app_config.server.setup_sock,
        &generated
            .temp_dir
            .path()
            .join("setup-response-create-and-initialize.sock"),
        serde_json::json!({
            "request_type": "CreateAndInitialize",
            "create_new_storage": true,
            "admin_certificate_data": {
                "subject_common_name": "Integration Test Admin",
                "issuer_common_name": app_config.root_ca_defaults.root_ca_common_name,
                "organization": app_config.admin_ca_defaults.admin_ca_organization,
                "organizational_unit": app_config.admin_ca_defaults.admin_ca_organizational_unit,
                "locality": app_config.admin_ca_defaults.admin_ca_locality,
                "state": app_config.admin_ca_defaults.admin_ca_state,
                "country": app_config.admin_ca_defaults.admin_ca_country,
                "validity_days": app_config.admin_ca_defaults.admin_ca_validity_days,
            }
        }),
    );

    assert_eq!(
        create_and_initialize_response["response"]["status"],
        serde_json::Value::String("success".to_string())
    );

    let final_status = setup_server_thread
        .join()
        .expect("setup server thread panicked");

    assert_eq!(final_status.storage_state, storage::StorageState::Ready);
}
