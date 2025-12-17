//! Protocol Module
//!
//! Defines the IPC protocol for PKI Chain including request/response types
//! and serialization/deserialization functions.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Filter options for listing certificates
#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum Filter {
    All,
    Intermediate,
    User,
    Root,
}

/// Request types from external applications
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Request {
    CreateIntermediate {
        subject_common_name: String,
        organization: String,
        organizational_unit: String,
        locality: String,
        state: String,
        country: String,
        validity_days: u32,
    },
    CreateUser {
        subject_common_name: String,
        organization: String,
        organizational_unit: String,
        locality: String,
        state: String,
        country: String,
        validity_days: u32,
        issuer_common_name: String,
    },
    ListCertificates {
        filter: String,
    },
    PKIStatus,
    SocketTest,
    GetWebClientTLSCertificate,
}

/// Response types sent back to clients
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Response {
    CreateIntermediateResponse {
        message: String,
        common_name: String,
        organization: String,
        organizational_unit: String,
        country: String,
        height: u64,
    },
    CreateUserResponse {
        message: String,
        common_name: String,
        organization: String,
        organizational_unit: String,
        locality: String,
        state: String,
        country: String,
        issuer_common_name: String,
        validity_days: u32,
        height: u64,
    },
    ListCertificatesResponse {
        message: String,
        certificates: Vec<serde_json::Value>,
        count: usize,
    },
    PKIStatusResponse {
        message: String,
        status: String,
        total_certificates: u64,
        total_keys: u64,
        tracked_subject_names: usize,
        certificate_chain_valid: bool,
        private_key_chain_valid: bool,
        pki_chain_in_sync: bool,
    },
    SocketTestResponse {
        message: String,
    },
    GetWebClientTLSCertificateResponse {
        message: String,
        certificate: String,
        private_key: String,
        certificate_chain: Vec<String>,
        subject_common_name: String,
    },
    Error {
        message: String,
    },
}

/// Serialize a Request to length-prefixed byte array
///
/// # Arguments
/// * `request` - The Request to serialize
///
/// # Returns
/// * `Result<(u32, Vec<u8>)>` - Tuple of (length, bytes) where bytes includes 4-byte length prefix
///
/// # Example
/// ```no_run
/// use pki_chain::protocol::{Request, serialize_request};
///
/// let request = Request::SocketTest;
/// let (size, bytes) = serialize_request(&request)?;
/// // bytes = [4-byte length] + [JSON data]
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn serialize_request(request: &Request) -> Result<(u32, Vec<u8>)> {
    let json = serde_json::to_string(request).context("Failed to serialize request to JSON")?;

    let json_bytes = json.as_bytes();
    let length = json_bytes.len() as u32;

    let mut buffer = Vec::with_capacity(4 + json_bytes.len());
    buffer.extend_from_slice(&length.to_le_bytes());
    buffer.extend_from_slice(json_bytes);

    Ok((length, buffer))
}

/// Deserialize a byte array to Request
///
/// # Arguments
/// * `bytes` - Byte array containing JSON-encoded Request
///
/// # Returns
/// * `Result<Request>` - Deserialized Request enum
///
/// # Example
/// ```no_run
/// use pki_chain::protocol::deserialize_request;
///
/// let request_bytes = b"{\"type\":\"SocketTest\"}";
/// let request = deserialize_request(request_bytes)?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn deserialize_request(bytes: &[u8]) -> Result<Request> {
    let json_str = std::str::from_utf8(bytes).context("Failed to decode request bytes as UTF-8")?;

    let request: Request =
        serde_json::from_str(json_str).context("Failed to deserialize JSON to Request")?;

    Ok(request)
}

/// Serialize a Response to length-prefixed byte array
///
/// # Arguments
/// * `response` - The Response to serialize
///
/// # Returns
/// * `Result<(u32, Vec<u8>)>` - Tuple of (length, bytes) where bytes includes 4-byte length prefix
///
/// # Example
/// ```no_run
/// use pki_chain::protocol::{Response, serialize_response};
///
/// let response = Response::SocketTestResponse { message: "test".to_string() };
/// let (size, bytes) = serialize_response(&response)?;
/// // bytes = [4-byte length] + [JSON data]
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn serialize_response(response: &Response) -> Result<(u32, Vec<u8>)> {
    let json = serde_json::to_string(response).context("Failed to serialize response to JSON")?;

    let json_bytes = json.as_bytes();
    let length = json_bytes.len() as u32;

    let mut buffer = Vec::with_capacity(4 + json_bytes.len());
    buffer.extend_from_slice(&length.to_le_bytes());
    buffer.extend_from_slice(json_bytes);

    Ok((length, buffer))
}

/// Deserialize a byte array to Response
///
/// # Arguments
/// * `bytes` - Byte array containing JSON-encoded Response
///
/// # Returns
/// * `Result<Response>` - Deserialized Response enum
///
/// # Example
/// ```no_run
/// use pki_chain::protocol::deserialize_response;
///
/// let response_bytes = b"{\"type\":\"SocketTestResponse\",\"message\":\"test\"}";
/// let response = deserialize_response(response_bytes)?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn deserialize_response(bytes: &[u8]) -> Result<Response> {
    let json_str =
        std::str::from_utf8(bytes).context("Failed to decode response bytes as UTF-8")?;

    let response: Response =
        serde_json::from_str(json_str).context("Failed to deserialize JSON to Response")?;

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_request() {
        let request = Request::SocketTest;
        let result = serialize_request(&request);
        assert!(result.is_ok());

        let (length, bytes) = result.unwrap();
        assert!(length > 0);
        assert_eq!(bytes.len(), (length + 4) as usize);
    }

    #[test]
    fn test_deserialize_response() {
        let json = r#"{"type":"SocketTestResponse","message":"test"}"#;
        let result = deserialize_response(json.as_bytes());
        assert!(result.is_ok());

        if let Response::SocketTestResponse { message } = result.unwrap() {
            assert_eq!(message, "test");
        } else {
            panic!("Wrong response type");
        }
    }
}
