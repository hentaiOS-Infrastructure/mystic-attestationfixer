//
// Copyright 2024, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This crate implements droidfoodattestation.

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
    Tag::Tag,
};
use android_security_postprocessor::aidl::android::security::postprocessor::{
    CertificateChain::CertificateChain,
    IKeystoreCertificatePostProcessor::IKeystoreCertificatePostProcessor,
};
use android_security_postprocessor::binder::{Interface, Status};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
    IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
};
use android_system_keystore2::binder;
use droidfood_attestation_proto::overwrite::{
    AttestationKeyCertificateProfile as WireAttestationKeyCertificateProfile,
    OverwriteAttestationRequest, OverwriteAttestationResponse,
    OverwriteAttestationResponsePlaintext, ProvisionAttestationKeyRequest,
    ProvisionAttestationKeyResponse, ProvisionAttestationKeyResponsePlaintext,
};
use log::{debug, error};
use mystic_attestation_provisioner::aidl::mystic::attestation::provisioner::{
    AttestationKeyCertificateProfile::AttestationKeyCertificateProfile as BinderAttestationKeyCertificateProfile,
    IBackendAttestationKeyProvisioner::IBackendAttestationKeyProvisioner,
    ProvisionedAttestationKey::ProvisionedAttestationKey,
};
use openssl::hkdf::hkdf;
use openssl::md::Md;
use openssl::sha::sha256;
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::x509::{X509Ref, X509};
use protobuf::{Message, MessageField};
use reqwest::blocking::{Client, Response};
use rustutils::android::system_properties;
use std::collections::HashSet;
use std::io::Read;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use uuid::Uuid;

const BACKEND_GRPC_DIRECT_BASE: &str = "https://greendroidfood-pa.helluvaos.com";
const BACKEND_GRPC_PROXY_BASE: &str = "https://greendroidfood-pa.meowproxy.net";
const BACKEND_GRPC_SERVICE: &str = "mystic.attestation.public.v1.AttestationOverwriter";
const ERROR_SERVER_REQUEST: i32 = -2;
const ERROR_SERVER_RESPONSE: i32 = -3;
const ERROR_REPROVISION_ATTESTATION_KEY: i32 = -4;
const KEYSTORE2_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";
const RESPONSE_KEY_ALIAS_PREFIX: &str = "mystic_response_";
const RESPONSE_KEY_CHALLENGE_PREFIX: &str = "MysticAttestation response key v1:";
const DEVICE_IDENTITY_TRUSTED_ALIAS: &str = "mystic_device_identity_v2";
const DEVICE_IDENTITY_FALLBACK_ALIAS: &str = "mystic_device_identity_fallback_v2";
const DEVICE_IDENTITY_CHALLENGE_DOMAIN: &[u8] = b"MysticAttestation persistent device identity v2";
const DEVICE_IDENTITY_REQUEST_DOMAIN: &[u8] = b"MysticAttestation device identity request v2";
const RESPONSE_HKDF_INFO: &[u8] = b"MysticAttestation overwrite response v1";
const RESPONSE_AAD_PREFIX: &str = "MysticAttestation overwrite response aad v1:";
const PROVISION_RESPONSE_HKDF_INFO: &[u8] = b"MysticAttestation provision response v1";
const PROVISION_RESPONSE_AAD_PREFIX: &str = "MysticAttestation provision response aad v1:";
const ATTESTATION_PROTOCOL_VERSION: u32 = 2;
const RESPONSE_CERT_NOT_AFTER_MS: i64 = 2_461_449_600_000;
const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const BACKEND_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const BACKEND_TCP_KEEPALIVE: Duration = Duration::from_secs(30);
const BACKEND_TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const BACKEND_TCP_USER_TIMEOUT: Duration = Duration::from_secs(45);
const BACKEND_RETRY_DELAY: Duration = Duration::from_millis(250);
const BACKEND_REQUEST_ATTEMPTS: usize = 3;
const GRPC_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

static BACKEND_CLIENT: OnceLock<Result<Client, String>> = OnceLock::new();

/// Routes overwrite requests through the proxy instead of the direct backend.
pub const USE_BACKEND_PROXY: bool = false;

/// Enables verbose Droidfood-only diagnostics in this processor binary.
pub const INTENSIVE_LOGS_ENABLED: bool = false;

fn backend_grpc_base() -> &'static str {
    if USE_BACKEND_PROXY {
        BACKEND_GRPC_PROXY_BASE
    } else {
        BACKEND_GRPC_DIRECT_BASE
    }
}

fn backend_grpc_url(method: &str) -> String {
    format!("{}/{}/{}", backend_grpc_base(), BACKEND_GRPC_SERVICE, method)
}

macro_rules! intensive_log {
    ($($arg:tt)+) => {
        if INTENSIVE_LOGS_ENABLED {
            debug!($($arg)+);
        }
    };
}

/// The `IKeystoreCertificatePostProcessor` implementation.
pub struct KeystoreCertificatePostProcessor;

impl Interface for KeystoreCertificatePostProcessor {}

impl IKeystoreCertificatePostProcessor for KeystoreCertificatePostProcessor {
    fn processKeystoreCertificates(
        &self,
        old_keymint_certificates: &CertificateChain,
    ) -> Result<CertificateChain, Status> {
        if is_internal_identity_certificate(&old_keymint_certificates.leafCertificate) {
            intensive_log!("skipping overwrite for internal KeyMint identity attestation");
            return Ok(CertificateChain {
                leafCertificate: old_keymint_certificates.leafCertificate.clone(),
                remainingChain: old_keymint_certificates.remainingChain.clone(),
            });
        }

        match leaf_is_signed_by_first_issuer(
            &old_keymint_certificates.leafCertificate,
            &old_keymint_certificates.remainingChain,
        ) {
            Ok(true) => {}
            Ok(false) => {
                intensive_log!(
                    "attestation leaf does not match the supplied attest key; requesting V2 reprovisioning"
                );
                return Err(service_error(
                    ERROR_REPROVISION_ATTESTATION_KEY,
                    "Supplied attestation key does not sign the generated certificate.",
                ));
            }
            Err(err) => {
                return Err(service_error(ERROR_SERVER_REQUEST, &err));
            }
        }

        let request_id = Uuid::new_v4().to_string();
        intensive_log!("sending attestation overwrite request: request_id={request_id}");

        let device_identity = load_or_generate_device_identity()?;
        let response_key = generate_response_key(&request_id)?;
        let response = request_overwrite(
            &request_id,
            &old_keymint_certificates.leafCertificate,
            &old_keymint_certificates.remainingChain,
            &device_identity,
            &response_key.certificate_chain,
        );
        let response = match response {
            Ok(response) => response,
            Err(OverwriteRequestError::InvalidArgument(message)) => {
                intensive_log!(
                    "attestation overwrite rejected: request_id={request_id} message={message}"
                );
                return Err(service_error(ERROR_SERVER_REQUEST, &message));
            }
            Err(OverwriteRequestError::Backend(message)) => {
                intensive_log!(
                    "attestation overwrite backend failed: request_id={request_id} error={message}"
                );
                return Err(service_error(ERROR_SERVER_REQUEST, &message));
            }
        };

        let decrypted = match decrypt_response(&request_id, &response_key.descriptor, &response) {
            Ok(decrypted) => decrypted,
            Err(err) => {
                intensive_log!(
                    "attestation overwrite encrypted response failed: request_id={request_id} error={err}"
                );
                return Err(service_error(ERROR_SERVER_RESPONSE, &err));
            }
        };

        if decrypted.reprovision_attestation_key {
            intensive_log!(
                "backend requested V2 attestation-key reprovisioning: request_id={request_id}"
            );
            return Err(service_error(
                ERROR_REPROVISION_ATTESTATION_KEY,
                "Backend requested attestation-key reprovisioning.",
            ));
        }

        if decrypted.leaf_certificate.is_empty() || decrypted.remaining_chain.is_empty() {
            intensive_log!(
                "server returned an incomplete encrypted certificate chain: request_id={request_id}"
            );
            return Err(service_error(
                ERROR_SERVER_RESPONSE,
                "Server returned an incomplete certificate chain.",
            ));
        }

        if decrypted.leaf_certificate == old_keymint_certificates.leafCertificate
            && decrypted.remaining_chain == old_keymint_certificates.remainingChain
        {
            error!(
                "attestation overwrite backend authorized original-chain fallback: request_id={request_id}"
            );
        }

        intensive_log!(
            "attestation overwrite response received: request_id={} leaf_bytes={} chain_bytes={}",
            request_id,
            decrypted.leaf_certificate.len(),
            decrypted.remaining_chain.len()
        );
        Ok(CertificateChain {
            leafCertificate: decrypted.leaf_certificate,
            remainingChain: decrypted.remaining_chain,
        })
    }
}

impl IBackendAttestationKeyProvisioner for KeystoreCertificatePostProcessor {
    fn provisionAttestationKey(
        &self,
        certificate_profile: &BinderAttestationKeyCertificateProfile,
        wrapping_key_leaf_certificate: &[u8],
        wrapping_key_remaining_chain: &[u8],
    ) -> Result<ProvisionedAttestationKey, Status> {
        let request_id = Uuid::new_v4().to_string();
        intensive_log!("sending attestation-key provisioning request: request_id={request_id}");

        let device_identity = load_or_generate_device_identity()?;
        let response_key = generate_response_key(&request_id)?;
        let response = request_provision(
            &request_id,
            &device_identity,
            &response_key.certificate_chain,
            certificate_profile,
            wrapping_key_leaf_certificate,
            wrapping_key_remaining_chain,
        );
        let response = match response {
            Ok(response) => response,
            Err(OverwriteRequestError::InvalidArgument(message)) => {
                intensive_log!(
                    "attestation-key provisioning rejected: request_id={request_id} message={message}"
                );
                return Err(service_error(ERROR_SERVER_REQUEST, &message));
            }
            Err(OverwriteRequestError::Backend(message)) => {
                intensive_log!(
                    "attestation-key provisioning backend failed: request_id={request_id} error={message}"
                );
                return Err(service_error(ERROR_SERVER_REQUEST, &message));
            }
        };

        let decrypted = match decrypt_provision_response(
            &request_id,
            &response_key.descriptor,
            &response,
        ) {
            Ok(decrypted) => decrypted,
            Err(err) => {
                intensive_log!(
                        "attestation-key provisioning encrypted response failed: request_id={request_id} error={err}"
                    );
                return Err(service_error(ERROR_SERVER_RESPONSE, &err));
            }
        };

        validate_provisioned_attestation_key(&decrypted).map_err(|err| {
            intensive_log!(
                "attestation-key provisioning material invalid: request_id={request_id} error={err}"
            );
            service_error(ERROR_SERVER_RESPONSE, &err)
        })?;

        intensive_log!(
            "attestation-key provisioning response received: request_id={} wrapper_bytes={} leaf_bytes={} chain_bytes={}",
            request_id,
            decrypted.secure_key_wrapper.len(),
            decrypted.leaf_certificate.len(),
            decrypted.remaining_chain.len()
        );
        Ok(ProvisionedAttestationKey {
            secureKeyWrapper: decrypted.secure_key_wrapper,
            leafCertificate: decrypted.leaf_certificate,
            remainingChain: decrypted.remaining_chain,
        })
    }
}

struct ResponseKey {
    descriptor: KeyDescriptor,
    certificate_chain: Vec<Vec<u8>>,
}

impl Drop for ResponseKey {
    fn drop(&mut self) {
        delete_key(&self.descriptor);
    }
}

struct DeviceIdentityKey {
    descriptor: KeyDescriptor,
    certificate_chain: Vec<Vec<u8>>,
    untrusted_device_serial: String,
}

enum OverwriteRequestError {
    InvalidArgument(String),
    Backend(String),
}

enum OverwriteAttemptError {
    InvalidArgument(String),
    EmptyResponse,
    Retryable(String),
    Fatal(String),
}

fn request_with_retry<T>(
    operation: &str,
    request_id: &str,
    mut request: impl FnMut(Duration) -> Result<T, OverwriteAttemptError>,
) -> Result<T, OverwriteRequestError> {
    let deadline = Instant::now() + BACKEND_REQUEST_TIMEOUT;
    for attempt in 1..=BACKEND_REQUEST_ATTEMPTS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(OverwriteRequestError::Backend(format!(
                "{operation} request deadline exceeded"
            )));
        }
        let retry_error = match request(remaining) {
            Ok(response) => return Ok(response),
            Err(OverwriteAttemptError::InvalidArgument(message)) => {
                return Err(OverwriteRequestError::InvalidArgument(message));
            }
            Err(OverwriteAttemptError::Fatal(message)) => {
                return Err(OverwriteRequestError::Backend(message));
            }
            Err(OverwriteAttemptError::EmptyResponse) => {
                intensive_log!(
                    "{} empty response retry: request_id={} attempt={}/{}",
                    operation,
                    request_id,
                    attempt,
                    BACKEND_REQUEST_ATTEMPTS
                );
                OverwriteRequestError::InvalidArgument("INVALID_ARGUMENT".to_owned())
            }
            Err(OverwriteAttemptError::Retryable(message)) => {
                intensive_log!(
                    "{} transport retry: request_id={} attempt={}/{} error={}",
                    operation,
                    request_id,
                    attempt,
                    BACKEND_REQUEST_ATTEMPTS,
                    message
                );
                OverwriteRequestError::Backend(message)
            }
        };
        if attempt == BACKEND_REQUEST_ATTEMPTS {
            return Err(retry_error);
        }
        let retry_delay = BACKEND_RETRY_DELAY * attempt as u32;
        if deadline.saturating_duration_since(Instant::now()) <= retry_delay {
            return Err(retry_error);
        }
        std::thread::sleep(retry_delay);
    }
    unreachable!()
}

fn request_overwrite(
    request_id: &str,
    leaf_certificate: &[u8],
    remaining_chain: &[u8],
    device_identity: &DeviceIdentityKey,
    response_key_chain: &[Vec<u8>],
) -> Result<OverwriteAttestationResponse, OverwriteRequestError> {
    let mut request = OverwriteAttestationRequest::new();
    request.leaf_certificate = leaf_certificate.to_vec();
    request.remaining_chain = remaining_chain.to_vec();
    request.request_id = request_id.to_owned();
    request.device_attestation_chain = device_identity.certificate_chain.clone();
    request.response_encryption_key_chain = response_key_chain.to_vec();
    request.untrusted_device_serial = device_identity.untrusted_device_serial.clone();
    request.protocol_version = ATTESTATION_PROTOCOL_VERSION;
    let digest = overwrite_device_identity_digest(&request);
    request.device_identity_signature = sign_device_identity(&device_identity.descriptor, &digest)
        .map_err(OverwriteRequestError::Backend)?;

    let request_bytes = request.write_to_bytes().map_err(|err| {
        OverwriteRequestError::Backend(format!(
            "attestation overwrite request encode failed: {err:?}"
        ))
    })?;
    let request_frame = encode_grpc_frame(&request_bytes).map_err(|err| {
        OverwriteRequestError::Backend(format!("attestation overwrite request frame failed: {err}"))
    })?;
    let client = backend_client()?;
    request_with_retry("attestation overwrite", request_id, |remaining| {
        request_overwrite_once(client, request_id, &request_frame, remaining)
    })
}

fn wire_attestation_key_profile(
    profile: &BinderAttestationKeyCertificateProfile,
) -> Result<WireAttestationKeyCertificateProfile, OverwriteRequestError> {
    let mut wire = WireAttestationKeyCertificateProfile::new();
    wire.subject_der = profile.subjectDer.clone();
    wire.serial_number = profile.serialNumber.clone();
    wire.not_before_ms = profile.notBeforeMs;
    wire.not_after_ms = profile.notAfterMs;
    wire.attestation_challenge = profile.attestationChallenge.clone();
    wire.attestation_application_id = profile.attestationApplicationId.clone();
    Ok(wire)
}

fn request_provision(
    request_id: &str,
    device_identity: &DeviceIdentityKey,
    response_key_chain: &[Vec<u8>],
    certificate_profile: &BinderAttestationKeyCertificateProfile,
    wrapping_key_leaf_certificate: &[u8],
    wrapping_key_remaining_chain: &[u8],
) -> Result<ProvisionAttestationKeyResponse, OverwriteRequestError> {
    let mut request = ProvisionAttestationKeyRequest::new();
    request.request_id = request_id.to_owned();
    request.device_attestation_chain = device_identity.certificate_chain.clone();
    request.response_encryption_key_chain = response_key_chain.to_vec();
    request.untrusted_device_serial = device_identity.untrusted_device_serial.clone();
    request.certificate_profile =
        MessageField::some(wire_attestation_key_profile(certificate_profile)?);
    let wrapping_leaf = split_concatenated_der_certificates(wrapping_key_leaf_certificate)
        .map_err(OverwriteRequestError::Backend)?;
    if wrapping_leaf.len() != 1 {
        return Err(OverwriteRequestError::Backend(
            "wrapping-key leaf field must contain exactly one certificate".to_owned(),
        ));
    }
    request.wrapping_key_chain.push(wrapping_leaf[0].to_vec());
    let wrapping_chain = split_concatenated_der_certificates(wrapping_key_remaining_chain)
        .map_err(OverwriteRequestError::Backend)?;
    request
        .wrapping_key_chain
        .extend(wrapping_chain.into_iter().map(|certificate| certificate.to_vec()));
    let digest = provision_device_identity_digest(&request);
    request.device_identity_signature = sign_device_identity(&device_identity.descriptor, &digest)
        .map_err(OverwriteRequestError::Backend)?;

    let request_bytes = request.write_to_bytes().map_err(|err| {
        OverwriteRequestError::Backend(format!(
            "attestation-key provisioning request encode failed: {err:?}"
        ))
    })?;
    let request_frame = encode_grpc_frame(&request_bytes).map_err(|err| {
        OverwriteRequestError::Backend(format!(
            "attestation-key provisioning request frame failed: {err}"
        ))
    })?;
    let client = backend_client()?;
    request_with_retry("attestation-key provisioning", request_id, |remaining| {
        request_provision_once(client, request_id, &request_frame, remaining)
    })
}

fn backend_client() -> Result<&'static Client, OverwriteRequestError> {
    match BACKEND_CLIENT.get_or_init(|| {
        Client::builder()
            .use_rustls_tls()
            .connect_timeout(BACKEND_CONNECT_TIMEOUT)
            .timeout(BACKEND_REQUEST_TIMEOUT)
            .http2_adaptive_window(true)
            .tcp_keepalive(BACKEND_TCP_KEEPALIVE)
            .tcp_keepalive_interval(BACKEND_TCP_KEEPALIVE_INTERVAL)
            .tcp_keepalive_retries(3_u32)
            .tcp_user_timeout(BACKEND_TCP_USER_TIMEOUT)
            .build()
            .map_err(|err| format!("attestation overwrite HTTP client failed: {err:?}"))
    }) {
        Ok(client) => Ok(client),
        Err(message) => Err(OverwriteRequestError::Backend(message.clone())),
    }
}

fn request_overwrite_once(
    client: &Client,
    request_id: &str,
    request_frame: &[u8],
    timeout: Duration,
) -> Result<OverwriteAttestationResponse, OverwriteAttemptError> {
    let payload = request_rpc_once(
        client,
        request_id,
        request_frame,
        timeout,
        "OverwriteAttestation",
        "attestation overwrite",
    )?;
    OverwriteAttestationResponse::parse_from_bytes(&payload).map_err(|err| {
        OverwriteAttemptError::Retryable(format!(
            "attestation overwrite response decode failed: {err:?}"
        ))
    })
}

fn request_provision_once(
    client: &Client,
    request_id: &str,
    request_frame: &[u8],
    timeout: Duration,
) -> Result<ProvisionAttestationKeyResponse, OverwriteAttemptError> {
    let payload = request_rpc_once(
        client,
        request_id,
        request_frame,
        timeout,
        "ProvisionAttestationKey",
        "attestation-key provisioning",
    )?;
    ProvisionAttestationKeyResponse::parse_from_bytes(&payload).map_err(|err| {
        OverwriteAttemptError::Retryable(format!(
            "attestation-key provisioning response decode failed: {err:?}"
        ))
    })
}

fn request_rpc_once(
    client: &Client,
    request_id: &str,
    request_frame: &[u8],
    timeout: Duration,
    method: &str,
    operation: &str,
) -> Result<Vec<u8>, OverwriteAttemptError> {
    let mut response = client
        .post(backend_grpc_url(method))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("user-agent", "DroidfoodAttestationFixer/0.1")
        .timeout(timeout)
        .body(request_frame.to_vec())
        .send()
        .map_err(|err| {
            OverwriteAttemptError::Retryable(format!("{operation} HTTP/2 failed: {err:?}"))
        })?;

    let http_status = response.status();
    let grpc_status = response
        .headers()
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let grpc_message = response
        .headers()
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| "INVALID_ARGUMENT".to_owned());
    let grpc_failed = match grpc_status.as_deref() {
        Some(status) => status != "0",
        None => false,
    };
    if !http_status.is_success() || grpc_failed {
        if grpc_status.as_deref() == Some("3") {
            return Err(OverwriteAttemptError::InvalidArgument(grpc_message));
        }
        let message =
            format!("{operation} rejected: http_status={http_status} grpc_status={grpc_status:?}");
        if http_status.is_server_error() || http_status.as_u16() == 429 {
            return Err(OverwriteAttemptError::Retryable(message));
        }
        return Err(OverwriteAttemptError::Fatal(message));
    }

    let body = read_grpc_response_body(&mut response).map_err(OverwriteAttemptError::Retryable)?;
    if body.is_empty() && grpc_status.is_none() {
        intensive_log!(
            "{operation} returned an empty gRPC body without exposed trailers; treating as INVALID_ARGUMENT: request_id={request_id}"
        );
        return Err(OverwriteAttemptError::EmptyResponse);
    }
    decode_grpc_frame(&body).map_err(|err| {
        OverwriteAttemptError::Retryable(format!("{operation} response frame failed: {err}"))
    })
}

fn read_grpc_response_body(response: &mut Response) -> Result<Vec<u8>, String> {
    if response.content_length().is_some_and(|len| len > GRPC_MAX_MESSAGE_BYTES as u64 + 5) {
        return Err("backend response exceeds the size limit".to_owned());
    }
    let mut body = Vec::new();
    response
        .take((GRPC_MAX_MESSAGE_BYTES + 6) as u64)
        .read_to_end(&mut body)
        .map_err(|err| format!("backend response read failed: {err:?}"))?;
    if body.len() > GRPC_MAX_MESSAGE_BYTES + 5 {
        return Err("backend response exceeds the size limit".to_owned());
    }
    Ok(body)
}

fn encode_grpc_frame(payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > GRPC_MAX_MESSAGE_BYTES {
        return Err("request payload exceeds the gRPC message size limit".to_owned());
    }
    let len = u32::try_from(payload.len()).map_err(|_| "payload too large".to_owned())?;
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn decode_grpc_frame(body: &[u8]) -> Result<Vec<u8>, String> {
    if body.len() < 5 {
        return Err("response body is shorter than a gRPC frame header".to_owned());
    }
    if body[0] != 0 {
        return Err("compressed gRPC response is not supported".to_owned());
    }
    let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    if len > GRPC_MAX_MESSAGE_BYTES {
        return Err("gRPC message payload exceeds the size limit".to_owned());
    }
    let frame_len =
        5usize.checked_add(len).ok_or_else(|| "gRPC message length overflow".to_owned())?;
    if body.len() < frame_len {
        return Err("response body ended before the gRPC message payload".to_owned());
    }
    if body.len() != frame_len {
        return Err("response body contained trailing gRPC data".to_owned());
    }
    Ok(body[5..frame_len].to_vec())
}

fn is_internal_identity_certificate(leaf_certificate: &[u8]) -> bool {
    let prefix = RESPONSE_KEY_CHALLENGE_PREFIX.as_bytes();
    let identity_challenge = device_identity_challenge();
    leaf_certificate.windows(prefix.len()).any(|window| window == prefix)
        || leaf_certificate
            .windows(identity_challenge.len())
            .any(|window| window == identity_challenge)
}

fn generate_response_key(request_id: &str) -> Result<ResponseKey, Status> {
    let keystore = keystore_service()?;
    let security_level =
        keystore.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).map_err(|err| {
            service_error(ERROR_SERVER_REQUEST, &format!("keystore security level failed: {err:?}"))
        })?;
    let descriptor = KeyDescriptor {
        domain: Domain::APP,
        nspace: -1,
        alias: Some(format!("{RESPONSE_KEY_ALIAS_PREFIX}{request_id}")),
        blob: None,
    };
    let params = response_key_params(request_id, ResponseIdentity::None);
    let metadata = security_level
        .generateKey(&descriptor, None, &params, 0, b"MysticAttestation")
        .map_err(|err| {
            service_error(ERROR_SERVER_REQUEST, &format!("response key generation failed: {err:?}"))
        })?;
    let certificate_chain = certificate_chain_from_metadata(
        metadata.certificate,
        metadata.certificateChain,
        "response key",
    )?;
    Ok(ResponseKey { descriptor: metadata.key, certificate_chain })
}

fn load_or_generate_device_identity() -> Result<DeviceIdentityKey, Status> {
    if let Some(identity) = load_device_identity(DEVICE_IDENTITY_TRUSTED_ALIAS, false)? {
        return Ok(identity);
    }
    if let Some(identity) = load_device_identity(DEVICE_IDENTITY_FALLBACK_ALIAS, true)? {
        return Ok(identity);
    }

    let keystore = keystore_service()?;
    let security_level =
        keystore.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).map_err(|err| {
            service_error(ERROR_SERVER_REQUEST, &format!("keystore security level failed: {err:?}"))
        })?;
    let trusted_descriptor = app_key_descriptor(DEVICE_IDENTITY_TRUSTED_ALIAS);
    let full_params = device_identity_params(ResponseIdentity::Full);
    let metadata = match security_level.generateKey(
        &trusted_descriptor,
        None,
        &full_params,
        0,
        b"MysticAttestation",
    ) {
        Ok(metadata) => metadata,
        Err(full_err) => {
            delete_key(&trusted_descriptor);
            intensive_log!(
                "full persistent device identity rejected; retrying with serial: {full_err:?}"
            );
            let serial_params = device_identity_params(ResponseIdentity::Serial);
            match security_level.generateKey(
                &trusted_descriptor,
                None,
                &serial_params,
                0,
                b"MysticAttestation",
            ) {
                Ok(metadata) => metadata,
                Err(serial_err) => {
                    delete_key(&trusted_descriptor);
                    return generate_fallback_device_identity(
                        &security_level,
                        full_err,
                        serial_err,
                    );
                }
            }
        }
    };
    let certificate_chain = certificate_chain_from_metadata(
        metadata.certificate,
        metadata.certificateChain,
        "device identity",
    )?;
    Ok(DeviceIdentityKey {
        descriptor: metadata.key,
        certificate_chain,
        untrusted_device_serial: String::new(),
    })
}

fn load_device_identity(alias: &str, fallback: bool) -> Result<Option<DeviceIdentityKey>, Status> {
    let descriptor = app_key_descriptor(alias);
    let keystore = keystore_service()?;
    let entry = match keystore.getKeyEntry(&descriptor) {
        Ok(entry) => entry,
        Err(_) => return Ok(None),
    };
    let certificate_chain = certificate_chain_from_metadata(
        entry.metadata.certificate,
        entry.metadata.certificateChain,
        "stored device identity",
    )?;
    let untrusted_device_serial = if fallback { fallback_device_serial()? } else { String::new() };
    Ok(Some(DeviceIdentityKey {
        descriptor: entry.metadata.key,
        certificate_chain,
        untrusted_device_serial,
    }))
}

fn generate_fallback_device_identity(
    security_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    full_err: binder::Status,
    serial_err: binder::Status,
) -> Result<DeviceIdentityKey, Status> {
    let serial = fallback_device_serial()?;
    error!(
        "hardware serial attestation failed; using a persistent hardware key plus UNTRUSTED \
         ro.serialno: full={full_err:?}, serial={serial_err:?}"
    );
    let descriptor = app_key_descriptor(DEVICE_IDENTITY_FALLBACK_ALIAS);
    let metadata = security_level
        .generateKey(
            &descriptor,
            None,
            &device_identity_params(ResponseIdentity::None),
            0,
            b"MysticAttestation",
        )
        .map_err(|err| {
            service_error(
                ERROR_SERVER_REQUEST,
                &format!("fallback device identity generation failed: {err:?}"),
            )
        })?;
    let certificate_chain = certificate_chain_from_metadata(
        metadata.certificate,
        metadata.certificateChain,
        "fallback device identity",
    )?;
    Ok(DeviceIdentityKey {
        descriptor: metadata.key,
        certificate_chain,
        untrusted_device_serial: serial,
    })
}

fn fallback_device_serial() -> Result<String, Status> {
    let serial = String::from_utf8_lossy(&get_system_prop("ro.serialno")).trim().to_owned();
    if serial.is_empty() {
        return Err(service_error(
            ERROR_SERVER_REQUEST,
            "hardware serial attestation failed and ro.serialno is empty",
        ));
    }
    Ok(serial)
}

fn app_key_descriptor(alias: &str) -> KeyDescriptor {
    KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias.to_owned()), blob: None }
}

fn certificate_chain_from_metadata(
    certificate: Option<Vec<u8>>,
    remaining_chain: Option<Vec<u8>>,
    description: &str,
) -> Result<Vec<Vec<u8>>, Status> {
    let mut certificate_chain = Vec::new();
    certificate_chain.push(certificate.ok_or_else(|| {
        service_error(ERROR_SERVER_REQUEST, &format!("{description} returned no certificate"))
    })?);
    if let Some(chain) = remaining_chain {
        if !chain.is_empty() {
            certificate_chain.push(chain);
        }
    }
    Ok(certificate_chain)
}

#[derive(Clone, Copy)]
enum ResponseIdentity {
    Full,
    Serial,
    None,
}

fn response_key_params(request_id: &str, identity: ResponseIdentity) -> Vec<KeyParameter> {
    let mut params = vec![
        key_param(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::EC)),
        key_param(Tag::EC_CURVE, KeyParameterValue::EcCurve(EcCurve::P_256)),
        key_param(Tag::PURPOSE, KeyParameterValue::KeyPurpose(KeyPurpose::AGREE_KEY)),
        key_param(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        key_param(Tag::NO_AUTH_REQUIRED, KeyParameterValue::BoolValue(true)),
        key_param(
            Tag::ATTESTATION_CHALLENGE,
            KeyParameterValue::Blob(response_key_challenge(request_id)),
        ),
        key_param(
            Tag::CERTIFICATE_NOT_AFTER,
            KeyParameterValue::DateTime(RESPONSE_CERT_NOT_AFTER_MS),
        ),
        key_param(Tag::CERTIFICATE_SERIAL, KeyParameterValue::Blob(vec![1])),
    ];
    params.extend(device_attestation_params(identity));
    params
}

fn device_identity_params(identity: ResponseIdentity) -> Vec<KeyParameter> {
    let mut params = vec![
        key_param(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::EC)),
        key_param(Tag::EC_CURVE, KeyParameterValue::EcCurve(EcCurve::P_256)),
        key_param(Tag::PURPOSE, KeyParameterValue::KeyPurpose(KeyPurpose::SIGN)),
        key_param(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        key_param(Tag::NO_AUTH_REQUIRED, KeyParameterValue::BoolValue(true)),
        key_param(Tag::ATTESTATION_CHALLENGE, KeyParameterValue::Blob(device_identity_challenge())),
        key_param(
            Tag::CERTIFICATE_NOT_AFTER,
            KeyParameterValue::DateTime(RESPONSE_CERT_NOT_AFTER_MS),
        ),
        key_param(Tag::CERTIFICATE_SERIAL, KeyParameterValue::Blob(vec![2])),
    ];
    params.extend(device_attestation_params(identity));
    params
}

fn decrypt_response(
    request_id: &str,
    key: &KeyDescriptor,
    response: &OverwriteAttestationResponse,
) -> Result<OverwriteAttestationResponsePlaintext, String> {
    let plaintext = decrypt_response_envelope(
        request_id,
        key,
        &response.encrypted_response,
        &response.response_nonce,
        &response.response_ephemeral_public_key,
        RESPONSE_HKDF_INFO,
        RESPONSE_AAD_PREFIX,
    )?;
    OverwriteAttestationResponsePlaintext::parse_from_bytes(&plaintext)
        .map_err(|err| format!("response payload decode failed: {err:?}"))
}

fn decrypt_provision_response(
    request_id: &str,
    key: &KeyDescriptor,
    response: &ProvisionAttestationKeyResponse,
) -> Result<ProvisionAttestationKeyResponsePlaintext, String> {
    let plaintext = decrypt_response_envelope(
        request_id,
        key,
        &response.encrypted_response,
        &response.response_nonce,
        &response.response_ephemeral_public_key,
        PROVISION_RESPONSE_HKDF_INFO,
        PROVISION_RESPONSE_AAD_PREFIX,
    )?;
    ProvisionAttestationKeyResponsePlaintext::parse_from_bytes(&plaintext)
        .map_err(|err| format!("provisioning response payload decode failed: {err:?}"))
}

fn decrypt_response_envelope(
    request_id: &str,
    key: &KeyDescriptor,
    encrypted_response: &[u8],
    response_nonce: &[u8],
    response_ephemeral_public_key: &[u8],
    hkdf_info: &[u8],
    aad_prefix: &str,
) -> Result<Vec<u8>, String> {
    if encrypted_response.is_empty()
        || response_nonce.is_empty()
        || response_ephemeral_public_key.is_empty()
    {
        return Err("server returned an incomplete encrypted response".to_owned());
    }
    let secret = derive_keymint_secret(key, response_ephemeral_public_key)?;
    let aes_key = derive_response_aes_key(request_id, &secret, hkdf_info)?;
    aes_gcm_decrypt(
        &aes_key,
        response_nonce,
        encrypted_response,
        response_aad(aad_prefix, request_id).as_bytes(),
    )
}

fn validate_provisioned_attestation_key(
    provisioned: &ProvisionAttestationKeyResponsePlaintext,
) -> Result<(), String> {
    if provisioned.secure_key_wrapper.is_empty()
        || provisioned.leaf_certificate.is_empty()
        || provisioned.remaining_chain.is_empty()
    {
        return Err("server returned incomplete attestation-key material".to_owned());
    }

    let leaf_der = split_concatenated_der_certificates(&provisioned.leaf_certificate)?;
    if leaf_der.len() != 1 {
        return Err("provisioned leaf field contains more than one certificate".to_owned());
    }
    let certificate = X509::from_der(leaf_der[0])
        .map_err(|err| format!("provisioned leaf certificate is invalid: {err:?}"))?;
    let chain_der = split_concatenated_der_certificates(&provisioned.remaining_chain)?;
    let mut fingerprints = HashSet::with_capacity(chain_der.len() + 1);
    fingerprints.insert(sha256(leaf_der[0]));

    let mut chain = Vec::with_capacity(chain_der.len());
    for (index, der) in chain_der.iter().enumerate() {
        if !fingerprints.insert(sha256(der)) {
            return Err(format!(
                "provisioned certificate chain contains duplicate certificate {index}"
            ));
        }
        chain.push(
            X509::from_der(der)
                .map_err(|err| format!("provisioned certificate {index} is invalid: {err:?}"))?,
        );
    }

    verify_certificate_signature(&certificate, &chain[0], "leaf")?;
    for (index, pair) in chain.windows(2).enumerate() {
        verify_certificate_signature(&pair[0], &pair[1], &format!("chain certificate {index}"))?;
    }
    Ok(())
}

fn split_concatenated_der_certificates(mut encoded: &[u8]) -> Result<Vec<&[u8]>, String> {
    const MAX_CHAIN_CERTIFICATES: usize = 16;

    let mut certificates = Vec::new();
    while !encoded.is_empty() {
        if certificates.len() == MAX_CHAIN_CERTIFICATES {
            return Err("provisioned certificate chain is too long".to_owned());
        }
        if encoded.len() < 2 || encoded[0] != 0x30 {
            return Err("provisioned certificate chain is not concatenated DER".to_owned());
        }

        let first_length = encoded[1];
        let (header_length, content_length) = if first_length & 0x80 == 0 {
            (2usize, usize::from(first_length))
        } else {
            let length_bytes = usize::from(first_length & 0x7f);
            if length_bytes == 0 || length_bytes > std::mem::size_of::<usize>() {
                return Err("provisioned certificate has an invalid DER length".to_owned());
            }
            if encoded.len() < 2 + length_bytes || encoded[2] == 0 {
                return Err("provisioned certificate has a truncated or non-canonical DER length"
                    .to_owned());
            }
            let mut length = 0usize;
            for byte in &encoded[2..2 + length_bytes] {
                length = length
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(usize::from(*byte)))
                    .ok_or_else(|| "provisioned certificate DER length overflowed".to_owned())?;
            }
            if length < 128 {
                return Err("provisioned certificate has a non-canonical DER length".to_owned());
            }
            (2 + length_bytes, length)
        };

        let certificate_length = header_length
            .checked_add(content_length)
            .ok_or_else(|| "provisioned certificate DER length overflowed".to_owned())?;
        if certificate_length > encoded.len() {
            return Err("provisioned certificate is truncated".to_owned());
        }
        certificates.push(&encoded[..certificate_length]);
        encoded = &encoded[certificate_length..];
    }

    if certificates.is_empty() {
        return Err("provisioned certificate chain is empty".to_owned());
    }
    Ok(certificates)
}

fn leaf_is_signed_by_first_issuer(leaf_der: &[u8], remaining_chain: &[u8]) -> Result<bool, String> {
    let leaf = X509::from_der(leaf_der)
        .map_err(|err| format!("attestation leaf certificate is invalid: {err:?}"))?;
    let Ok(certificates) = split_concatenated_der_certificates(remaining_chain) else {
        return Ok(false);
    };
    let Some(issuer_der) = certificates.first() else {
        return Ok(false);
    };
    let Ok(issuer) = X509::from_der(issuer_der) else {
        return Ok(false);
    };
    let Ok(issuer_key) = issuer.public_key() else {
        return Ok(false);
    };
    Ok(leaf.verify(&issuer_key).unwrap_or(false))
}

fn verify_certificate_signature(
    child: &X509Ref,
    issuer: &X509Ref,
    description: &str,
) -> Result<(), String> {
    let issuer_name = child
        .issuer_name()
        .to_der()
        .map_err(|err| format!("{description} issuer name is invalid: {err:?}"))?;
    let subject_name = issuer
        .subject_name()
        .to_der()
        .map_err(|err| format!("{description} parent subject is invalid: {err:?}"))?;
    if issuer_name != subject_name {
        return Err(format!("{description} issuer does not match its parent subject"));
    }

    let issuer_key = issuer
        .public_key()
        .map_err(|err| format!("{description} parent public key is invalid: {err:?}"))?;
    if !child
        .verify(&issuer_key)
        .map_err(|err| format!("{description} signature validation failed: {err:?}"))?
    {
        return Err(format!("{description} is not signed by its parent certificate"));
    }
    Ok(())
}

fn derive_keymint_secret(key: &KeyDescriptor, peer_public_key: &[u8]) -> Result<Vec<u8>, String> {
    let keystore =
        raw_keystore_service().map_err(|err| format!("keystore connect failed: {err:?}"))?;
    let security_level = keystore
        .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .map_err(|err| format!("keystore security level failed: {err:?}"))?;
    let params =
        vec![key_param(Tag::PURPOSE, KeyParameterValue::KeyPurpose(KeyPurpose::AGREE_KEY))];
    let operation = security_level
        .createOperation(key, &params, false)
        .map_err(|err| format!("response key operation failed: {err:?}"))?;
    let operation =
        operation.iOperation.ok_or_else(|| "response key operation missing".to_owned())?;
    operation
        .finish(Some(peer_public_key), None)
        .map_err(|err| format!("response key agreement failed: {err:?}"))?
        .ok_or_else(|| "response key agreement returned no secret".to_owned())
}

fn sign_device_identity(key: &KeyDescriptor, request_digest: &[u8]) -> Result<Vec<u8>, String> {
    if request_digest.len() != 32 {
        return Err("device identity request digest must be 32 bytes".to_owned());
    }
    let keystore =
        raw_keystore_service().map_err(|err| format!("keystore connect failed: {err:?}"))?;
    let security_level = keystore
        .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .map_err(|err| format!("keystore security level failed: {err:?}"))?;
    let params = vec![
        key_param(Tag::PURPOSE, KeyParameterValue::KeyPurpose(KeyPurpose::SIGN)),
        key_param(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
    ];
    let operation = security_level
        .createOperation(key, &params, false)
        .map_err(|err| format!("device identity signing operation failed: {err:?}"))?;
    let operation = operation
        .iOperation
        .ok_or_else(|| "device identity signing operation missing".to_owned())?;
    operation
        .finish(Some(request_digest), None)
        .map_err(|err| format!("device identity signing failed: {err:?}"))?
        .ok_or_else(|| "device identity signing returned no signature".to_owned())
}

fn overwrite_device_identity_digest(request: &OverwriteAttestationRequest) -> Vec<u8> {
    let mut canonical = Vec::new();
    push_identity_field(&mut canonical, DEVICE_IDENTITY_REQUEST_DOMAIN);
    push_identity_field(&mut canonical, b"OverwriteAttestation");
    push_identity_u32(&mut canonical, request.protocol_version);
    push_identity_field(&mut canonical, request.request_id.trim().as_bytes());
    push_identity_field(&mut canonical, &request.leaf_certificate);
    push_identity_field(&mut canonical, &request.remaining_chain);
    push_identity_fields(&mut canonical, &request.device_attestation_chain);
    push_identity_fields(&mut canonical, &request.response_encryption_key_chain);
    push_identity_field(&mut canonical, request.untrusted_device_serial.trim().as_bytes());
    sha256(&canonical).to_vec()
}

fn provision_device_identity_digest(request: &ProvisionAttestationKeyRequest) -> Vec<u8> {
    let mut canonical = Vec::new();
    push_identity_field(&mut canonical, DEVICE_IDENTITY_REQUEST_DOMAIN);
    push_identity_field(&mut canonical, b"ProvisionAttestationKey");
    push_identity_u32(&mut canonical, ATTESTATION_PROTOCOL_VERSION);
    push_identity_field(&mut canonical, request.request_id.trim().as_bytes());
    push_identity_fields(&mut canonical, &request.device_attestation_chain);
    push_identity_fields(&mut canonical, &request.response_encryption_key_chain);
    push_identity_field(&mut canonical, request.untrusted_device_serial.trim().as_bytes());
    if let Some(profile) = request.certificate_profile.as_ref() {
        push_identity_u32(&mut canonical, 1);
        push_identity_field(&mut canonical, &profile.subject_der);
        push_identity_field(&mut canonical, &profile.serial_number);
        canonical.extend_from_slice(&profile.not_before_ms.to_be_bytes());
        canonical.extend_from_slice(&profile.not_after_ms.to_be_bytes());
        push_identity_field(&mut canonical, &profile.attestation_challenge);
        push_identity_field(&mut canonical, &profile.attestation_application_id);
    } else {
        push_identity_u32(&mut canonical, 0);
    }
    push_identity_fields(&mut canonical, &request.wrapping_key_chain);
    sha256(&canonical).to_vec()
}

fn push_identity_fields(canonical: &mut Vec<u8>, values: &[Vec<u8>]) {
    push_identity_u32(canonical, values.len() as u32);
    for value in values {
        push_identity_field(canonical, value);
    }
}

fn push_identity_field(canonical: &mut Vec<u8>, value: &[u8]) {
    canonical.extend_from_slice(&(value.len() as u64).to_be_bytes());
    canonical.extend_from_slice(value);
}

fn push_identity_u32(canonical: &mut Vec<u8>, value: u32) {
    canonical.extend_from_slice(&value.to_be_bytes());
}

fn derive_response_aes_key(
    request_id: &str,
    secret: &[u8],
    hkdf_info: &[u8],
) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    let salt = sha256(&response_key_challenge(request_id));
    hkdf(&mut key, Md::sha256(), secret, &salt, hkdf_info)
        .map_err(|err| format!("response key derivation failed: {err:?}"))?;
    Ok(key)
}

fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    encrypted: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    const GCM_TAG_LEN: usize = 16;
    if encrypted.len() < GCM_TAG_LEN {
        return Err("encrypted response is too short".to_owned());
    }
    let (ciphertext, tag) = encrypted.split_at(encrypted.len() - GCM_TAG_LEN);
    let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, key, Some(nonce))
        .map_err(|err| format!("response decrypt init failed: {err:?}"))?;
    crypter.pad(false);
    crypter.aad_update(aad).map_err(|err| format!("response decrypt aad failed: {err:?}"))?;
    crypter.set_tag(tag).map_err(|err| format!("response decrypt tag failed: {err:?}"))?;
    let mut out = vec![0u8; ciphertext.len() + Cipher::aes_256_gcm().block_size()];
    let count = crypter
        .update(ciphertext, &mut out)
        .map_err(|err| format!("response decrypt update failed: {err:?}"))?;
    let rest = crypter
        .finalize(&mut out[count..])
        .map_err(|err| format!("response decrypt verify failed: {err:?}"))?;
    out.truncate(count + rest);
    Ok(out)
}

fn keystore_service() -> Result<binder::Strong<dyn IKeystoreService>, Status> {
    raw_keystore_service().map_err(|err| {
        service_error(ERROR_SERVER_REQUEST, &format!("keystore connect failed: {err:?}"))
    })
}

fn raw_keystore_service() -> binder::Result<binder::Strong<dyn IKeystoreService>> {
    Ok(binder::get_interface(KEYSTORE2_SERVICE)?)
}

fn delete_key(key: &KeyDescriptor) {
    match raw_keystore_service().and_then(|keystore| keystore.deleteKey(key)) {
        Ok(()) => intensive_log!("deleted response key"),
        Err(err) => error!("failed to delete response key: {err:?}"),
    }
}

fn key_param(tag: Tag, value: KeyParameterValue) -> KeyParameter {
    KeyParameter { tag, value }
}

fn device_attestation_params(identity: ResponseIdentity) -> Vec<KeyParameter> {
    let ids = match identity {
        ResponseIdentity::Full => &[
            (Tag::ATTESTATION_ID_BRAND, "brand"),
            (Tag::ATTESTATION_ID_DEVICE, "device"),
            (Tag::ATTESTATION_ID_PRODUCT, "name"),
            (Tag::ATTESTATION_ID_SERIAL, "serialno"),
            (Tag::ATTESTATION_ID_MANUFACTURER, "manufacturer"),
            (Tag::ATTESTATION_ID_MODEL, "model"),
        ][..],
        ResponseIdentity::Serial => &[(Tag::ATTESTATION_ID_SERIAL, "serialno")][..],
        ResponseIdentity::None => &[],
    };
    ids.iter()
        .filter_map(|&(tag, property)| {
            let value = get_attest_id_value(tag, property);
            if value.is_empty() {
                None
            } else {
                Some(key_param(tag, KeyParameterValue::Blob(value)))
            }
        })
        .collect()
}

fn get_attest_id_value(attest_id: Tag, prop_name: &str) -> Vec<u8> {
    if attest_id == Tag::ATTESTATION_ID_SERIAL {
        return get_system_prop(&format!("ro.{prop_name}"));
    }

    let attestation_prop = get_system_prop(&format!("ro.product.{prop_name}_for_attestation"));
    if !attestation_prop.is_empty() {
        return attestation_prop;
    }
    let vendor_prop = get_system_prop(&format!("ro.product.vendor.{prop_name}"));
    if !vendor_prop.is_empty() {
        return vendor_prop;
    }
    get_system_prop(&format!("ro.product.{prop_name}"))
}

fn get_system_prop(name: &str) -> Vec<u8> {
    match system_properties::read(name) {
        Ok(Some(value)) => value.as_bytes().to_vec(),
        _ => vec![],
    }
}

fn response_key_challenge(request_id: &str) -> Vec<u8> {
    format!("{RESPONSE_KEY_CHALLENGE_PREFIX}{request_id}").into_bytes()
}

fn device_identity_challenge() -> Vec<u8> {
    sha256(DEVICE_IDENTITY_CHALLENGE_DOMAIN).to_vec()
}

fn response_aad(prefix: &str, request_id: &str) -> String {
    format!("{prefix}{request_id}")
}

fn service_error(code: i32, message: &str) -> Status {
    Status::new_service_specific_error_str(code, Some(message))
}
