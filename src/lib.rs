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

//! This crate implements droidfoodattestation

use log::{error, info};

use android_security_postprocessor::aidl::android::security::postprocessor::{
    CertificateChain::CertificateChain,
    IKeystoreCertificatePostProcessor::IKeystoreCertificatePostProcessor,
};

use android_security_postprocessor::binder::{Interface, Status};
use base64::prelude::*;
use serde_json::Value;
use std::ops::Deref;
use uuid::Uuid;

#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("http_client.h");
        fn get_new_certificate_chain(old_certificate_chain: &str) -> UniquePtr<CxxVector<u8>>;
    }
}

const ERROR_JSON_DECODE: i32 = -2;
const ERROR_SERVER_RESPONSE: i32 = -3;

/// The `IKeystoreCertificatePostProcessor` implementation.
pub struct KeystoreCertificatePostProcessor;

impl Interface for KeystoreCertificatePostProcessor {}

impl IKeystoreCertificatePostProcessor for KeystoreCertificatePostProcessor {
    fn processKeystoreCertificates(
        &self,
        old_keymint_certificates: &CertificateChain,
    ) -> Result<CertificateChain, Status> {
        let old_leaf_certificate = &old_keymint_certificates.leafCertificate;
        let old_attestation_chain = &old_keymint_certificates.remainingChain;

        let request_id = Uuid::new_v4();

        // Generate the encoded request to be sent to Greenboot servers.
        let encoded_request = "{\"certificate_chain\": [".to_owned()
            + "\""
            + &BASE64_STANDARD.encode(old_leaf_certificate)
            + "\",\""
            + &BASE64_STANDARD.encode(old_attestation_chain)
            + "\"], \"request_id\":\""
            + &request_id.to_string()
            + "\"}";
        info!("sending request to server: request_id: {}", &request_id);

        // Receive the response from libcurl implementation, parse it, and
        // convert it into the format keystore understands.
        let ffi_result = ffi::get_new_certificate_chain(&encoded_request);
        let ffi_response = ffi_result.deref().as_slice();
        let response: Value = match serde_json::from_str(&String::from_utf8_lossy(ffi_response)) {
            Ok(res) => res,
            Err(e) => {
                error!("Error when trying to decode message: {:?}, error: {:#?}", ffi_response, e);
                return Err(Status::new_service_specific_error_str(
                    ERROR_JSON_DECODE,
                    Some("Failure when connecting to server."),
                ));
            }
        };
        info!("response received from server: {:#?}", response);
        if response["error"] != Value::Null {
            info!("Error on communicating with the server: {:?}", response["error"]);
            Err(Status::new_service_specific_error_str(
                ERROR_SERVER_RESPONSE,
                Some("Server responded with error."),
            ))
        } else {
            let overwritten_chain = response["overwrittenCertificateChain"].as_array().unwrap();
            let leaf_certificate = base64_decode(&overwritten_chain[0]);
            let remaining_chain = base64_decode(&overwritten_chain[1]);
            Ok(CertificateChain {
                leafCertificate: leaf_certificate?.to_vec(),
                remainingChain: remaining_chain?.to_vec(),
            })
        }
    }
}

fn base64_decode(v: &Value) -> Result<Vec<u8>, Status> {
    let certificate_bytes = match v.as_str() {
        Some(val) => BASE64_STANDARD.decode(val),
        None => {
            return Err(Status::new_service_specific_error_str(
                ERROR_JSON_DECODE,
                Some("Could not convert returned value from server to string."),
            ))
        }
    };
    match certificate_bytes {
        Ok(bytes) => Ok(bytes),
        Err(_) => Err(Status::new_service_specific_error_str(
            ERROR_JSON_DECODE,
            Some("Could not base64 decode the returned string"),
        )),
    }
}
