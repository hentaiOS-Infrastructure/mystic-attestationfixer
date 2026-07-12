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

//! This crate implements droidfoodattestation_server

use android_logger::FilterBuilder;
use log::{error, info};
use std::panic;

use droidfoodattestation::{intensive_logs_enabled, KeystoreCertificatePostProcessor};

use android_security_postprocessor::aidl::android::security::postprocessor::{
    IKeystoreCertificatePostProcessor::BnKeystoreCertificatePostProcessor
};

use android_security_postprocessor::binder::BinderFeatures;

static SERVICE_NAME: &str = "rkp_cert_processor.service";

fn main() {
    let mut log_filter = FilterBuilder::new();
    log_filter.filter(None, log::LevelFilter::Info);
    if intensive_logs_enabled() {
        log_filter.filter(Some("droidfoodattestation"), log::LevelFilter::Debug);
    }

    let log_level =
        if intensive_logs_enabled() { log::LevelFilter::Debug } else { log::LevelFilter::Info };

    // Initialize android logging
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("droidfood_attestation")
            .with_filter(log_filter.build())
            .with_max_level(log_level),
    );

    // Redirect panic messages to logcat
    panic::set_hook(Box::new(|panic_info| {
        error!("{panic_info}");
    }));

    info!("{SERVICE_NAME} starting up");

    let post_processor = KeystoreCertificatePostProcessor;
    let post_processor_binder =
        BnKeystoreCertificatePostProcessor::new_binder(post_processor, BinderFeatures::default());

    binder::register_lazy_service(SERVICE_NAME, post_processor_binder.as_binder())
        .expect("Failed to register keystore post processor");

    binder::ProcessState::join_thread_pool();
}
