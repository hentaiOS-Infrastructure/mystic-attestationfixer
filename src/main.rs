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

use droidfoodattestation::{KeystoreCertificatePostProcessor, INTENSIVE_LOGS_ENABLED};

use android_security_postprocessor::aidl::android::security::postprocessor::{
    IKeystoreCertificatePostProcessor::BnKeystoreCertificatePostProcessor,
};

use binder::binder_impl::Binder;
use binder::BinderFeatures;
use mystic_attestation_provisioner::aidl::mystic::attestation::provisioner::IBackendAttestationKeyProvisioner::BnBackendAttestationKeyProvisioner;

static SERVICE_NAME: &str = "rkp_cert_processor.service";

fn main() {
    let mut log_filter = FilterBuilder::new();
    log_filter.filter(None, log::LevelFilter::Info);
    if INTENSIVE_LOGS_ENABLED {
        log_filter.filter(Some("droidfoodattestation"), log::LevelFilter::Debug);
    }

    let log_level =
        if INTENSIVE_LOGS_ENABLED { log::LevelFilter::Debug } else { log::LevelFilter::Info };

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

    let provisioner = KeystoreCertificatePostProcessor;
    let provisioner_binder =
        BnBackendAttestationKeyProvisioner::new_binder(provisioner, BinderFeatures::default());

    let post_processor = KeystoreCertificatePostProcessor;
    let mut post_processor_binder = Binder::<BnKeystoreCertificatePostProcessor>::try_from(
        BnKeystoreCertificatePostProcessor::new_binder(post_processor, BinderFeatures::default())
            .as_binder(),
    )
    .expect("Failed to recover local keystore post processor binder");
    post_processor_binder
        .set_extension(&mut provisioner_binder.as_binder())
        .expect("Failed to attach attestation-key provisioner extension");

    binder::register_lazy_service(
        SERVICE_NAME,
        binder::Interface::as_binder(&post_processor_binder),
    )
    .expect("Failed to register keystore post processor");

    binder::ProcessState::join_thread_pool();
}
