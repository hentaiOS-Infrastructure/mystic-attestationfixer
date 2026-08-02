// SPDX-License-Identifier: Apache-2.0
package mystic.attestation.provisioner;

import mystic.attestation.provisioner.AttestationKeyCertificateProfile;
import mystic.attestation.provisioner.ProvisionedAttestationKey;

/** Supplies a backend-owned attestation key for immediate hardware import. */
@SensitiveData
interface IBackendAttestationKeyProvisioner {
    ProvisionedAttestationKey provisionAttestationKey(
            in AttestationKeyCertificateProfile certificateProfile,
            in byte[] wrappingKeyLeafCertificate,
            in byte[] wrappingKeyRemainingChain);
}
