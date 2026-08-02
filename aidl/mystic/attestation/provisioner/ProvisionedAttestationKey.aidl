// SPDX-License-Identifier: Apache-2.0
package mystic.attestation.provisioner;

/** One wrapped EC P-256 attestation key and its certificate chain. */
parcelable ProvisionedAttestationKey {
    byte[] secureKeyWrapper;
    byte[] leafCertificate;
    byte[] remainingChain;
}
