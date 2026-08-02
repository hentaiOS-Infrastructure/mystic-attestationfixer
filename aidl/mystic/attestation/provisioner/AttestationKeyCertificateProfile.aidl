// SPDX-License-Identifier: Apache-2.0
package mystic.attestation.provisioner;

/** Caller-selected certificate fields for a backend-provisioned ATTEST_KEY. */
parcelable AttestationKeyCertificateProfile {
    byte[] subjectDer;
    byte[] serialNumber;
    long notBeforeMs;
    long notAfterMs;
    byte[] attestationChallenge;
    byte[] attestationApplicationId;
    /** Original Android caller; used locally to resolve a missing application ID. */
    int callerUid = -1;
}
