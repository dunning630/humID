A real iPhone's App Attest attestation object and the assertion it made next (iOS 14.4,
development environment, 23 January 2021), used to check that `crates/humid-attest` reads
Apple's format the way devices emit it.

Source: https://github.com/veehaitch/devicecheck-appattest (src/test/resources/ios-14.4.yaml),
Apache License 2.0, Copyright Vincent Haupert. Only the first attestation and assertion samples
were kept, converted to JSON (`attestation_b64` and `assertion.assertion_b64` are unchanged).
They chain to Apple's production App Attestation root, so they are verified with the pinned
root, at the time they were made.
