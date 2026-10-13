Real Android key attestation certificate chains, used to check that
`@humid/attest` parses the KeyDescription extension the way devices emit it.

Source: https://github.com/google/android-key-attestation (src/test/resources/pem
and ParsedAttestationRecordTest.java), Apache License 2.0, Copyright Google LLC.
These sample chains are not signed by Google's production root; the tests trust
their own root explicitly.
