Throwaway fixtures for the enrollment-replay tests in certs.service.spec.ts,
made offline with OpenSSL 3.6.2 on 2026-10-25. Public material only; the two
private keys were shredded.
enroll.csr     CSR, CN=replay-fixture, key A
enroll.crt     self-signed certificate, CN=replay-fixture, key A (the "issued" one)
other-key.crt  same CN, key B (a different device)
other-cn.crt   key A, CN=someone-else
expired.crt    CN=replay-fixture, another key, valid 2020-01-01 to 2020-01-02 (expired)
