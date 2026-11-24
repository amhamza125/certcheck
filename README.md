# CertCheck

A credential verification registry for the GenLayer Bradbury testnet.

CertCheck lets anyone register a certificate claim and have it checked against the issuer's own public page. The check runs inside a GenLayer intelligent contract: the contract fetches the page, a validator jury compares the record, and the verdict is stored on-chain where anyone can read it — no screenshots, no manual review queue.

## How it works

1. A registrant calls `register` with the holder's name, the issuer, the certificate ID, and the URL of the issuer's public certificate page. The claim's evidence is bound with a SHA-256 hash at registration time.
2. `verify` fetches the issuer page and the jury checks two things: the record on the page matches the claim, and the page actually sits on the issuer's domain.
3. The verdict — `VERIFIED`, `REJECTED`, or `UNVERIFIABLE` — is stored on-chain with a reason code.

## Features

- Issuer-domain gate: a page hosted on an unrelated domain is rejected with `ISSUER_DOMAIN_MISMATCH`, even if the text on it looks right.
- Wrong-holder detection: a genuine page that names a different person is rejected with `WRONG_HOLDER`.
- SHA-256 evidence binding: the evidence hash is locked while a claim is open and released on every terminal state, so the same evidence can be registered again once a claim has finished.
- Registrant-only re-verification: only the account that registered a claim can ask for it to be verified again.
- Abandonment timeout: if a claim is left sitting with no verification, anyone can call `force_finalize` after the timeout. The claim closes as unverifiable and its hash lock is released, so no claim can squat on the registry forever.

## Contracts (Bradbury, chain 4221)

| Role | Address |
| --- | --- |
| Production | `0x4a1c58221f6F24077260EDc807c1D229179f9776` |
| Proof twin | `0xe35E8fA06236FBB971c65d8A517364b0F70aFe4F` |

## Live results

The live exhibits used a test issuer page published for this project, the fictional Bradbury Test Institute: https://bradbury-test-institute.vercel.app

- A genuine record that matches the page: **VERIFIED / MATCHES_RECORD**.
- The same certificate claimed under a different holder's name: **REJECTED / WRONG_HOLDER**.
- A claim pointing at a page on an unrelated domain: **REJECTED / ISSUER_DOMAIN_MISMATCH**.

## Main methods

| Method | What it does |
| --- | --- |
| `register(holder, issuer, certificate_id, issuer_page_url)` | Registers a certificate claim and binds its evidence hash. |
| `verify(claim_id)` | Fetches the issuer page, runs the jury check, and stores the verdict. |
| `get_claim(claim_id)` | Returns the stored claim and its verdict. |
| `force_finalize(claim_id)` | Closes an abandoned claim after the timeout and releases its hash lock. |
