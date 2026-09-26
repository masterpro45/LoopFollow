# LoopFollow — Sweet Miranda fork (masterpro45/LoopFollow)

LoopFollow runs on the caregiver's phone. This fork adds the **Sweet Miranda approver**: Face ID approval of settings proposals for Miranda's Trio. The Trio side, safety rules and the build/test runbook are in `masterpro45/Trio`: see `CLAUDE.md` and `.claude/skills/sweet-miranda-release/SKILL.md` there.

## Branches and builds

- `main` tracks upstream `loopandlearn/LoopFollow` releases (currently v7.1.0).
- `sweetmiranda` is the approver feature on top of `main`.
- `claude/approver-token-char-count-75brkh` is `sweetmiranda` plus the expiry check before signing. Merge it into `sweetmiranda` before the next build from that branch.
- Builds run through **Actions → Build LoopFollow** (`build_LoopFollow.yml`), started manually. About 8 min, uploaded to TestFlight.

## Where the code is

All in `LoopFollow/SweetMiranda/SweetMirandaApproverView.swift`, plus one row in `Settings/SettingsMenuView.swift` (Settings › Sweet Miranda).

- Creating a key makes a Secure Enclave P-256 key with `.biometryCurrentSet` (Face ID only, no passcode fallback) and posts an `enroll` document to Nightscout. Trio ignores `enroll`: the dashboard turns it into an `approver.add` proposal, which only Miranda's phone can approve.
- Approving reads a pending proposal from Nightscout, signs it and posts an `approval` document. Her Trio checks the signature and applies the change.
- It uses its own narrow Nightscout token, separate from the main LoopFollow one.

## Signing contract (must match Trio's `SMApprovers` exactly)

```
payload   = "SMAPPROVE1|<smId>|<sha256 hex of sorted-keys JSON of smChanges>|<smExpires as sent>"
signature = ECDSA P-256 (SecKeyCreateSignature, .ecdsaSignatureMessageX962SHA256), DER
keyId     = first 16 hex chars of SHA-256(x9.63 public key)
```

- Only sign when `smExpires` is in the future and at most 24 h + 5 min away (`SweetMirandaApprover.signableExpiry`), because Trio ignores any other signature.
- Never sign `approver.*` proposals: those need her phone.
- If you change any of this, change Trio in the same round and build both apps.
