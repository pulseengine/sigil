# WSC Key Lifecycle Management

This document describes the complete lifecycle of cryptographic keys in WSC, from generation to secure destruction.

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Date | 2026-01-04 |
| Classification | Public |
| Review Cycle | Annually |

---

## Key Types

### 1. Ed25519 Signing Keys

| Property | Value |
|----------|-------|
| Algorithm | Ed25519 (RFC 8032) |
| Key Size | 256-bit (32 bytes public, 64 bytes secret) |
| Security Level | 128-bit |
| Use Case | Long-term module signing |

### 2. ECDSA P-256 Ephemeral Keys

| Property | Value |
|----------|-------|
| Algorithm | ECDSA P-256 (secp256r1) |
| Key Size | 256-bit |
| Security Level | 128-bit |
| Use Case | Keyless signing (Sigstore) |
| Lifetime | Single use, zeroized after signing |

### 3. X.509 Certificate Keys

| Property | Value |
|----------|-------|
| Algorithm | Ed25519 or ECDSA P-256 |
| Use Case | Device provisioning |
| Lifetime | Certificate validity period |

---

## Key Lifecycle Phases

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Generation  │───►│  Storage    │───►│    Use      │───►│ Destruction │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                  │                  │                  │
      ▼                  ▼                  ▼                  ▼
  Entropy         Permissions          Signing           Zeroization
  Validation      Encryption (opt)    Verification       Secure Delete
```

---

## Phase 1: Key Generation

### Secure Generation Process

```rust
// Ed25519 key generation uses system CSPRNG
let keypair = KeyPair::generate();

// Ephemeral ECDSA uses p256 crate with OsRng
let signing_key = SigningKey::random(&mut OsRng);
```

### Entropy Sources

| Platform | Entropy Source |
|----------|---------------|
| Linux | /dev/urandom (getrandom syscall) |
| macOS | SecRandomCopyBytes |
| Windows | BCryptGenRandom |
| WASM | wasm_js getrandom |

### Generation Checklist

- [ ] Use system CSPRNG only
- [ ] Verify entropy source available
- [ ] Generate key ID if needed
- [ ] Log generation event (without key material)

---

## Phase 2: Key Storage

### File-Based Storage (Default)

```bash
# Secret key file permissions
-rw-------  (0600) owner read/write only

# Public key file permissions
-rw-r--r--  (0644) world readable
```

### Secure Storage Implementation

```rust
// src/secure_file.rs enforces permissions
pub fn write_secure(path: &Path, content: &[u8]) -> Result<()> {
    let file = File::create(path)?;
    set_secure_permissions(&file)?;  // 0600
    file.write_all(content)?;
    Ok(())
}
```

### Storage Locations

| Key Type | Default Location | Permissions |
|----------|-----------------|-------------|
| Secret Key | ~/.wsc/keys/*.sec | 0600 |
| Public Key | ~/.wsc/keys/*.pub | 0644 |
| Key Bundle | ~/.wsc/trust/*.json | 0644 |

### Encrypted Storage (Recommended for Production)

For high-security deployments:

```bash
# Encrypt secret key with passphrase
wsc key encrypt --key signing.sec --output signing.sec.enc

# Decrypt for use
wsc key decrypt --key signing.sec.enc --output signing.sec
```

### HSM Storage (Roadmap)

Future versions will support:
- TPM 2.0
- ATECC608A (I2C secure element)
- NXP SE050 EdgeLock
- ARM TrustZone

---

## Phase 3: Key Use

### Signing Operations

1. **Load key from secure storage**
   ```rust
   let sk = SecretKey::from_file("signing.sec")?;
   ```

2. **Sign module**
   ```rust
   let signed = sk.sign(module, Some(&key_id))?;
   ```

3. **Key stays in memory during operation**

4. **Automatic zeroization on drop**

### Verification Operations

1. **Load public key or key set**
   ```rust
   let pk = PublicKey::from_file("signing.pub")?;
   ```

2. **Verify signature**
   ```rust
   pk.verify(&mut reader, None)?;
   ```

### Key Rotation

Recommended rotation schedule:

| Key Type | Rotation Period | Trigger |
|----------|----------------|---------|
| Signing Key | 1-2 years | Policy, compromise |
| Ephemeral | Single use | Automatic |
| CA Certificate | 5-10 years | CA policy |
| Device Certificate | 1-2 years | Renewal |

---

## Phase 4: Key Destruction

### Secure Zeroization

WSC uses the `zeroize` crate to securely clear key material:

```rust
// SecretKey implements Drop with zeroization
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.sk.zeroize();  // ed25519-compact handles this
    }
}

// Message buffers are wrapped in Zeroizing<T>
let mut msg: Zeroizing<Vec<u8>> = Zeroizing::new(vec![]);
// ... use msg ...
// Automatic zeroization when msg goes out of scope
```

### What Gets Zeroized

| Data | Zeroization Method |
|------|-------------------|
| Ed25519 secret key | ed25519_compact::SecretKey (implicit) |
| ECDSA signing key | p256 SigningKey (Drop) |
| OIDC tokens | Manual zeroize in OidcToken::drop |
| Message buffers | Zeroizing<Vec<u8>> wrapper |

### File Destruction

When deleting key files:

```bash
# Secure delete (Linux)
shred -u signing.sec

# Secure delete (macOS)
rm -P signing.sec

# Overwrite before delete (cross-platform)
dd if=/dev/urandom of=signing.sec bs=64 count=1
rm signing.sec
```

---

## Key Compromise Response

If a key is suspected compromised:

### Immediate Actions

1. **Stop signing with compromised key**
2. **Notify stakeholders**
3. **Generate new key pair**
4. **Re-sign critical modules**

### Recovery Steps

See [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) for detailed procedures.

### Post-Incident

1. **Root cause analysis**
2. **Update security controls**
3. **Document lessons learned**

---

## Compliance Requirements

### Key Management Requirements (IEC 62443)

| Requirement | WSC Implementation |
|-------------|-------------------|
| Unique key per device | Key ID support |
| Secure key storage | 0600 permissions, HSM roadmap |
| Key destruction | Zeroization |
| Key rotation | Manual process documented |

### NIST SP 800-57 Compliance

| Crypto Period | Key Type | WSC Support |
|---------------|----------|-------------|
| 1-2 years | Signing key | Manual rotation |
| Single use | Ephemeral | Automatic |
| 10+ years | CA key | External PKI |

---

## Operational Procedures

### Daily Operations

- No action required for verification-only deployments
- Monitor key file permissions (if automated)

### Weekly Operations

- Review signing logs
- Check for key expiration warnings

### Quarterly Operations

- Review key rotation schedule
- Update trust bundles if needed
- Security audit of key storage

### Annual Operations

- Key rotation (if policy requires)
- Review and update this document
- Compliance verification

---

## Key Inventory Template

| Key ID | Type | Created | Expires | Owner | Status |
|--------|------|---------|---------|-------|--------|
| abc123 | Ed25519 | 2026-01-01 | 2027-01-01 | Team A | Active |
| def456 | P-256 | 2026-01-04 | Ephemeral | CI/CD | Used |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-04 | WSC Team | Initial key lifecycle docs |
