# Per-namespace Auto Unseal -- implementation decisions

Choices made while implementing the RFC (PR #4087) that the RFC does not
yet state. All of them are to be confirmed with the team; once confirmed,
they are added to the RFC.

Each entry states the choice, the reason, the alternative that was set
aside, and where it lives in the code.

## Emerged during development

### 1. KMS configuration storage

- [no , the config is not plain text in our case] 

**Decision.** The KMS configuration of a namespace (wrapper type and its
configuration map, including credentials) is stored in a separate storage
entry, `core/seal-kms-config`, under the parent namespace's barrier and scoped
to the namespace storage prefix, next to `core/seal-config`.

**Why.** `SealConfig` is shared with the root namespace, whose seal
configuration is persisted in plaintext. Keeping credentials out of it removes
any risk of them ending up in plaintext storage. Storing the entry under the
parent barrier matches the trust model in the RFC: the parent manages the
seal configuration of its children.

**Alternative.** A new field in `SealConfig`: less code, but credentials
would sit in a struct that is persisted in plaintext for the root namespace.

**Where.** `namespaceSealKMSConfigPath` and `namespaceKMSConfig` in
`internal/vault/seal_manager.go`; written in `SetSeal`, read back in
`namespaceKMSConfig`. The entry is also removed on namespace deletion
(`knownNamespaceCoreEntriesToCleanup` in `namespace_store.go`).

### 2. Recovery shares at creation

- [R]  Part of the fields of the API , ok. Check the presence of a Shamir HCL .Add the field to actual stanza.
- One recovery per seal (https://openbao.org/community/rfcs/parallel-unseal/). What happens in case of update of recovery? (open in RFC)

**Decision.** For Auto Unseal, recovery shares are set with
`recovery_shares` and `recovery_threshold` in the seal stanza. `shares` and
`threshold` remain Shamir only, and are rejected for Auto Unseal with a hint
to use the recovery settings.

**Why.** Same naming as the root initialization, where recovery settings are
distinct from barrier shares. Using the same names with two meanings would
be confusing. All other stanza entries are passed to the wrapper unchanged.

~~**Alternative.** Reuse `shares` and `threshold` as recovery settings for~~
~~Auto Unseal: fewer keys, but the same name with two meanings.~~

**Where.** `parseAutoSealConfig` in `internal/vault/logical_system_namespaces.go`;
recovery key generated in `SealManager.InitializeRecovery`.

~~### 3. Scope of the first implementation step

- [ R] 

**Decision.** The first step covers creation of a namespace with Auto Unseal
and its automatic unseal at boot when the KMS is reachable. The retry when
the KMS is unreachable comes in a later step.

**Why.** Without automatic unseal at boot, a restarted server would leave
every Auto Unseal namespace sealed, which makes the feature unusable even for
testing.

**Alternative.** Creation only, with boot behavior in a later step: a
smaller first step, but not usable across restarts.

**Where.** `loadNamespacesRecursive` in `internal/vault/namespace_store.go`
calls `SealManager.UnsealWithStoredKeys` and then loads the children through
the namespace's own barrier.~~

### 4. Restricted mode for wrappers

- [ ] 

**Decision.** Namespace wrappers are always configured with
`WithDisallowEnvVars(true)`.

**Why.** As stated in the RFC, a namespace must never pick up configuration
or credentials belonging to the server, such as environment variables or
credential files. The option is honored by the go-kms-wrapping wrappers and
forwarded to external plugins.

**Alternative.** None considered: it is required by the RFC.

**Where.** `newNamespaceAutoSeal` in `internal/vault/seal_manager.go`.

## Proposed during implementation, to be confirmed

### 5. Recovery settings are required

- [R]  Keep the default

**Proposal.** `recovery_shares` and `recovery_threshold` must both be present
in the stanza for Auto Unseal; there is no default. `0`/`0` defers
generation, as described in the RFC.

**Why.** The RFC does not define a default. Requiring an explicit value
avoids inventing one; a default (for example 5/3, as in `bao operator init`)
can be added later without breaking existing requests.

**Alternative.** A default when the settings are missing, such as 5/3.

### 6. `pgp_keys` rejected for Auto Unseal

- [R ] support it, use the alternative solution, like the root namespace does.

**Proposal.** PGP encryption of recovery shares is not supported in this
first step; a request with `pgp_keys` is rejected.

**Why.** For the root, PGP keys for recovery shares are a separate parameter
from PGP keys for unseal shares. Reusing `pgp_keys` for recovery would mix the
two meanings; a dedicated parameter can be added later if needed.

**Alternative.** Accept `pgp_keys` and apply it to the recovery shares.

### 7. Response field names

- [R]  keep being inconsistent , and using recovery_

**Proposal.** For Auto Unseal, the shares are returned as
`recovery_key_shares` and `recovery_key_threshold`. For Shamir, the fields
stay `key_shares` and `key_threshold`.

**Why.** Recovery shares cannot unseal the namespace; returning them under
the same name as unseal shares could mislead operators and tooling.

**Alternative.** Return the recovery shares as `key_shares` and
`key_threshold`, as for Shamir.

### 8. No periodic health check yet

- [R ] TBD - on hold

**Proposal.** Namespace auto seals are created without the periodic health
check used by the root seal.

**Why.** The root health check only reports through server logs, which the
RFC considers unsuitable for namespace operators. The seal state endpoint
will cover this in a later step.

**Alternative.** Enable the root health check for namespace seals now,
reporting through server logs only.

### 9. Namespaces created with Auto Unseal stay unsealed

- [R ] covered 

**Proposal.** At the end of creation, Shamir namespaces are sealed as before,
while Auto Unseal namespaces are left unsealed.

**Why.** The RFC states that a namespace created with Auto Unseal starts in
its unsealed state and needs no manual unseal step.

**Alternative.** None considered: it is required by the RFC.

**Where.** End of `setNamespaceLocked` in `internal/vault/namespace_store.go`.

### 10. Manually sealed namespaces are not unsealed at boot

- [R ] leave to parent. for rfc: TBD "if and what parameters we make mandatory for the manual unseal , after manual seal"
Suggestion: like the root namespace. 

**Proposal.** An Auto Unseal namespace that was sealed by an operator is not
unsealed automatically at boot. (rfc: RFC how to undoit) 

**Why.** An explicit seal is an operator decision and must survive a restart.
The same rule already applies to the gRPC root key sharing.

**Alternative.** Unseal every Auto Unseal namespace at boot, ignoring a
previous manual seal.

**Where.** `loadNamespacesRecursive` in `internal/vault/namespace_store.go`.

## Implementation notes

- [ ] 

- **Transient fields in `SealConfig`.** The KMS configuration and the
  recovery configuration travel from the API handler to the seal manager in
  two unexported fields of `SealConfig`. They are never persisted, since
  unexported fields are skipped by JSON encoding. This avoids changing the
  signature of `ModifyNamespaceByPath`, which has many callers in tests. A
  reviewer may prefer an explicit parameter.

## Known limits of the first step

- [ ] 

- If the KMS of a namespace is unreachable at boot, loading the namespaces
  fails and the root cannot be unsealed. The retry step fixes this; until
  then, this step must not be proposed upstream on its own.
- The existing gRPC root key sharing still applies to Auto Unseal namespaces.
  A later step excludes them, as described in the RFC.
