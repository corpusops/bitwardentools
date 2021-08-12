## CHANGES

### 1.0.51
- Do not need private key for confirming users
  [Didier 'OdyX' Raboud <didier.raboud@liip.ch>]
### 1.0.49
- complete vaultier `AS_SINGLE_ORG=false` acls
- feed collections accesses also with global `accessAll=true` users.

### 1.0.47
- vaultier migration: add notify script
- vaultier migration: finish cycle
- Add orga/collection memberships managment methods
- Rename tokens attribute
- Better error messagfes
- Optimize login & token management
- Cache overhaul and factorization
- Vaultier AsOneOrganization import variants
- Clarify docs

### 1.0.46
- Compatibility leftovers with bitwarden_rs `1.20`.

### 1.0.45
- Compatibility with bitwarden_rs `1.20` (was `1.18`).

### 1.0.44
- initial release


### Cut a release

```sh
./release.sh $version
```

