## CHANGES

### 2.0.1
- **Remember that bitwardentools development, and so support is now halted.**
- Fix for adhoc login introduced by the new multiuser flag (major login problem reported by an user). [kiorky]

### 2.0.0
- support for vaultwarden 1.31+
- Improve cache handling in context on multi users (SEE DISCLAIMER)

### 1.0.57
- QA & CI/CD fixes [kiorky]
- Fix newer vaultwarden patch [kiorky]
- Fix newer vaultwarden adduser [kiorky]
- Fix new vaultwarden create_orga [kiorky]
- Fix newer vaultwarden set_org_acces [kiorky]

### 1.0.56
- Customizable auth payload support (2Factor, api auth) [Markus Kötter <koetter@cispa.de>])

### 1.0.55
- ensure requests is in requirements [kiorky]

### 1.0.54
- bugfix: exclude folderId from getting encrypted [Thomas Kriechbaumer <thomas@kriechbaumer.name>]

### 1.0.53
- kdfIterations payload change fix [kiorky]
- add delete_user [kiorky]

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

