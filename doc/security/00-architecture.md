# Architecture de Sécurité

## Cible de Sécurité

Cette étude de sécurité porte sur la **cible de sécurité maximale** d'Open Bastion (Mode E) :

| Composant                | Configuration                                                            |
| ------------------------ | ------------------------------------------------------------------------ |
| **Architecture réseau**  | Bastion + backends isolés                                                |
| **Authentification SSH** | Certificats signés par la CA LLNG uniquement (`AuthorizedKeysFile none`) |
| **Autorisation SSH**     | Vérification LLNG `/pam/authorize` à chaque connexion                    |
| **Escalade sudo**        | Token temporaire LLNG uniquement (réauthentification SSO)                |
| **Révocation**           | KRL obligatoire + désactivation compte LLNG                              |
| **Bastion → Backend**    | Certificat éphémère signé par la CA LLNG (vouching par cert)             |

```mermaid
flowchart TB
    subgraph Client["Client SSH"]
        cert["Certificat signé\npar CA LLNG (1 an)"]
    end

    subgraph Infra["Infrastructure"]
        subgraph Bastion["Bastion"]
            sshd_b["sshd\nTrustedCA + KRL\nAuthorizedKeysFile none"]
            pam_b["PAM\n/pam/authorize"]
        end

        subgraph Backend["Backend"]
            sshd_be["sshd\nTrustedCA + KRL\nAuthorizedKeysFile none"]
            pam_be["PAM\n/pam/authorize\n+ allowlist bastions"]
            sudo_be["sudo\nToken LLNG\n(réauth SSO)"]
        end
    end

    LLNG["Portail LLNG\n(CA, authorize, bastion-cert, KRL)"]

    Client -->|SSH + certificat| Bastion
    Bastion -->|SSH + cert éphémère (source-address épinglée)| Backend
    pam_b -->|/pam/authorize → voucher| LLNG
    pam_be -->|/pam/authorize\n/pam/verify (sudo)| LLNG
```

D'autres architectures moins restrictives sont possibles (serveur isolé, sans CA, sans bastion), mais cette étude se concentre sur la configuration offrant le meilleur profil de risque.

## Flux d'Authentification

```mermaid
sequenceDiagram
    participant User as Utilisateur
    participant PAM as Module PAM
    participant LLNG as Portail LLNG

    User->>PAM: Token à usage unique
    PAM->>LLNG: POST /pam/verify
    LLNG-->>PAM: Attributs utilisateur + autorisation
    Note over LLNG: Token consommé (usage unique)
    PAM-->>User: Session établie
```

1. L'utilisateur fournit un token à usage unique généré par le portail LLNG
2. Le module PAM vérifie le token via l'endpoint `/pam/verify`
3. Le token est consommé _(usage unique)_ et ne peut pas être rejoué
4. Le serveur retourne les attributs utilisateur et le statut d'autorisation

## Sécurité du Transport

### Configuration TLS

| Paramètre         | Défaut       | Description                                     |
| ----------------- | ------------ | ----------------------------------------------- |
| `min_tls_version` | 13 (TLS 1.3) | Version TLS minimale (12=1.2, 13=1.3)           |
| `verify_ssl`      | true         | Vérifier le certificat serveur                  |
| `ca_cert`         | système      | Chemin vers un certificat CA personnalisé       |
| `cert_pin`        | aucun        | Épinglage de certificat (format sha256//base64) |

**Épinglage de Certificat** : Lorsqu'il est configuré, le module valide la clé publique du serveur par rapport à la valeur épinglée, empêchant les attaques MITM même en cas de compromission de CA.

```ini
# Exemple de configuration
min_tls_version = 13
cert_pin = sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
```

### Signature des Requêtes (Optionnel)

Lorsque `request_signing_secret` est configuré, les requêtes incluent :

- `X-Timestamp` : Horodatage Unix _(le serveur devrait rejeter les valeurs trop anciennes)_
- `X-Nonce` : Format unique `timestamp_ms-uuid` _(le serveur devrait rejeter les doublons)_
- `X-Signature-256` : Signature HMAC-SHA256 de la requête

Cela fournit une défense en profondeur contre la falsification de requêtes, même si TLS est d'une façon ou d'une autre compromis.

## Authentification du Serveur

Le module PAM s'authentifie auprès du serveur LLNG en utilisant :

| Paramètre              | Description                                                         |
| ---------------------- | ------------------------------------------------------------------- |
| `server_token_file`    | Chemin vers le fichier contenant le token bearer du serveur         |
| `server_group`         | Nom du groupe serveur (défaut : "default")                          |
| `token_rotate_refresh` | Rotation automatique des tokens de rafraîchissement (défaut : true) |

Le token serveur doit être stocké dans un fichier avec des permissions restreintes (0600) appartenant à root.

### Authentification Client OAuth2

Pour les opérations d'introspection et de rafraîchissement de tokens OAuth2, le module utilise **JWT Client Assertion**
(RFC 7523) plutôt que l'authentification HTTP Basic. Cela offre une sécurité renforcée :

- Le `client_secret` n'est jamais transmis sur le réseau
- Chaque requête inclut un JWT unique signé avec HMAC-SHA256
- Le JWT contient : `iss`, `sub`, `aud`, `exp`, `iat`, et un `jti` unique (UUID v4)
- La validité du JWT est de 5 minutes pour éviter les attaques par rejeu

### Rotation Automatique des Tokens

Lorsque `token_rotate_refresh = true` (défaut), le module fait automatiquement tourner le token de rafraîchissement après chaque rafraîchissement de token réussi. Cela limite la fenêtre d'opportunité si un token est compromis, car les tokens volés deviennent invalides après la prochaine utilisation légitime.

## Authentification Bastion vers Backend (vouching par certificat éphémère)

Dans les architectures bastion/backend, le mécanisme de vouching par certificat garantit cryptographiquement que les connexions SSH vers les backends proviennent d'un bastion autorisé ayant réellement authentifié l'utilisateur.

> **Note :** L'ancien mécanisme JWT (`LLNG_BASTION_JWT` / `SendEnv`) était structurellement cassé — `SendEnv`/`AcceptEnv` ne renseignent que l'environnement du processus enfant SSH, jamais l'environnement PAM lu par `pam_getenv`. Il a été remplacé par ce mécanisme basé sur des certificats éphémères.

### Architecture

```mermaid
flowchart LR
    subgraph Bastion["Serveur Bastion"]
        proxy["ob-ssh-proxy"]
        helper["ob-bastion-cert-helper\n(root, sudoers NOPASSWD)"]
        voucher["LLNG_BASTION_VOUCHER\n(pam_putenv, tmpfs)"]
    end

    subgraph LLNG["Portail LLNG"]
        authorize["/pam/authorize\n(émet le voucher)"]
        bastion_cert["/pam/bastion-cert\n(signe le cert éphémère)"]
        sshca["CA ssh-ca"]
    end

    subgraph Backend["Serveur Backend"]
        sshd_be["sshd\nTrustedUserCAKeys + source-address\nAuthorizedPrincipalsCommand →\nob-ssh-principals (key-id + allowed_bastions)"]
        pam_be["pam_openbastion\n/pam/authorize (autorisation LLNG)"]
    end

    authorize -->|voucher lié à (bastion_id, user)| voucher
    proxy -->|1. voucher + clé pub éphémère| helper
    helper -->|2. POST Bearer=server_token| bastion_cert
    bastion_cert -->|3. signe via| sshca
    sshca -->|4. cert éphémère ~120s| helper
    helper -->|5. cert| proxy
    proxy -->|6. SSH -i eph -o CertificateFile=cert| sshd_be
    sshd_be -->|source-address + CA valide| pam_be
```

### Flux détaillé

1. L'utilisateur se connecte au bastion avec son certificat SSO. `pam_openbastion` appelle `POST /pam/authorize` → LLNG émet un **voucher réutilisable** lié à `(bastion_id, utilisateur)`, le stocke dans la session persistante de l'utilisateur et le renvoie. Le module PAM l'exporte via `pam_putenv("LLNG_BASTION_VOUCHER=…")` (transport **local au bastion** — contrairement à `SendEnv`, `sshd` fusionne l'environnement PAM dans la session via `pam_getenvlist`).
2. Sur le bastion, `ob-ssh-proxy [user@]backend` :
   a. génère une paire de clés éphémère **ed25519** en tmpfs (clé privée ne quitte jamais le bastion) ;
   b. via le helper réservé à root `ob-bastion-cert-helper` (règle sudoers NOPASSWD étroite, pas de setuid), `POST /pam/bastion-cert` avec le **jeton serveur** (réservé à root) en Bearer, le voucher, la clé publique, l'utilisateur et l'hôte cible ;
   c. LLNG vérifie le voucher côté serveur, signe la clé publique avec la CA `ssh-ca` : principal = utilisateur, `key-id = bastion=<bastion_id>;user=<user>;target=<hôte>`, validité ~120 s, option critique `source-address` épinglée à l'IP du bastion ;
   d. `ssh -i <eph> -o CertificateFile=<cert> -o IdentitiesOnly=yes <user>@<backend>` ; les fichiers temporaires sont effacés après connexion.
3. Le backend sshd valide nativement : signature CA, fenêtre de validité, `principal == utilisateur`, **`source-address`** (refus si la connexion ne vient pas de l'IP du bastion). **Avant PAM**, `AuthorizedPrincipalsCommand` exécute `ob-ssh-principals` (en tant que `nobody`) qui lit le `key-id` (`%i`), vérifie que `bastion=<id>` figure dans `/etc/open-bastion/allowed_bastions` et que `user=<u>` correspond au login, et n'émet le principal que dans ce cas — un cert SSO direct (sans `bastion=`) est donc **refusé avant PAM**. `pam_openbastion` (`acct_mgmt`) effectue ensuite l'autorisation applicative via `/pam/authorize`.

### Propriétés de Sécurité du Voucher

- **Validité** : `min(now + pamAccessBastionVoucherTtl [défaut 43200 s = 12 h], expires_at du cert SSO)` — la durée de vie du cert SSO est le vrai plafond.
- **Réutilisable** : plusieurs sauts simultanés (`scp host1: host2:`) utilisent le même voucher.
- **Renouvellement FAIL-CLOSED** : si le voucher est expiré, `ob-ssh-proxy` affiche « Votre autorisation bastion a expiré. Reconnectez-vous au bastion » et sort en erreur. Pas de re-vouching silencieux.
- **Inutilisable seul** : un voucher volé est sans valeur sans le jeton serveur root requis en Bearer sur `/pam/bastion-cert`.

### Bénéfices de Sécurité

| Menace                          | Sans vouching cert                  | Avec vouching cert                                                                                                         |
| ------------------------------- | ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Accès direct au backend         | Possible si réseau accessible       | Bloqué — cert SSO direct refusé (key-id sans `bastion=`), cert épinglé à l'IP du bastion                                   |
| Contournement VPN vers backend  | Possible                            | Bloqué — `source-address` critique dans le cert, sshd refuse hors IP bastion                                               |
| Mauvaise configuration pare-feu | Expose les backends                 | Backends toujours protégés — enforcement sshd-natif                                                                        |
| Rejeu d'un identifiant volé     | Clé/token compromis = accès backend | Voucher volé inutile sans le jeton server root ; cert valide 120 s seulement                                               |
| Bastion non autorisé            | N/A                                 | Bloqué — `allowed_bastions` vérifié par `ob-ssh-principals` (AuthorizedPrincipalsCommand, avant PAM) via le key-id du cert |

### Configuration (Backend)

```bash
# ob-backend-setup --allowed-bastions bastion-01,bastion-02
# ou Ansible : ob_bastion_allowed_bastions: "bastion-01,bastion-02"
# → écrit /etc/open-bastion/allowed_bastions (0644, répertoire 0711)
# Vide = tout bastion vouché accepté ; absent = mode hérité (pas de vérification)
# FAIL-CLOSED si le fichier est illisible
```

```bash
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/llng_ca.pub          # déjà requis
AuthorizedPrincipalsCommand /usr/sbin/ob-ssh-principals %u %f %i
AuthorizedPrincipalsCommandUser nobody
# Supprimer : AcceptEnv LLNG_BASTION_JWT
```

### Champs du Certificat Éphémère

| Champ cert SSH   | Valeur                                                             |
| ---------------- | ------------------------------------------------------------------ |
| `principal`      | Nom d'utilisateur proxifié                                         |
| `key-id`         | `bastion=<bastion_id>;user=<user>;target=<target_host>`            |
| `validity`       | ~120 s (`pamAccessBastionCertTtl`)                                 |
| `source-address` | IP du bastion (option critique — sshd refuse si connexion hors IP) |
| `extension`      | `bastion-id@open-bastion = <bastion_id>` (optionnel, audit)        |

### Paramètres LLNG (`pam-access`)

| Paramètre                    | Défaut  | Description                                                                                      |
| ---------------------------- | ------- | ------------------------------------------------------------------------------------------------ |
| `pamAccessBastionGroups`     | bastion | Groupes autorisés à obtenir des vouchers / certs bastion                                         |
| `pamAccessBastionVoucherTtl` | 43200   | Plafond de validité du voucher en secondes (12 h) ; la durée du cert SSO prime                   |
| `pamAccessBastionCertTtl`    | 120     | Validité du certificat éphémère en secondes                                                      |
| `pamAccessServerGroups`      | —       | Table `client_id → groupe` ; `/pam/bastion-cert` ne fait jamais confiance à un groupe revendiqué |
| `sshCaActivation`            | 0       | Doit être mis à **1** pour activer le plugin ssh-ca requis par ce mécanisme                      |

## Sécurité du Cache de Tokens

### Chiffrement au Repos

Lorsque `cache_encrypted = true` _(défaut)_, les tokens en cache sont chiffrés en utilisant :

- **Algorithme** : AES-256-GCM _(chiffrement authentifié)_
- **Dérivation de clé** : PBKDF2-SHA256 avec 100 000 itérations
- **Source de la clé** : Machine ID (`/etc/machine-id`) + nom d'utilisateur du cache comme sel
- **Authentification** : Le tag GCM empêche la falsification

```
Format du fichier :
[Texte clair : "expires_at\n"][Magic : LLNGCACHE02][IV : 12 octets][Tag : 16 octets][Texte chiffré]
```

L'en-tête d'horodatage en clair permet des vérifications rapides d'expiration sans déchiffrement
_(optimisation des performances)_. Cependant, l'horodatage est **dupliqué à l'intérieur du payload chiffré**
pour vérification d'intégrité. Si un attaquant modifie l'en-tête en clair pour étendre la validité du cache,
la discordance avec l'horodatage chiffré entraîne un rejet immédiat et la suppression du fichier cache.

### Isolation du Cache

- Le cache de chaque utilisateur est stocké dans un fichier séparé
- Permissions du fichier : 0600 _(lecture/écriture propriétaire uniquement)_
- Permissions du répertoire : 0700

### Invalidation du Cache

Lorsque `cache_invalidate_on_logout = true` _(défaut)_ :

- Le cache de l'utilisateur est effacé à la fermeture de sa session PAM
- Empêche la réutilisation de tokens périmés

### TTL Basé sur le Risque

| Type de service        | TTL par défaut |
| ---------------------- | -------------- |
| Services normaux       | 300 secondes   |
| Services à haut risque | 60 secondes    |

Configurer les services à haut risque via `high_risk_services` _(séparés par des virgules)_.

## Limitation de Débit

Protection contre les attaques par force brute :

| Paramètre                    | Défaut | Description                            |
| ---------------------------- | ------ | -------------------------------------- |
| `rate_limit_enabled`         | true   | Activer la limitation de débit         |
| `rate_limit_max_attempts`    | 5      | Échecs avant verrouillage              |
| `rate_limit_initial_lockout` | 30s    | Durée initiale de verrouillage         |
| `rate_limit_max_lockout`     | 3600s  | Durée maximale de verrouillage         |
| `rate_limit_backoff_mult`    | 2.0    | Multiplicateur d'attente exponentielle |

L'état de verrouillage est stocké par utilisateur dans `rate_limit_state_dir`.

## Sécurité de la Création Automatique d'Utilisateurs

Lorsque `create_user_enabled = true`, les utilisateurs peuvent être créés automatiquement à la première connexion.

### Validation des Chemins

Tous les chemins sont validés avant utilisation :

**Validation du Shell** (`approved_shells`) :

- Doit figurer dans la liste approuvée _(défaut : shells courants comme /bin/bash, /bin/zsh)_
- Doit être un chemin absolu
- Pas de séquences de traversée de répertoire _(.., //)_
- Pas de métacaractères shell

**Validation du Répertoire Personnel** (`approved_home_prefixes`) :

- Doit commencer par un préfixe approuvé _(défaut : /home, /var/home)_
- Mêmes vérifications de sécurité que pour le shell

**Validation du Répertoire Squelette** :

- Doit être un chemin absolu
- Doit appartenir à root
- Pas de liens symboliques dans les composants du chemin
- Pas de motifs dangereux

### Génération d'UID

- Les UID sont générés de façon déterministe à partir du hash du nom d'utilisateur
- Plage : 10000-60000 _(configurable)_
- **Gestion des collisions** : Si l'UID existe, l'opération échoue de façon sûre _(retourne 0)_
- Pas de repli vers des UID aléatoires qui pourraient entraîner un comportement imprévisible

### Sécurité du Module NSS

Le module NSS (`libnss_openbastion.so`) fournit la résolution des utilisateurs :

- **Protection contre les débordements de tampon** : Toutes les copies de chaînes utilisent `safe_strcpy()` avec vérification des limites
- **Validation des entrées serveur** : Les chemins de shell et de répertoire personnel provenant du serveur sont validés par rapport aux listes approuvées
- **Contrôle de la plage d'UID** : Les UID fournis par le serveur doivent être dans la plage min_uid/max_uid configurée
- **Sécurité par défaut** : Retourne les codes d'erreur appropriés en cas d'échec ; les chemins invalides se replient sur les valeurs par défaut

### Manipulation Directe de /etc/passwd et /etc/shadow

Les comptes utilisateurs sont créés en écrivant directement dans `/etc/passwd` et `/etc/shadow` plutôt qu'en utilisant
des outils externes comme `useradd`. Ce choix de conception a été fait pour :

**Avantages** :

- **Portabilité** : Pas de dépendance à `useradd` qui peut ne pas exister ou avoir des options différentes selon les distributions
- **Atomicité** : Le contrôle du verrouillage de fichier par un seul processus garantit un état cohérent
- **Prévisibilité** : Pas de variations de comportement d'outils externes ni de prompts inattendus

**Compromis** :

- Les hooks de création de compte PAM ne sont pas déclenchés _(ce module EST le hook PAM)_
- Les contextes SELinux doivent être gérés séparément si nécessaire
- Les journaux d'audit système ne voient que les modifications de fichiers, pas les événements sémantiques de type "utilisateur créé"

**Atténuations** :

- Le module émet ses propres événements d'audit structurés lorsque `audit_enabled = true`
- Les opérations sur les fichiers utilisent des verrous exclusifs (`flock`) pour éviter les conditions de course
- Si l'écriture dans `/etc/shadow` échoue après le succès de `/etc/passwd`, une annulation est tentée via `userdel`
- Protection TOCTOU : l'existence de l'utilisateur est revérifiée après acquisition des verrous

## Journalisation d'Audit

Lorsque `audit_enabled = true` :

| Paramètre         | Défaut | Description                               |
| ----------------- | ------ | ----------------------------------------- |
| `audit_log_file`  | aucun  | Chemin du fichier de journal d'audit JSON |
| `audit_to_syslog` | true   | Émettre également vers syslog             |
| `audit_level`     | 1      | 0=critique, 1=événements auth, 2=tous     |

Les événements d'audit incluent :

- Tentatives d'authentification _(succès/échec)_
- Décisions d'autorisation
- Déclenchements de limitation de débit
- Événements de création d'utilisateur

### Classification des Types d'Événements

Les événements d'audit utilisent des codes différenciés pour l'intégration SIEM :

| Type d'événement       | Description                                                       |
| ---------------------- | ----------------------------------------------------------------- |
| `AUDIT_AUTH_SUCCESS`   | Authentification réussie                                          |
| `AUDIT_AUTH_FAILURE`   | Authentification échouée                                          |
| `AUDIT_AUTHZ_DENIED`   | Autorisation refusée (utilisateur valide, sans permission)        |
| `AUDIT_SECURITY_ERROR` | Échec cryptographique/sécurité (signature invalide, JWT malformé) |
| `AUDIT_RATE_LIMITED`   | Limitation de débit déclenchée                                    |
| `AUDIT_USER_CREATED`   | Compte utilisateur local créé                                     |
| `AUDIT_SERVER_ERROR`   | Erreur de communication avec le backend                           |

Cette classification permet aux équipes de sécurité de distinguer :

- Les échecs d'autorisation (l'utilisateur n'a pas la permission) → `AUDIT_AUTHZ_DENIED`
- Les incidents de sécurité (tentative d'attaque) → `AUDIT_SECURITY_ERROR`

## Notifications Webhook

Pour la surveillance de sécurité en temps réel :

| Paramètre        | Description                                  |
| ---------------- | -------------------------------------------- |
| `notify_enabled` | Activer les webhooks                         |
| `notify_url`     | URL de l'endpoint webhook                    |
| `notify_secret`  | Secret HMAC pour les signatures des webhooks |

## Sécurité de la Configuration

### Gestion des Secrets

| Paramètre              | Défaut         | Description                   |
| ---------------------- | -------------- | ----------------------------- |
| `secrets_encrypted`    | true           | Chiffrer les secrets au repos |
| `secrets_use_keyring`  | true           | Utiliser le trousseau noyau   |
| `secrets_keyring_name` | "open-bastion" | Identifiant du trousseau      |

### Permissions des Fichiers

Permissions recommandées :

| Fichier                              | Permissions | Propriétaire |
| ------------------------------------ | ----------- | ------------ |
| `/etc/open-bastion/openbastion.conf` | 0600        | root         |
| Fichier token serveur                | 0600        | root         |
| Répertoire cache                     | 0700        | root         |
| Répertoire état limitation de débit  | 0700        | root         |

## Sécurité des Scripts

Les scripts shell (`ob-ssh-proxy`, `ob-enroll`, `ob-ssh-cert`) mettent en œuvre des mesures de sécurité :

### Construction JSON

Les scripts utilisent `jq` pour la construction des payloads JSON plutôt que l'interpolation de chaînes :

```bash
# Sûr - utilise le passage d'arguments jq
json_payload=$(jq -n --arg user "$user" --arg host "$host" '{user: $user, host: $host}')

# Non sûr - vulnérable à l'injection (NON UTILISÉ)
# json_payload="{\"user\": \"$user\"}"
```

Cela empêche les attaques par injection JSON où des entrées malveillantes pourraient sortir du contexte de chaîne.

### Validation des Fichiers de Configuration

Les scripts vérifient la sécurité des fichiers de configuration avant de les sourcer :

```bash
# Vérifier que le propriétaire est root
# Vérifier l'absence de permissions d'écriture pour le groupe/les autres
# Refuser de sourcer en cas d'échec des vérifications
```

Cela empêche l'escalade de privilèges via une injection de configuration malveillante.

## Considérations de Sécurité Opérationnelle

### Avertissement sur la Journalisation de Débogage

**CRITIQUE : Ne jamais activer la journalisation de débogage en environnement de production.**

Lorsque `log_level = debug`, le module peut journaliser des informations sensibles dans syslog :

- Métadonnées du certificat SSH (key_id, numéro de série, principals)
- Détails de validation des tokens
- Paramètres de requête d'autorisation

**Risque** : Si les journaux de débogage sont capturés par un agrégateur de logs ou accessibles par des utilisateurs non autorisés,
ces informations pourraient être utilisées pour :

- Identifier la topologie de l'infrastructure
- Suivre les mouvements des utilisateurs entre les systèmes
- Corréler des sessions à des fins de ciblage

**Recommandation** :

- Utiliser `log_level = warn` ou `log_level = error` en production
- Si la journalisation de débogage est temporairement nécessaire, s'assurer que l'accès à syslog est restreint
- Faire tourner et purger rapidement les journaux contenant des sorties de débogage

### Exigence de Stabilité du Machine-ID

La clé de chiffrement pour les tokens et secrets en cache est dérivée de `/etc/machine-id`.

**Impact d'un changement de machine-id** :

- Tous les tokens en cache deviennent illisibles (réauthentification automatique requise)
- Les secrets chiffrés dans le magasin de secrets deviennent définitivement irrécupérables
- Les tokens d'enrôlement serveur doivent être réémis

**Scénarios provoquant un changement de machine-id** :

- Clonage de VM sans régénération du machine-id
- Réinstallation du système
- Réutilisation d'une image de conteneur sur différents hôtes
- Recréation d'instance chez certains fournisseurs cloud

**Recommandations** :

1. **Documenter la stabilité du machine-id** comme exigence de déploiement
2. **Avant une migration système** : Sauvegarder les tokens d'enrôlement ou planifier un ré-enrôlement
3. **Clonage de VM** : Toujours régénérer le machine-id (`systemd-machine-id-setup`) et ré-enrôler
4. **Surveillance** : Alerter sur les changements de machine-id via la gestion de configuration

**Procédure de ré-enrôlement après changement de machine-id** :

```bash
# 1. L'ancien fichier token est maintenant inutilisable - le supprimer
rm /var/lib/open-bastion/token

# 2. Relancer l'enrôlement
ob-enroll --portal https://auth.example.com --client-id pam-access
```

## Sécurité des Comptes de Service

Les comptes de service (ansible, backup, deploy, etc.) sont des comptes locaux qui s'authentifient uniquement par clé SSH,
contournant l'authentification OIDC. Ils sont définis dans un fichier de configuration local.

### Sécurité du Fichier de Configuration

| Exigence    | Description                                                 |
| ----------- | ----------------------------------------------------------- |
| Propriété   | Doit appartenir à root (uid 0)                              |
| Permissions | Doit être 0600 (lecture/écriture propriétaire uniquement)   |
| Liens sym.  | Le fichier ne doit pas être un lien symbolique (O_NOFOLLOW) |
| Emplacement | `/etc/open-bastion/service-accounts.conf` (configurable)    |

### Validation des Comptes

Les comptes de service sont validés selon les mêmes règles de sécurité que les utilisateurs réguliers :

| Champ             | Validation                                                                       |
| ----------------- | -------------------------------------------------------------------------------- |
| `name`            | Lettres minuscules, chiffres, underscore, tiret ; max 32 caractères              |
| `key_fingerprint` | Doit commencer par `SHA256:` ou `MD5:`, uniquement des caractères base64 valides |
| `shell`           | Doit figurer dans la liste `approved_shells`                                     |
| `home`            | Doit correspondre à `approved_home_prefixes`                                     |
| `uid`/`gid`       | Doit être dans la plage valide (0-65534)                                         |

### Exigence du Serveur SSH

**Important :** Le serveur SSH doit avoir `ExposeAuthInfo yes` dans `/etc/ssh/sshd_config` :

```bash
# /etc/ssh/sshd_config
ExposeAuthInfo yes
```

Ce paramètre permet au module PAM d'accéder à l'empreinte de clé SSH via la variable d'environnement `SSH_USER_AUTH`,
qui est requise pour la validation de l'empreinte.

### Flux d'Authentification

```mermaid
sequenceDiagram
    participant SA as Compte de Service
    participant SSH as Serveur SSH
    participant PAM as Module PAM

    SA->>SSH: Authentification par clé SSH
    SSH->>PAM: pam_sm_authenticate
    Note over SSH: ExposeAuthInfo fournit<br/>SSH_USER_AUTH avec l'empreinte
    PAM->>PAM: Extrait l'empreinte de SSH_USER_AUTH
    PAM->>PAM: Vérifie service_accounts.conf
    PAM->>PAM: Valide que l'empreinte correspond à la config
    Note over PAM: Empreinte OK = autorisé
    PAM-->>SSH: PAM_SUCCESS
    SSH-->>SA: Session établie
```

1. Le compte de service se connecte via SSH avec sa clé configurée
2. Le serveur SSH expose l'empreinte de clé via `SSH_USER_AUTH` (nécessite `ExposeAuthInfo yes`)
3. Le module PAM extrait l'empreinte et vérifie si l'utilisateur est dans `service_accounts.conf`
4. Le module PAM valide que l'empreinte de clé SSH correspond à la valeur configurée
5. Si l'empreinte correspond, le compte est autorisé localement (pas d'appel LLNG nécessaire)
6. Les permissions sudo sont vérifiées depuis le même fichier de configuration

### Bénéfices de Sécurité

| Fonctionnalité         | Bénéfice                                                            |
| ---------------------- | ------------------------------------------------------------------- |
| Configuration locale   | Pas de dépendance réseau pour les comptes de service                |
| Contrôle par serveur   | Chaque serveur liste explicitement les comptes de service autorisés |
| Liaison par clé SSH    | La validation de l'empreinte empêche la substitution de clé         |
| Journalisation d'audit | Tous les accès de comptes de service sont journalisés               |
| Contrôle sudo          | Permissions sudo fines par compte                                   |

### Limitations

| Limitation                  | Atténuation                                            |
| --------------------------- | ------------------------------------------------------ |
| Pas de gestion centralisée  | Utiliser la gestion de configuration (Ansible, Puppet) |
| Rotation manuelle des clés  | Mettre en œuvre des procédures de rotation des clés    |
| Dépendance au fichier local | Surveiller l'intégrité des fichiers avec AIDE/Tripwire |

### Exemple de Configuration

```ini
[ansible]
key_fingerprint = SHA256:abc123def456
sudo_allowed = true
sudo_nopasswd = true
gecos = Ansible Automation
shell = /bin/bash
home = /var/lib/ansible
```

## Politique de Clés SSH

Le module PAM peut imposer des restrictions sur les types de clés SSH autorisés et leurs tailles minimales.
Cela empêche les connexions utilisant des algorithmes cryptographiques faibles ou obsolètes.

### Configuration

| Paramètre                | Défaut | Description                                        |
| ------------------------ | ------ | -------------------------------------------------- |
| `ssh_key_policy_enabled` | false  | Activer les restrictions de type de clé SSH        |
| `ssh_key_allowed_types`  | tous   | Liste séparée par des virgules des types autorisés |
| `ssh_key_min_rsa_bits`   | 2048   | Taille minimale de clé RSA en bits                 |
| `ssh_key_min_ecdsa_bits` | 256    | Taille minimale de clé ECDSA en bits               |

### Types de Clés Supportés

| Type         | Algorithme                | Recommandation                             |
| ------------ | ------------------------- | ------------------------------------------ |
| `ed25519`    | Ed25519                   | **Recommandé** - Moderne, rapide, sécurisé |
| `sk-ed25519` | Ed25519 avec FIDO2        | **Recommandé** - Lié au matériel           |
| `sk-ecdsa`   | ECDSA avec FIDO2          | **Recommandé** - Lié au matériel           |
| `ecdsa`      | ECDSA (P-256/P-384/P-521) | Acceptable                                 |
| `rsa`        | RSA                       | Acceptable avec ≥3072 bits                 |
| `dsa`        | DSA                       | **Obsolète** - Devrait être désactivé      |

### Considérations de Sécurité

- **Clés DSA** : Devraient être désactivées. DSA est considéré comme obsolète et a une taille de clé fixe de 1024 bits.
- **Clés RSA** : Devraient exiger au moins 2048 bits, de préférence 3072 bits pour une sécurité à long terme.
- **Clés ECDSA** : P-256 (256 bits) est la courbe minimale recommandée.
- **Clés Ed25519** : Toujours 256 bits, pas de configuration de taille nécessaire.
- **FIDO2/Clés de Sécurité** : `sk-ed25519` et `sk-ecdsa` fournissent des clés privées liées au matériel.

### Exemple : Configuration Haute Sécurité

```ini
ssh_key_policy_enabled = true
ssh_key_allowed_types = ed25519, sk-ed25519, sk-ecdsa
```

Cette configuration n'autorise que les clés Ed25519 et les clés de sécurité matérielles FIDO2.

## Atténuation des Menaces

| Menace                      | Atténuation                                                                                                             |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Rejeu de token              | Tokens à usage unique, invalidation du cache                                                                            |
| Attaques MITM               | TLS 1.3, épinglage de certificat                                                                                        |
| Force brute                 | Limitation de débit avec attente exponentielle                                                                          |
| Falsification du cache      | Chiffrement authentifié AES-256-GCM                                                                                     |
| Injection de chemin         | Validation stricte des chemins, listes approuvées                                                                       |
| Débordement de tampon       | Opérations sur chaînes avec vérification des limites, snprintf avec terminaison null                                    |
| Collision d'UID             | Détection de collision à sécurité intégrée                                                                              |
| Falsification de requête    | Signature HMAC optionnelle avec nonces                                                                                  |
| DoS par épuisement mémoire  | Limites de taille de réponse (256 Ko), limites de groupes (256 max)                                                     |
| Dépassement d'entier        | Validation des entrées dans l'encodage base64, calculs d'attente                                                        |
| JSON malformé               | Validation de type pour les champs de réponse critiques                                                                 |
| Exposition du secret client | JWT Client Assertion (RFC 7523) - secret jamais transmis                                                                |
| Contournement du bastion    | Certificat éphémère lié à `(bastion_id, user)` via voucher serveur ; `source-address` épinglée à l'IP du bastion        |
| Accès direct au backend     | Cert SSO direct refusé (key-id sans `bastion=`) ; cert éphémère épinglé à l'IP du bastion via `source-address` critique |
| Clés SSH faibles            | Application de la politique de clés SSH avec restrictions de type/taille                                                |
| Force brute sur le cache    | Limitation de débit pour les consultations de cache hors-ligne avec attente exponentielle                               |
