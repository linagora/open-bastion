# Analyse de Sécurité - Phase 2 : Connexion SSH

## 1. Description des Architectures

Cette analyse couvre quatre architectures de déploiement SSH avec le module PAM LLNG :

| Architecture | Description                  | Niveau de sécurité |
| ------------ | ---------------------------- | ------------------ |
| **A**        | Serveur isolé                | Base               |
| **B**        | Serveur isolé + SSH CA       | Amélioré           |
| **C**        | Bastion + backends           | Élevé              |
| **D**        | Bastion + backends + SSH CA  | Optimal            |

### Acteurs

| Acteur            | Rôle                                              |
| ----------------- | ------------------------------------------------- |
| **Utilisateur**   | Personne se connectant en SSH                     |
| **Client SSH**    | Machine de l'utilisateur (laptop, workstation)    |
| **Serveur SSH**   | Serveur cible avec PAM LLNG                       |
| **Bastion**       | Point d'entrée unique pour les connexions SSH     |
| **Backend**       | Serveur accessible uniquement via le bastion      |
| **Portail LLNG**  | Serveur d'authentification/autorisation           |
| **SSH CA**        | Autorité de certification pour les clés SSH       |

---

## 2. Architecture A : Serveur Isolé

### Description

Configuration la plus simple : un serveur SSH autonome avec PAM LLNG.

```
┌─────────────┐                    ┌─────────────┐                    ┌─────────────┐
│   Client    │                    │  Serveur    │                    │   Portail   │
│    SSH      │                    │    SSH      │                    │    LLNG     │
└──────┬──────┘                    └──────┬──────┘                    └──────┬──────┘
       │                                  │                                  │
       │ 1. ssh user@server               │                                  │
       │─────────────────────────────────>│                                  │
       │                                  │                                  │
       │                                  │ 2. PAM: /pam/authorize           │
       │                                  │  user=X, host=server             │
       │                                  │─────────────────────────────────>│
       │                                  │                                  │
       │                                  │ 3. {authorized: true/false,      │
       │                                  │     groups: [...]}               │
       │                                  │<─────────────────────────────────│
       │                                  │                                  │
       │ 4. Session établie (ou refusée)  │                                  │
       │<─────────────────────────────────│                                  │
       │                                  │                                  │
```

### Authentification

L'utilisateur s'authentifie auprès du serveur SSH avec :
- Clé SSH publique/privée (méthode recommandée)
- Mot de passe (déconseillé, voir R-A1)

### Autorisation

Le module PAM LLNG appelle `/pam/authorize` avec :
- `user` : nom d'utilisateur
- `host` : hostname du serveur
- `service` : "sshd"

LLNG vérifie :
- L'utilisateur existe et est actif
- L'utilisateur est autorisé à accéder à ce serveur/server_group
- Les groupes et attributs de l'utilisateur

### Configuration

```ini
# /etc/security/pam_llng.conf
portal_url = https://auth.example.com
server_group = production
verify_ssl = true
```

```
# /etc/pam.d/sshd
auth       required     pam_llng.so
account    required     pam_llng.so
```

---

## 3. Architecture B : Serveur Isolé + SSH CA

### Description

Le serveur utilise des certificats SSH signés par une autorité de certification (SSH CA). Cette architecture améliore la traçabilité et permet une gestion centralisée des clés.

```
┌─────────────┐                    ┌─────────────┐                    ┌─────────────┐
│   Client    │                    │  Serveur    │                    │   Portail   │
│    SSH      │                    │    SSH      │                    │    LLNG     │
│ (cert signé)│                    │ (TrustedCA) │                    │             │
└──────┬──────┘                    └──────┬──────┘                    └──────┬──────┘
       │                                  │                                  │
       │ 1. ssh user@server               │                                  │
       │    (présente certificat)         │                                  │
       │─────────────────────────────────>│                                  │
       │                                  │                                  │
       │                                  │ 2. Vérifie signature CA          │
       │                                  │    Extrait: key_id, serial,      │
       │                                  │    principals, ca_fingerprint    │
       │                                  │                                  │
       │                                  │ 3. PAM: /pam/authorize           │
       │                                  │  user=X, host=server,            │
       │                                  │  ssh_cert={key_id, serial, ...}  │
       │                                  │─────────────────────────────────>│
       │                                  │                                  │
       │                                  │ 4. Vérifie cert non révoqué      │
       │                                  │    Vérifie autorisation          │
       │                                  │<─────────────────────────────────│
       │                                  │                                  │
       │ 5. Session établie               │                                  │
       │<─────────────────────────────────│                                  │
       │                                  │                                  │
```

### Certificat SSH

Le certificat SSH contient :
- `key_id` : identifiant unique du certificat
- `serial` : numéro de série
- `principals` : liste des usernames autorisés
- `valid_after` / `valid_before` : période de validité
- Signature de la CA

### Extraction des informations de certificat

Le module PAM extrait les informations via les variables d'environnement SSH :
- `SSH_USER_AUTH` : méthode d'authentification (contient "-cert-" pour certificat)
- `SSH_CERT_KEY_ID` : identifiant du certificat
- `SSH_CERT_SERIAL` : numéro de série
- `SSH_CERT_PRINCIPALS` : principals autorisés
- `SSH_CERT_CA_KEY_FP` : empreinte de la CA

```c
// src/pam_llng.c:616-631
const char *key_id = pam_getenv(pamh, "SSH_CERT_KEY_ID");
const char *serial = pam_getenv(pamh, "SSH_CERT_SERIAL");
const char *principals = pam_getenv(pamh, "SSH_CERT_PRINCIPALS");
const char *ca_fp = pam_getenv(pamh, "SSH_CERT_CA_KEY_FP");
```

### Avantages vs Architecture A

| Aspect           | Architecture A   | Architecture B               |
| ---------------- | ---------------- | ---------------------------- |
| Traçabilité      | Username seul    | key_id, serial, principals   |
| Révocation       | Impossible sans LLNG | Possible via CRL ou LLNG |
| Durée de vie clé | Illimitée        | Limitée par certificat       |
| Audit            | Basique          | Complet avec serial          |

### Configuration serveur SSH

```bash
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/ca_user_key.pub
ExposeAuthInfo yes   # Requis pour SSH_CERT_* variables
```

---

## 4. Architecture C : Bastion + Backends

### Description

Les serveurs backends ne sont accessibles que via un bastion. Cette architecture offre :
- Point d'entrée unique et auditable
- Réduction de la surface d'attaque des backends
- Possibilité de segmentation réseau

```
                                       ┌─────────────────────────────────────────┐
                                       │           Zone sécurisée                │
┌─────────────┐      ┌─────────────┐   │   ┌─────────────┐   ┌─────────────┐    │
│   Client    │      │   Bastion   │   │   │  Backend 1  │   │  Backend 2  │    │
│    SSH      │      │  (PAM LLNG) │   │   │ (PAM LLNG)  │   │ (PAM LLNG)  │    │
└──────┬──────┘      └──────┬──────┘   │   └──────┬──────┘   └──────┬──────┘    │
       │                    │          │          │                  │           │
       │ 1. ssh bastion     │          │          │                  │           │
       │───────────────────>│          │          │                  │           │
       │                    │          │          │                  │           │
       │    2. PAM vérifie  │          │          │                  │           │
       │       sur LLNG     │          │          │                  │           │
       │                    │          │          │                  │           │
       │ 3. Session bastion │          │          │                  │           │
       │<───────────────────│          │          │                  │           │
       │                    │          │          │                  │           │
       │ 4. ssh backend1    │          │          │                  │           │
       │───────────────────>│──────────┼─────────>│                  │           │
       │                    │          │          │                  │           │
       │                    │          │   5. PAM vérifie            │           │
       │                    │          │      sur LLNG               │           │
       │                    │          │          │                  │           │
       │ 6. Session backend │          │          │                  │           │
       │<───────────────────┼──────────┼──────────│                  │           │
       │                    │          │          │                  │           │
       └────────────────────┴──────────┴──────────┴──────────────────┴───────────┘
                                       │           Réseau privé                  │
                                       └─────────────────────────────────────────┘
```

### Double vérification PAM

1. **Sur le bastion** : LLNG vérifie que l'utilisateur peut accéder au bastion
2. **Sur le backend** : LLNG vérifie que l'utilisateur peut accéder à ce backend spécifique

### Configuration réseau sécurisée (backends)

**IMPORTANT** : Pour maximiser la sécurité, les backends doivent être configurés pour n'accepter les connexions SSH que depuis le bastion :

```bash
# /etc/ssh/sshd_config sur les backends
# Accepter UNIQUEMENT les connexions depuis le bastion
ListenAddress 10.0.0.0    # IP privée uniquement
# OU utiliser un firewall :
# iptables -A INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT  # IP bastion
# iptables -A INPUT -p tcp --dport 22 -j DROP
```

Ou via groupe de sécurité (AWS/GCP/Azure) :
- Backends : SSH (22) autorisé uniquement depuis le security group du bastion

### Avantages sécurité

| Aspect                | Sans restriction réseau       | Avec restriction au bastion      |
| --------------------- | ----------------------------- | -------------------------------- |
| Surface d'attaque     | Backends exposés              | Bastion seul exposé              |
| Contournement         | Possible si IP backend connue | Impossible                       |
| Audit                 | Partiel                       | Complet (tout passe par bastion) |
| Compromission bastion | Accès backends                | Accès backends (identique)       |

### Configuration server_group

```ini
# Bastion : /etc/security/pam_llng.conf
server_group = bastion

# Backends : /etc/security/pam_llng.conf
server_group = backend-prod
```

Côté LLNG, définir les autorisations :
- Groupe "ops" → accès bastion + backend-prod
- Groupe "dev" → accès bastion + backend-dev
- Groupe "admin" → accès bastion + tous backends

---

## 5. Architecture D : Bastion + Backends + SSH CA

### Description

Architecture optimale combinant :
- Bastion comme point d'entrée unique
- Certificats SSH pour traçabilité et révocation
- Double vérification PAM sur bastion et backends
- Restriction réseau des backends

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                                                                  │
│  ┌─────────────┐                                           ┌─────────────┐      │
│  │   SSH CA    │                                           │   Portail   │      │
│  │ (signe les  │                                           │    LLNG     │      │
│  │ certificats)│                                           │             │      │
│  └──────┬──────┘                                           └──────┬──────┘      │
│         │                                                         │             │
│         │ Certificat signé                                        │             │
│         ▼                                                         │             │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐       │             │
│  │   Client    │      │   Bastion   │      │   Backend   │       │             │
│  │    SSH      │─────>│  (PAM LLNG) │─────>│  (PAM LLNG) │       │             │
│  │ (cert signé)│      │ (TrustedCA) │      │ (TrustedCA) │       │             │
│  └─────────────┘      └──────┬──────┘      └──────┬──────┘       │             │
│                              │                    │               │             │
│                              │ Vérifie cert +     │ Vérifie cert +│             │
│                              │ autorise via LLNG  │ autorise LLNG │             │
│                              │                    │               │             │
│                              └────────────────────┴───────────────┘             │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Flux complet

1. **Émission certificat** : L'utilisateur obtient un certificat SSH signé par la CA
   - Durée de vie courte (ex: 8h, 24h)
   - Principals = username + groupes
   - key_id = identifiant unique pour audit

2. **Connexion bastion** :
   - SSH vérifie la signature CA
   - PAM LLNG envoie les infos certificat à LLNG
   - LLNG vérifie : utilisateur actif, certificat non révoqué, accès bastion autorisé

3. **Connexion backend** :
   - Même certificat présenté au backend
   - SSH vérifie la signature CA
   - PAM LLNG envoie les infos certificat à LLNG
   - LLNG vérifie : accès backend autorisé

### Agent forwarding vs ProxyJump

**Option 1 : Agent forwarding** (déconseillé)
```bash
ssh -A bastion
# puis sur bastion:
ssh backend
```
⚠️ Risque : Si le bastion est compromis, l'attaquant peut utiliser l'agent.

**Option 2 : ProxyJump** (recommandé)
```bash
ssh -J bastion backend
# ou dans ~/.ssh/config:
Host backend
    ProxyJump bastion
```
✓ La clé privée ne quitte jamais le client.

### Configuration complète

**CA SSH :**
```bash
# Générer la CA
ssh-keygen -t ed25519 -f /etc/ssh/ca_key -C "SSH CA"

# Signer un certificat utilisateur (durée 8h)
ssh-keygen -s /etc/ssh/ca_key \
    -I "user@example.com-$(date +%Y%m%d)" \
    -n "username" \
    -V +8h \
    -z $(date +%s) \
    user_key.pub
```

**Serveurs (bastion et backends) :**
```bash
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/ca_user_key.pub
ExposeAuthInfo yes
# Optionnel: révocation
RevokedKeys /etc/ssh/revoked_keys
```

**Backends uniquement :**
```bash
# Restreindre l'accès au bastion
# /etc/ssh/sshd_config
ListenAddress 10.0.0.0  # Réseau privé uniquement
```

---

## 6. Analyse des Risques

### Échelle de cotation

| Score | Probabilité     | Impact      |
| ----- | --------------- | ----------- |
| 1     | Très improbable | Négligeable |
| 2     | Peu probable    | Limité      |
| 3     | Probable        | Important   |
| 4     | Très probable   | Critique    |

---

### R-S1 - Authentification par mot de passe SSH

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   3   |
| **Impact**      |   4   |

**Architectures concernées :** A, B, C, D (si mal configuré)

**Description :** L'authentification SSH par mot de passe est vulnérable aux attaques par force brute et au phishing.

**Vecteurs d'attaque :**
- Brute-force du mot de passe
- Credential stuffing (mots de passe réutilisés)
- Phishing pour obtenir le mot de passe
- Keylogger sur le client

**Remédiation configuration :**
```bash
# /etc/ssh/sshd_config
PasswordAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
```

|                 | Score résiduel             |
| --------------- | :------------------------: |
| **Probabilité** | 1 (avec clés uniquement)   |
| **Impact**      |             4              |

---

### R-S2 - Vol de clé SSH privée

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   2   |
| **Impact**      |   4   |

**Architectures concernées :** A, C (sans certificats)

**Description :** Une clé SSH privée volée permet un accès illimité jusqu'à sa suppression manuelle des authorized_keys.

**Vecteurs d'attaque :**
- Compromission du poste client
- Backup non chiffré contenant la clé
- Clé sans passphrase
- Malware voleur de clés

**Conséquence :** Accès permanent à tous les serveurs où la clé est autorisée.

**Remédiation embarquée :**
- PAM LLNG vérifie l'autorisation à chaque connexion (l'utilisateur peut être désactivé)
- Audit des connexions avec IP source

**Remédiation configuration :**
```bash
# Clés avec passphrase obligatoire
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/id_ed25519
# -a 100 : 100 rounds de dérivation (protection brute-force passphrase)

# Utiliser ssh-agent avec timeout
ssh-add -t 8h ~/.ssh/id_ed25519
```

**Remédiation architecturale :**
- Passer à l'architecture B ou D (certificats avec durée de vie limitée)

|                 | Score résiduel                                    |
| --------------- | :-----------------------------------------------: |
| **Probabilité** |                         2                         |
| **Impact**      | 3 (avec désactivation utilisateur LLNG possible)  |

---

### R-S3 - Certificat SSH compromis

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   2   |
| **Impact**      |   3   |

**Architectures concernées :** B, D

**Description :** Un certificat SSH volé permet un accès limité dans le temps (durée de validité du certificat).

**Vecteurs d'attaque :**
- Mêmes que R-S2 (compromission poste client)

**Facteurs atténuants :**
- Durée de vie courte du certificat (8h-24h recommandé)
- Révocation possible via LLNG ou CRL SSH
- Le serial permet d'identifier précisément le certificat compromis

**Remédiation embarquée :**
- PAM LLNG envoie le serial à LLNG pour vérification de révocation
- Audit complet avec key_id et serial

**Remédiation configuration (côté LLNG) :**
- Liste de révocation par serial
- Alerte si même certificat utilisé depuis IPs différentes

|                 | Score résiduel                        |
| --------------- | :-----------------------------------: |
| **Probabilité** | 1 (avec durée courte + révocation)    |
| **Impact**      |          2 (durée limitée)            |

---

### R-S4 - Compromission de la CA SSH

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   1   |
| **Impact**      |   4   |

**Architectures concernées :** B, D

**Description :** Si la clé privée de la CA SSH est compromise, l'attaquant peut émettre des certificats pour n'importe quel utilisateur.

**Vecteurs d'attaque :**
- Compromission du serveur hébergeant la CA
- Backup non chiffré de la clé CA
- Insider malveillant

**Conséquence :** Accès total à tous les serveurs faisant confiance à cette CA.

**Remédiation configuration :**
```bash
# CA sur machine air-gapped ou HSM
# Clé CA avec passphrase forte
ssh-keygen -t ed25519 -a 100 -f /secure/ca_key -C "SSH CA"

# Permissions strictes
chmod 400 /secure/ca_key
```

**Remédiation procédurale :**
- CA sur machine dédiée, non connectée au réseau
- Signature des certificats via processus audité
- Rotation périodique de la CA

**Remédiation architecturale :**
- Utiliser un HSM pour stocker la clé CA
- Short-lived CA (renouvellement régulier)

|                 | Score résiduel |
| --------------- | :------------: |
| **Probabilité** |       1        |
| **Impact**      |       4        |

---

### R-S5 - Contournement du bastion

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   3   |
| **Impact**      |   3   |

**Architectures concernées :** C, D (si mal configuré)

**Description :** Si les backends sont accessibles directement (sans passer par le bastion), la sécurité du bastion est contournée.

**Vecteurs d'attaque :**
- Backends avec SSH ouvert sur IP publique
- Règles firewall permissives
- VPN donnant accès direct au réseau des backends

**Conséquence :**
- Perte de l'audit centralisé
- Surface d'attaque élargie
- Attaques directes sur les backends

**Remédiation configuration (CRITIQUE) :**
```bash
# Sur les backends : /etc/ssh/sshd_config
ListenAddress 10.0.0.0  # Réseau privé uniquement

# Firewall sur les backends
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT  # IP bastion
iptables -A INPUT -p tcp --dport 22 -j DROP

# Security groups (cloud)
# Backend SG: SSH (22) from Bastion-SG only
```

**Vérification :**
```bash
# Depuis l'extérieur, doit échouer :
ssh -o ConnectTimeout=5 backend.internal.example.com
# Connection refused / timeout = OK
```

|                 | Score résiduel                  |
| --------------- | :-----------------------------: |
| **Probabilité** | 1 (avec restriction réseau)     |
| **Impact**      |               3                 |

---

### R-S6 - Compromission du bastion

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   2   |
| **Impact**      |   4   |

**Architectures concernées :** C, D

**Description :** Si le bastion est compromis, l'attaquant a potentiellement accès à tous les backends.

**Vecteurs d'attaque :**
- Exploit sur le bastion (vulnérabilité SSH, système)
- Credentials volés d'un admin bastion
- Supply chain attack

**Conséquence :**
- Interception des connexions transitant par le bastion
- Pivot vers les backends
- Vol de clés si agent forwarding utilisé

**Remédiation embarquée :**
- PAM LLNG sur les backends = double vérification
- Même si le bastion est compromis, l'attaquant doit avoir des credentials valides pour chaque backend

**Remédiation configuration :**
```bash
# Interdire l'agent forwarding sur le bastion
# /etc/ssh/sshd_config
AllowAgentForwarding no

# Utiliser ProxyJump côté client (la clé ne touche jamais le bastion)
# ~/.ssh/config
Host backend
    ProxyJump bastion
```

**Remédiation procédurale :**
- Bastion durci (CIS benchmark)
- Pas de comptes utilisateurs sur le bastion (passage uniquement)
- Monitoring renforcé du bastion

**Réduction d'impact avec PAM LLNG sur backends :**
- Même depuis un bastion compromis, chaque accès backend est vérifié
- L'attaquant doit compromettre AUSSI les credentials utilisateur

|                 | Score résiduel                      |
| --------------- | :---------------------------------: |
| **Probabilité** |                  2                  |
| **Impact**      | 3 (avec PAM LLNG sur backends)      |

---

### R-S7 - Serveur LLNG indisponible

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   2   |
| **Impact**      |   3   |

**Architectures concernées :** A, B, C, D

**Description :** Si LLNG est indisponible, les nouvelles connexions SSH ne peuvent pas être autorisées (sauf cache).

**Vecteurs d'attaque :**
- Panne réseau entre serveurs SSH et LLNG
- DoS sur LLNG
- Maintenance LLNG

**Conséquence :** Les utilisateurs ne peuvent plus se connecter aux serveurs.

**Remédiation embarquée :**
- Cache d'authentification offline (`src/auth_cache.c`)
- Les utilisateurs précédemment autorisés peuvent continuer à se connecter

**Remédiation configuration :**
```ini
# /etc/security/pam_llng.conf
auth_cache = true
auth_cache_ttl = 3600        # 1 heure de cache
auth_cache_offline_ttl = 86400  # 24h si LLNG indisponible
```

**Remédiation infrastructure :**
- LLNG en haute disponibilité
- Plusieurs portails LLNG (failover)

|                 | Score résiduel           |
| --------------- | :----------------------: |
| **Probabilité** |      1 (avec HA)         |
| **Impact**      | 2 (avec cache offline)   |

---

### R-S8 - Session SSH persistante après révocation

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   3   |
| **Impact**      |   2   |

**Architectures concernées :** A, B, C, D

**Description :** Une session SSH déjà établie n'est pas terminée si l'utilisateur est révoqué dans LLNG.

**Vecteurs d'attaque :**
- Utilisateur révoqué maintient une session ouverte
- Screen/tmux avec session persistante

**Conséquence :** L'utilisateur révoqué conserve son accès tant que la session est active.

**Remédiation configuration :**
```bash
# /etc/ssh/sshd_config
ClientAliveInterval 300      # Ping toutes les 5 min
ClientAliveCountMax 2        # Déconnexion après 2 échecs

# Timeout de session
# /etc/profile.d/timeout.sh
TMOUT=3600  # Déconnexion après 1h d'inactivité
```

**Remédiation procédurale :**
- Script de révocation qui tue les sessions actives :
```bash
# Lors de la révocation d'un utilisateur
pkill -u $USERNAME -KILL
```

|                 | Score résiduel |
| --------------- | :------------: |
| **Probabilité** |       2        |
| **Impact**      |       2        |

---

## 7. Matrices des Risques par Architecture

### Architecture A : Serveur Isolé

**Avant remédiation :**
```
                                    PROBABILITÉ
              ┌────────────────┬────────────────┬────────────────┬────────────────┐
              │       1        │       2        │       3        │       4        │
              │ Très improbable│  Peu probable  │    Probable    │ Très probable  │
   ┌──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
   │    4     │                │     R-S2       │     R-S1       │                │
 I │ Critique │                │                │                │                │
 M ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 P │    3     │                │     R-S7       │     R-S8       │                │
 A │Important │                │                │                │                │
 C ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 T │    2     │                │                │                │                │
   │  Limité  │                │                │                │                │
   └──────────┴────────────────┴────────────────┴────────────────┴────────────────┘
```

**Après remédiation :**
```
                                    PROBABILITÉ
              ┌────────────────┬────────────────┬────────────────┬────────────────┐
              │       1        │       2        │       3        │       4        │
              │ Très improbable│  Peu probable  │    Probable    │ Très probable  │
   ┌──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
   │    4     │     R-S1       │                │                │                │
 I │ Critique │                │                │                │                │
 M ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 P │    3     │                │     R-S2       │                │                │
 A │Important │                │                │                │                │
 C ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 T │    2     │     R-S7       │    R-S8        │                │                │
   │  Limité  │                │                │                │                │
   └──────────┴────────────────┴────────────────┴────────────────┴────────────────┘
```

---

### Architecture B : Serveur Isolé + SSH CA

**Avant remédiation :**
```
                                    PROBABILITÉ
              ┌────────────────┬────────────────┬────────────────┬────────────────┐
              │       1        │       2        │       3        │       4        │
              │ Très improbable│  Peu probable  │    Probable    │ Très probable  │
   ┌──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
   │    4     │     R-S4       │                │     R-S1       │                │
 I │ Critique │                │                │                │                │
 M ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 P │    3     │                │  R-S3  R-S7    │     R-S8       │                │
 A │Important │                │                │                │                │
 C ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 T │    2     │                │                │                │                │
   │  Limité  │                │                │                │                │
   └──────────┴────────────────┴────────────────┴────────────────┴────────────────┘
```

**Après remédiation :**
```
                                    PROBABILITÉ
              ┌────────────────┬────────────────┬────────────────┬────────────────┐
              │       1        │       2        │       3        │       4        │
              │ Très improbable│  Peu probable  │    Probable    │ Très probable  │
   ┌──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
   │    4     │  R-S1  R-S4    │                │                │                │
 I │ Critique │                │                │                │                │
 M ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 P │    3     │                │                │                │                │
 A │Important │                │                │                │                │
 C ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 T │    2     │  R-S3  R-S7    │     R-S8       │                │                │
   │  Limité  │                │                │                │                │
   └──────────┴────────────────┴────────────────┴────────────────┴────────────────┘
```

**Bénéfices SSH CA :** R-S3 (certificat compromis) remplace R-S2 (clé compromise) avec impact réduit grâce à la durée de vie limitée.

---

### Architecture C : Bastion + Backends

**Avant remédiation :**
```
                                    PROBABILITÉ
              ┌────────────────┬────────────────┬────────────────┬────────────────┐
              │       1        │       2        │       3        │       4        │
              │ Très improbable│  Peu probable  │    Probable    │ Très probable  │
   ┌──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
   │    4     │                │     R-S6       │     R-S1       │                │
 I │ Critique │                │                │                │                │
 M ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 P │    3     │                │  R-S2  R-S7    │  R-S5  R-S8    │                │
 A │Important │                │                │                │                │
 C ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 T │    2     │                │                │                │                │
   │  Limité  │                │                │                │                │
   └──────────┴────────────────┴────────────────┴────────────────┴────────────────┘
```

**Après remédiation (avec restriction réseau backends) :**
```
                                    PROBABILITÉ
              ┌────────────────┬────────────────┬────────────────┬────────────────┐
              │       1        │       2        │       3        │       4        │
              │ Très improbable│  Peu probable  │    Probable    │ Très probable  │
   ┌──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
   │    4     │     R-S1       │                │                │                │
 I │ Critique │                │                │                │                │
 M ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 P │    3     │     R-S5       │  R-S2  R-S6    │                │                │
 A │Important │                │                │                │                │
 C ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 T │    2     │     R-S7       │     R-S8       │                │                │
   │  Limité  │                │                │                │                │
   └──────────┴────────────────┴────────────────┴────────────────┴────────────────┘
```

**Bénéfice restriction réseau :** R-S5 (contournement bastion) passe de P=3 à P=1.

---

### Architecture D : Bastion + Backends + SSH CA

**Avant remédiation :**
```
                                    PROBABILITÉ
              ┌────────────────┬────────────────┬────────────────┬────────────────┐
              │       1        │       2        │       3        │       4        │
              │ Très improbable│  Peu probable  │    Probable    │ Très probable  │
   ┌──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
   │    4     │     R-S4       │     R-S6       │     R-S1       │                │
 I │ Critique │                │                │                │                │
 M ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 P │    3     │                │  R-S3  R-S7    │  R-S5  R-S8    │                │
 A │Important │                │                │                │                │
 C ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 T │    2     │                │                │                │                │
   │  Limité  │                │                │                │                │
   └──────────┴────────────────┴────────────────┴────────────────┴────────────────┘
```

**Après remédiation complète :**
```
                                    PROBABILITÉ
              ┌────────────────┬────────────────┬────────────────┬────────────────┐
              │       1        │       2        │       3        │       4        │
              │ Très improbable│  Peu probable  │    Probable    │ Très probable  │
   ┌──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
   │    4     │  R-S1  R-S4    │                │                │                │
 I │ Critique │                │                │                │                │
 M ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 P │    3     │     R-S5       │     R-S6       │                │                │
 A │Important │                │                │                │                │
 C ├──────────┼────────────────┼────────────────┼────────────────┼────────────────┤
 T │    2     │  R-S3  R-S7    │     R-S8       │                │                │
   │  Limité  │                │                │                │                │
   └──────────┴────────────────┴────────────────┴────────────────┴────────────────┘
```

**Architecture D = meilleur profil de risque :**
- Tous les risques critiques en P=1
- Certificats → durée de vie limitée
- Bastion → point d'entrée unique
- Restriction réseau → pas de contournement

---

## 8. Synthèse des Remédiations par Architecture

### Checklist Architecture A (Serveur Isolé)

- [ ] Désactiver l'authentification par mot de passe
- [ ] Clés SSH avec passphrase
- [ ] ssh-agent avec timeout
- [ ] PAM LLNG configuré avec `server_group`
- [ ] Cache offline activé
- [ ] Monitoring des connexions

### Checklist Architecture B (Serveur Isolé + SSH CA)

Tout de A, plus :
- [ ] CA SSH sur machine sécurisée (air-gap ou HSM)
- [ ] `TrustedUserCAKeys` configuré
- [ ] `ExposeAuthInfo yes` dans sshd_config
- [ ] Certificats avec durée de vie courte (8-24h)
- [ ] Processus de révocation documenté

### Checklist Architecture C (Bastion + Backends)

Tout de A, plus :
- [ ] **CRITIQUE** : Backends accessibles UNIQUEMENT depuis le bastion
- [ ] Firewall/Security Groups configurés
- [ ] `AllowAgentForwarding no` sur le bastion
- [ ] Clients configurés avec `ProxyJump`
- [ ] PAM LLNG sur bastion ET backends
- [ ] `server_group` différents (bastion vs backends)

### Checklist Architecture D (Bastion + Backends + SSH CA)

Tout de B et C, plus :
- [ ] CA SSH signant les certificats utilisateur
- [ ] Même CA de confiance sur bastion et backends
- [ ] Révocation centralisée via LLNG
- [ ] Audit complet avec key_id/serial

---

## 9. Recommandations

### Choix d'architecture

| Contexte | Architecture recommandée |
|----------|-------------------------|
| Petit projet, peu de serveurs | A (avec clés + PAM LLNG) |
| Conformité audit renforcé | B (certificats pour traçabilité) |
| Infrastructure importante | C (bastion obligatoire) |
| Haute sécurité / production critique | D (bastion + certificats) |

### Évolution progressive

```
A → B : Ajouter SSH CA
    └─ Gain : traçabilité, révocation, durée limitée

A → C : Ajouter bastion
    └─ Gain : point d'entrée unique, audit centralisé

B → D : Ajouter bastion
C → D : Ajouter SSH CA
    └─ Gain : cumul des avantages
```
