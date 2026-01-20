Pistes exploratoires pour améliorer la sécurité mais non implémentées.

## Vue Globale

### Matrice des Risques Après Remédiation (avec clients OIDC distincts + JWT bastion)

| Impact ↓ / Probabilité → |              1 - Très improbable                  | 2 - Peu probable |
|--------------------------|---------------------------------------------------|------------------|
| **4 - Critique**         | R5, R-S1, R-S4, R-SA2                             | R-SA1            |
| **3 - Important**        | R1, R3, R8, R12, R-S5                             | R-S6             |
| **2 - Limité**           | R4, R7, R9, R10, R11, R-S3, R-S7, R-S9, R-S10     | R6, R-S8         |
| **1 - Négligeable**      | R0, R13                                           |                  |

**Zones de risque :**
- Score ≥ 6 : Zone rouge (aucun risque dans cette zone après remédiation)
- Score 4-5 : Zone jaune → R5, R-S1, R-S4, R-SA2 (P=1, I=4), R-SA1 (P=2, I=4/3), R6, R-S8 (P=2, I=2), R-S6 (P=2, I=3)
- Score ≤ 3 : Zone verte → Tous les autres risques

**Nouveaux risques identifiés (PR #64 - JWT bastion) :**
- **R-S9** : Replay d'un JWT bastion intercepté (P=1, I=2 - détection replay réduit P)
- **R-S10** : Rotation des clés JWKS non propagée (P=1, I=1 - atténué par publication anticipée LLNG)

**Risques spécifiques aux comptes de service :**
- **R-SA1** : Vol de clé de compte de service (P=2, I=4 → I=3 avec monitoring)
- **R-SA2** : Compromission du fichier de configuration (P=1, I=4 - atténué par vérifications embarquées)

**Amélioration par intégration CrowdSec :**
- **R-S1** : Protection renforcée contre brute-force (blocage IPs communautaires + auto-ban local)
- **R-S6** : Détection comportementale sur le bastion (alertes centralisables via Crowdsieve)

Voir [01-enrollment.md](01-enrollment.md) et [02-ssh-connection.md](02-ssh-connection.md) pour les détails des risques et remédiations.

Voir [03-offboarding.md](03-offboarding.md) pour la procédure de révocation des accès administrateurs.

Voir la section "Comptes de Service" de [02-ssh-connection.md](02-ssh-connection.md) pour les risques spécifiques aux comptes de service.

---

## Pistes d'Amélioration - Enrôlement

### R5 _(P=1, I=4)_ - Usurpation du serveur LLNG

Pistes pour réduire la probabilité à quasi-zéro :
1. Rendre le certificate pinning obligatoire (pas juste recommandé)
2. mTLS : Le serveur PAM présente aussi un certificat client
3. DANE (DNSSEC + TLSA) : Validation du certificat via DNS signé

### R6 _(P=2, I=2)_ - Expiration device_code

Pistes pour réduire P à 1 :
1. Notification push quand l'admin approuve (l'opérateur sait que c'est bon)

### R1, R4, R7, R11 - Risques liés aux tokens/credentials

Pistes pour réduire I à 1 :
1. Token lié au matériel (TPM/HSM) : Le token ne peut être utilisé que sur la machine qui l'a obtenu
2. Groupes dynamiques basés sur des attributs (département, projet)

### R8 _(P=1, I=3)_ - Fuite mémoire

Pistes pour réduire P :
1. mlock() pour empêcher le swap des secrets
2. Intégration HSM/TPM pour ne jamais exposer le secret en mémoire utilisateur

---

## Pistes d'Amélioration - SSH

### R-S1 _(P=1, I=4)_ - Authentification par mot de passe

Pistes supplémentaires :
1. Audit automatisé de la configuration sshd (compliance check)
2. Alerting si `PasswordAuthentication yes` détecté

### R-S4 _(P=1, I=4)_ - Compromission de la CA SSH

Pistes supplémentaires :
1. CA intermédiaire (limiter l'exposition de la CA racine)
2. Rotation périodique de la CA avec période de transition
3. Monitoring des certificats émis (détection d'anomalies)

### R-S6 _(P=2, I=3)_ - Compromission du bastion

Pistes pour réduire P à 1 :
1. **Bastion éphémère** : Recréer le bastion régulièrement (immutable infrastructure)
2. **Zero-trust** : Pas de shell sur le bastion, uniquement ProxyJump
3. **Durcissement CIS** : Benchmark automatisé + remediation
4. **EDR/monitoring renforcé** : Détection d'intrusion sur le bastion

Pistes pour réduire I à 2 :
1. **Segmentation fine** : Plusieurs bastions par zone de sécurité
2. **Session recording** : Enregistrement de toutes les sessions transitant par le bastion

### R-S8 _(P=2, I=2)_ - Session persistante après révocation

Pistes pour réduire P à 1 :
1. **Webhook de révocation** : LLNG notifie les serveurs pour tuer les sessions
2. **Agent PAM actif** : Vérification périodique de l'autorisation (toutes les N minutes)
3. **Session courte forcée** : `TMOUT` + `ClientAliveInterval` agressifs

**Implémentation possible (côté PAM) :**
```c
// Vérification périodique dans un thread ou via cron
// Si utilisateur révoqué → envoyer SIGHUP au processus sshd de l'utilisateur
```

---

## Pistes d'Amélioration - JWT Bastion

### R-S9 _(P=1, I=2)_ - Replay JWT bastion - **IMPLÉMENTÉ**

**Détection de replay implémentée via cache JTI :**

Le module PAM maintient un cache thread-safe des `jti` (JWT ID) utilisés :

```c
// src/jti_cache.c - Vérifie et ajoute atomiquement
jti_cache_result_t result = jti_cache_check_and_add(cache, claims->jti, claims->exp);
if (result == JTI_CACHE_REPLAY_DETECTED) {
    return BASTION_JWT_REPLAY_DETECTED;
}
```

**Configuration :**
```ini
# /etc/open-bastion/openbastion.conf
bastion_jwt_replay_detection = true   # Activé par défaut
bastion_jwt_replay_cache_size = 10000 # Max entrées
bastion_jwt_replay_cleanup_interval = 60  # Nettoyage automatique
```

**Caractéristiques :**
- Cache hash table O(1) pour lookup/insertion
- Thread-safe avec mutex
- Nettoyage automatique des entrées expirées
- Gestion de la saturation (cleanup puis rejet si plein)

Pistes supplémentaires (non implémentées) :
1. **Vérification stricte IP** : Rejeter si `bastion_ip` != IP source SSH
2. **Nonce challenge** : Le backend génère un nonce (complexifie le protocole)

### R-S10 _(P=1, I=1)_ - Rotation JWKS non propagée

**Risque largement atténué par l'implémentation LLNG :**

LemonLDAP::NG gère nativement la rotation de clés de manière sécurisée :
- La future clé est publiée dans le JWKS **avant** d'être utilisée
- L'ancienne clé reste disponible **après** la rotation

→ Avec un TTL de cache ≤ 24h, la rotation est transparente et sans interruption.

Piste supplémentaire (optionnelle) :
1. **Push de notification** : LLNG notifie les backends via webhook pour refresh immédiat (utile uniquement en cas de compromission)

---

## Sécurités Implémentées (valorisation)

### Intégration CrowdSec - **IMPLÉMENTÉ**

Le module PAM intègre CrowdSec pour la détection et le blocage des menaces :

**Bouncer (pré-authentification) :**
```c
// src/crowdsec.c - Vérifie si l'IP est bannie avant auth
crowdsec_result_t result = crowdsec_check_ip(ctx, client_ip);
if (result == CS_DENY) {
    // Bloquer ou avertir selon crowdsec_action
}
```

**Watcher (post-authentification) :**
```c
// src/crowdsec.c - Reporte les échecs d'authentification
crowdsec_report_failure(ctx, client_ip, username, service);
// Auto-ban après max_failures dans block_delay secondes
```

**Configuration :**
```ini
# /etc/open-bastion/openbastion.conf
crowdsec_enabled = true
crowdsec_url = http://127.0.0.1:8080

# Bouncer
crowdsec_bouncer_key = <bouncer_key>
crowdsec_action = reject  # ou warn
crowdsec_fail_open = true

# Watcher
crowdsec_machine_id = <machine_id>
crowdsec_password = <password>
crowdsec_scenario = open-bastion/ssh-auth-failure
crowdsec_send_all_alerts = true
crowdsec_max_failures = 5
crowdsec_block_delay = 180
crowdsec_ban_duration = 4h
```

**Bénéfices sécurité :**
- Protection collaborative : bénéficie de la base de données communautaire CrowdSec
- Détection précoce : blocage des IPs malveillantes avant authentification
- Auto-ban local : bannissement automatique après N échecs
- Centralisation possible via [Crowdsieve](https://github.com/linagora/crowdsieve)

**Risques impactés :**
- **R-S1** : Réduction de P grâce au blocage des IPs de brute-force connues
- **R-S6** : Détection des comportements anormaux sur le bastion

### Génération UUID cryptographiquement sécurisée

Le `jti` (JWT ID) des tokens bastion est généré avec :
1. `Crypt::URandom` (si disponible)
2. `/dev/urandom` (fallback)

→ Protection contre les collisions et la prédictibilité.

### Vérification permissions fichier config (ob-ssh-proxy)

Le script vérifie avant de sourcer le fichier de configuration :
- Propriétaire = root (uid 0)
- Pas de permission group-writable ou world-writable

→ Protection contre l'injection de configuration malveillante.

### Construction JSON sécurisée

Le script utilise `jq` pour construire les payloads JSON au lieu d'interpolation directe :
```bash
json_payload=$(jq -n --arg user "$user" '{user: $user}')
```

→ Protection contre l'injection JSON.

### Vérification sécurisée du fichier de configuration des comptes de service

Le module PAM vérifie avant de charger `/etc/open-bastion/service-accounts.conf` :
- Ouverture avec `O_NOFOLLOW` (pas de symlinks)
- Vérification `fstat()` sur le fd ouvert (évite TOCTOU)
- Propriétaire = root (uid 0)
- Permissions strictes (pas de lecture group/other)

→ Protection contre l'injection de comptes de service malveillants.

### Validation stricte des comptes de service

- Nom : lowercase + chiffres + underscore/tiret, max 32 caractères
- Fingerprint : format SHA256: ou MD5: avec caractères base64 uniquement
- Shell : doit être dans la liste `approved_shells`
- Home : doit commencer par un préfixe de `approved_home_prefixes`

→ Protection contre les comptes mal configurés ou malveillants.

### Codes d'audit différenciés

- `AUDIT_SECURITY_ERROR` : Échecs cryptographiques (signature invalide, JWT malformé)
- `AUDIT_AUTHZ_DENIED` : Échecs d'autorisation (subject mismatch, bastion non autorisé)

→ Meilleure classification des incidents pour le SIEM.
