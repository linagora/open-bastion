Analyse des Risques - État Après Remédiations

## Risques Enrôlement

| Risque                            | Score (P×I) | Zone             | Remédiation                        |
|-----------------------------------|-------------|------------------|------------------------------------|
| R5                                | 1×4 = 4     | Critique         | Certificate pinning recommandé     |
| R6                                | 2×2 = 4     | Jaune (P=2, I=2) | TTL 10 min par défaut              |
| R1, R2, R3, R4, R7, R8, R11, R12  | 1×3 = 3     | Vert/Important   | Voir détails ci-dessous            |
| R0, R9, R10                       | 1×2 = 2     | Vert/Limité      | -                                  |
| R13                               | 1×1 = 1     | Négligeable      | PKCE implémenté                    |

**Changement notable :** R2 passe de P=2 à P=1 grâce à l'intégration CrowdSec (rate-limiting IP).

## Risques Connexion SSH (Architecture D)

Architecture optimale : Bastion + Backends + SSH CA + restrictions réseau

| Risque | Score (P×I) | Zone           | Remédiation                                     |
|--------|-------------|----------------|-------------------------------------------------|
| R-S1   | 1×4 = 4     | Critique       | `PasswordAuthentication no`                     |
| R-S4   | 1×4 = 4     | Critique       | CA sur HSM/air-gap                              |
| R-S5   | 1×3 = 3     | Vert/Important | Backends accessibles uniquement via bastion     |
| R-S6   | 2×3 = 6     | Jaune          | PAM LLNG sur backends + `AllowAgentForwarding no` |
| R-S3   | 1×2 = 2     | Vert/Limité    | Certificats courte durée (8-24h)                |
| R-S7   | 1×2 = 2     | Vert/Limité    | LLNG HA + cache offline                         |
| R-S8   | 2×2 = 4     | Jaune          | `ClientAliveInterval` + kill sessions           |

**Légende risques SSH :**
- **R-S1** : Authentification par mot de passe
- **R-S3** : Certificat SSH compromis
- **R-S4** : Compromission de la CA SSH
- **R-S5** : Contournement du bastion
- **R-S6** : Compromission du bastion
- **R-S7** : Serveur LLNG indisponible
- **R-S8** : Session persistante après révocation

Voir [02-ssh-connection.md](02-ssh-connection.md) pour les détails.

Pistes d'Amélioration par Risque

# R5 _(P=1, I=4)_ - Usurpation du serveur LLNG

Problème : Impact critique irréductible (compromission du SSO = game over)

Pistes pour réduire la probabilité à quasi-zéro :
1. Rendre le certificate pinning obligatoire (pas juste recommandé)
2. mTLS : Le serveur PAM présente aussi un certificat client
3. DANE (DNSSEC + TLSA) : Validation du certificat via DNS signé

# R2 _(P=1, I=3)_ - Brute-force du user_code (avec CrowdSec)

**Recommandations RFC 8628 :**

La RFC est claire : la protection repose sur la **combinaison entropie + rate-limiting**, pas sur un seul facteur.

| Format | Tentatives autorisées | Probabilité de succès |
|--------|----------------------|----------------------|
| 8 caractères base-20 | 5 tentatives max | 2^-32 (négligeable) |

**Format recommandé par la RFC :**
- **Base-20 sans voyelles** : `BCDFGHJKLMNPQRSTVWXZ`
  - Évite de former des mots embarrassants/offensants
  - Facile à saisir sur mobile (pas de shift, pas de chiffres)
  - Format typique : `BDFC-GHJK` (avec tiret pour lisibilité)
- **Alternative numérique** : 9+ chiffres pour entropie équivalente

**Implémentation LLNG :**

Le plugin `OIDCDeviceAuthorization.pm` implémente les recommandations RFC 8628 :

1. **Format user_code conforme** : Base-20 sans voyelles (`BCDFGHJKLMNPQRSTVWXZ`)
   - Évite les mots offensants
   - Format `XXXX-XXXX` pour la lisibilité
   - Configurable via `oidcServiceDeviceAuthorizationUserCodeLength` (défaut: 8)

2. **Intégration CrowdSec** : Rate-limiting IP délégué à CrowdSec
   - Scénario : `llng/device-auth-bruteforce`
   - Chaque tentative invalide est signalée via `_reportInvalidUserCode()`
   - Lockout automatique après N échecs (configurable dans CrowdSec)
   - Warning affiché si CrowdSec n'est pas configuré

3. **Expiration courte** : 10 min par défaut (`oidcServiceDeviceAuthorizationExpiration`)

**Configuration recommandée (côté LLNG) :**
```yaml
# Activer CrowdSec pour le rate-limiting (FORTEMENT RECOMMANDÉ)
crowdsec: 1
crowdsecAgent: 1

# Optionnel : réduire le TTL du device_code
oidcServiceDeviceAuthorizationExpiration: 300  # 5 min au lieu de 10
```

Avec CrowdSec activé, P passe à 1 car le brute-force devient "infeasible" (RFC 8628)

# R6 _(P=2, I=2)_ - Expiration device_code

Pistes pour réduire P à 1 :
1. Augmenter le TTL par défaut (10 min au lieu de 5)
2. Notification push quand l'admin approuve (l'opérateur sait que c'est bon)

# R1, R4, R7, R11 _(P=1, I=3)_ - Risques liés aux tokens/credentials

Pistes pour réduire I à 2 :
1. Token lié au matériel (TPM/HSM) : Le token ne peut être utilisé que sur la machine qui l'a obtenu
2. Segmentation plus fine (déjà fait, mais possibilité de groups dynamiques)

# R8 _(P=1, I=3)_ - Fuite mémoire

Pistes pour réduire P (quasi-impossible) :
1. mlock() pour empêcher le swap des secrets
2. Intégration HSM/TPM pour ne jamais exposer le secret en mémoire utilisateur

---

# Risques SSH - Pistes d'Amélioration

## R-S1 _(P=1, I=4)_ - Authentification par mot de passe

**Déjà optimal** avec `PasswordAuthentication no`. Impact critique irréductible (accès complet si compromis).

Pistes supplémentaires :
1. Audit automatisé de la configuration sshd (compliance check)
2. Alerting si `PasswordAuthentication yes` détecté

## R-S4 _(P=1, I=4)_ - Compromission de la CA SSH

**Déjà optimal** avec CA sur HSM/air-gap. Impact critique irréductible.

Pistes supplémentaires :
1. CA intermédiaire (limiter l'exposition de la CA racine)
2. Rotation périodique de la CA avec période de transition
3. Monitoring des certificats émis (détection d'anomalies)

## R-S6 _(P=2, I=3)_ - Compromission du bastion (ZONE JAUNE)

**Problème** : Même avec PAM LLNG sur backends, le bastion reste un point critique.

Pistes pour réduire P à 1 :
1. **Bastion éphémère** : Recréer le bastion régulièrement (immutable infrastructure)
2. **Zero-trust** : Pas de shell sur le bastion, uniquement ProxyJump
3. **Durcissement CIS** : Benchmark automatisé + remediation
4. **EDR/monitoring renforcé** : Détection d'intrusion sur le bastion

Pistes pour réduire I à 2 :
1. **Segmentation fine** : Plusieurs bastions par zone de sécurité
2. **Session recording** : Enregistrement de toutes les sessions transitant par le bastion

## R-S8 _(P=2, I=2)_ - Session persistante après révocation (ZONE JAUNE)

**Problème** : Une session SSH établie survit à la révocation de l'utilisateur.

Pistes pour réduire P à 1 :
1. **Webhook de révocation** : LLNG notifie les serveurs pour tuer les sessions
2. **Agent PAM actif** : Vérification périodique de l'autorisation (toutes les N minutes)
3. **Session courte forcée** : `TMOUT` + `ClientAliveInterval` agressifs

**Implémentation possible (côté PAM) :**
```c
// Vérification périodique dans un thread ou via cron
// Si utilisateur révoqué → envoyer SIGHUP au processus sshd de l'utilisateur
```

## R-S3, R-S5, R-S7 _(P=1, I=2-3)_ - Risques maîtrisés

Ces risques sont déjà en zone verte avec les remédiations actuelles :
- **R-S3** : Certificats courte durée + révocation LLNG
- **R-S5** : Restriction réseau backends → bastion uniquement
- **R-S7** : LLNG HA + cache offline PAM
