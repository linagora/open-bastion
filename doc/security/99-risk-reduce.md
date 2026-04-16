# Pistes d'Amélioration - Mode E (Sécurité Maximale)

## Matrice des Risques Résiduels (Mode E)

| Impact ↓ / Probabilité → | 1 - Très improbable                                 | 2 - Peu probable | 3 - Probable | 4 - Très probable |
| ------------------------ | --------------------------------------------------- | ---------------- | ------------ | ----------------- |
| **4 - Critique**         | R-S4, R-SA2                                         | R-SA1            |              |                   |
| **3 - Important**        | R5, R-S5, R-S11                                     | R-S6             |              |                   |
| **2 - Limité**           | R-S3, R-S7, R-S9, R-S10, R-S12, R-S15, R-S16, R-S17 | R6, R-S8         |              |                   |
| **1 - Négligeable**      | R0, R13, R-S14, R-S18                               |                  |              |                   |

**Zones de risque :**

- Score ≥ 6 : Zone rouge (aucun risque dans cette zone en Mode E)
- Score 4-5 : Zone jaune → R-S4, R-SA2 (P=1, I=4), R-SA1 (P=2, I=4/3), R6, R-S8 (P=2, I=2), R-S6 (P=2, I=3)
- Score ≤ 3 : Zone verte → Tous les autres risques

**Risques éliminés par le Mode E :**

- **R-S1** : Supprimé (aucun mot de passe SSH accepté)
- **R-S2** : Descendu à I=1 (clé SSH inutile sans certificat CA)
- **R-S18** : Descendu à P=1/I=1 (wrapper setgid + sticky bit empêchent l'effacement des sessions)

Voir [01-enrollment.md](01-enrollment.md) et [02-ssh-connection.md](02-ssh-connection.md) pour les détails des risques et remédiations.

Voir [03-offboarding.md](03-offboarding.md) pour la procédure de révocation des accès administrateurs.

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

### R-S4 _(P=1, I=4)_ - Compromission de la CA SSH

Pistes supplémentaires :

1. CA intermédiaire (limiter l'exposition de la CA racine)
2. Rotation périodique de la CA avec période de transition
3. Monitoring des certificats émis (détection d'anomalies)

### R-S6 _(P=2, I=3)_ - Compromission du bastion

Pistes pour réduire P à 1 :

1. **Bastion éphémère** : Recréer le bastion régulièrement (immutable infrastructure)
2. **Shell restreint** : Forcer `ob-ssh-proxy` comme unique commande autorisée sur le bastion (`ForceCommand` ou shell restreint)
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

### R-S9 _(P=1, I=2)_ - Replay JWT bastion

Pistes supplémentaires (non implémentées) :

1. **Vérification stricte IP** : Rejeter si `bastion_ip` != IP source SSH
2. **Nonce challenge** : Le backend génère un nonce (complexifie le protocole)

### R-S10 _(P=1, I=1)_ - Rotation JWKS non propagée

Piste supplémentaire (optionnelle) :

1. **Push de notification** : LLNG notifie les backends via webhook pour refresh immédiat (utile uniquement en cas de compromission)

---

## Pistes d'Amélioration - Spécifiques au Mode E

### R-S15 _(P=1, I=2)_ - KRL non à jour

Pistes pour réduire P à quasi-zéro :

1. **Monitoring actif** : Alerte si le fichier KRL a plus d'1h sans mise à jour
2. **Push de notification** : LLNG notifie les serveurs via webhook lors d'une révocation
3. **Réduction de l'intervalle cron** : Passer de 30 min à 5-10 min pour les environnements critiques

### R-S16 _(P=1, I=2)_ - Escalade sudo

Le Mode E bloque l'escalade par conception (réauthentification SSO obligatoire). Pistes supplémentaires :

1. **2FA obligatoire** : Exiger un second facteur pour l'obtention du token sudo
2. **Durée de token réduite** : Limiter la validité du token PAM-access à 5 minutes pour les opérations sudo
3. **Audit renforcé** : Logger chaque utilisation de sudo avec le token ID pour traçabilité

**Séparation des privilèges déjà implémentée (enregistrement de session) :** Le wrapper setgid `ob-session-recorder-wrapper` et les permissions `1770` sur `/var/lib/open-bastion/sessions` empêchent les utilisateurs de supprimer leurs enregistrements de session, réduisant le risque de falsification de preuves en cas de compromission.

### R-S18 _(P=1, I=1)_ - Effacement des enregistrements de session

**Score initial :** P=3, I=3 (zone jaune). Sans protection, tout utilisateur peut supprimer ses propres enregistrements de session.

**Remédiation implémentée :**

- Wrapper setgid `ob-session-recorder-wrapper` (groupe `ob-sessions`, mode `2755`)
- Répertoire sessions `/var/lib/open-bastion/sessions` en mode `1770 root:ob-sessions` (sticky bit)
- `setregid()` dans le wrapper pour persister le gid à travers l'exec du script bash
- Syslog (`auth.info`) comme journal d'audit indépendant et inaltérable

**Score résiduel :** P=1, I=1 (zone verte). L'utilisateur ne peut ni accéder ni supprimer les fichiers de session. Syslog préserve les traces minimales même en cas de compromission root.

Pistes supplémentaires :

1. **Centralisation syslog** : Envoyer les logs vers un serveur distant (SIEM) pour résister à une compromission root
2. **Attribut append-only** : `chattr +a` sur les fichiers de session (nécessite CAP_LINUX_IMMUTABLE, donc un mécanisme setuid dédié)
3. **Signature des sessions** : Signer cryptographiquement les fichiers de session à la clôture pour détecter toute altération

### R-S17 _(P=1, I=2)_ - Verrouillage total (lockout)

Avant remédiation, ce risque est en **zone rouge** (P=2, I=4). La remédiation le ramène à P=1/I=2 via :

- Compte de service de secours (`service-accounts.conf`) avec clé stockée en coffre-fort — **pré-configuré par le paquet `open-bastion-linagora`** (compte `linagora`, clé RSA, `sudo_allowed = true`)
- Procédure de recouvrement console documentée et testée — **accès root via ttyS0 pré-configuré** dans `/etc/securetty` par le paquet bootstrap (`PermitRootLogin no` bloque SSH, console OVH reste le filet de sécurité)
- LLNG en haute disponibilité

> **Note nscd :** Après toute modification de la configuration NSS (`/etc/nsswitch.conf`), redémarrer `nscd` (`systemctl restart nscd`) est obligatoire pour vider le cache négatif. Un cache négatif résiduel peut bloquer temporairement la résolution des utilisateurs du bastion même après configuration correcte.

Pistes pour réduire davantage :

1. **Test de recouvrement périodique** : Simuler un lockout (désactiver LLNG en environnement de test) et valider la procédure console + compte de service de secours au moins une fois par an
2. **Alerte proactive** : Monitorer l'âge du cache offline et alerter quand il atteint 80% du TTL configuré, avant l'expiration
3. **Cache offline étendu pour le compte de secours** : Configurer un TTL offline plus long spécifiquement pour le compte de service de recouvrement
4. **Runbook automatisé** : Script de recouvrement pré-positionné sur le serveur (accessible uniquement via console) pour réactiver l'accès en une commande
