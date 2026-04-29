# Pistes d'Amélioration - Mode E (Sécurité Maximale)

## Matrice des Risques Résiduels (Mode E)

| Impact ↓ / Probabilité → | 1 - Très improbable                          | 2 - Peu probable | 3 - Probable | 4 - Très probable |
| ------------------------ | -------------------------------------------- | ---------------- | ------------ | ----------------- |
| **4 - Critique**         | R-S4, R-SA2                                  | R-SA1            |              |                   |
| **3 - Important**        | R5, R-S5, R-S11                              | R-S6             |              |                   |
| **2 - Limité**           | R-S7, R-S9, R-S10, R-S12, R-S16, R-S17, R-S20, R-S21 | R6, R-S8         |              |                   |
| **1 - Négligeable**      | R0, R13, R-S14, R-S15, R-S19                 | R-S3, R-S18      |              |                   |

> **Note :** R-S3 et R-S15 ont été descendus d'un cran sur l'axe Impact grâce au **binding fingerprint SSH** introduit dans le plugin PamAccess ≥ 0.1.16. La vérification est effectuée côté LLNG à la fois sur `/pam/authorize` (à chaque ouverture de session SSH, phase PAM `account`) et sur `/pam/verify` (à chaque utilisation d'un token PAM pour sudo ou ré-authentification) : tant que l'empreinte de la clef SSH n'est pas présente, active et non révoquée dans la session persistante LLNG, ni la session SSH ni l'escalade sudo ne sont autorisées, indépendamment de la fraîcheur de la KRL locale. Voir [02-ssh-connection.md](02-ssh-connection.md) pour les détails.

> **Note (R-S18, R-S19, R-S20, R-S21) :** Les scores résiduels indiqués ci-dessus pour R-S19, R-S20 et R-S21 supposent l'activation **simultanée** du hardening (PR1 #112, `--enable-hardening`) et de la trace auditd (PR2 #113, `--enable-audit-trace`). En l'absence d'activation, R-S19 reste à (P=3, I=3), R-S20 et R-S21 restent à (P=2, I=3) — tous trois en zone jaune. Voir [doc/hardening.md](../hardening.md) et [doc/audit.md](../audit.md) (documentations techniques en anglais) pour les détails opérationnels.

**Zones de risque :**

- Score ≥ 6 : Zone rouge (aucun risque dans cette zone en Mode E avec PR1 + PR2 activées)
- Score 4-5 : Zone jaune → R-S4, R-SA2 (P=1, I=4), R-SA1 (P=2, I=4/3), R6, R-S8 (P=2, I=2), R-S6 (P=2, I=3)
- Score ≤ 3 : Zone verte → Tous les autres risques (incluant R-S18 à P=2, I=1 = score 2)

**Risques éliminés ou ramenés en zone verte par le Mode E (avec PR1 et PR2 activées) :**

- **R-S1** : Supprimé (aucun mot de passe SSH accepté)
- **R-S2** : Descendu à I=1 (clé SSH inutile sans certificat CA)
- **R-S18** : Reste à (P=2, I=1). Le wrapper setgid empêche l'accès aux recordings d'autres utilisateurs, mais l'utilisateur est propriétaire de son propre sous-répertoire `2770 user:ob-sessions` et peut donc supprimer ses propres recordings. La traçabilité est préservée par syslog `auth.info` (start/end de session, journal indépendant root-only) et, si PR2 (#113) est activée, par le watch auditd `-w /var/lib/open-bastion/sessions/` qui trace l'événement d'effacement même s'il réussit. Pistes pour passer à I=1 (ou à P=1 sans setuid) : voir [section R-S18 ci-dessous](#r-s18-p2-i1-résiduel---effacement-des-recordings).
- **R-S19** : Descendu à (P=1, I=1) grâce à `KillUserProcesses=yes` (le cgroup utilisateur est tué à la fin de la session, y compris les processus détachés via `setsid`) et au pre-flight refusant `Linger=yes`.
- **R-S20** : Descendu à (P=1, I=2) grâce à `at.allow` vide + `atd` masqué + `cron.allow` root-only + pre-flight `Linger=yes`. Limite résiduelle (I=2) : crontab pré-existant non purgé.
- **R-S21** : Descendu à (P=1, I=2) grâce aux règles auditd `-S execve -S execveat` + watches sur les fichiers sensibles + `connect()`. Limite résiduelle (I=2) : `sendto`/`sendmsg` UDP non-connectés non tracés par défaut.

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

### R-S18 _(P=2, I=1)_ - Effacement des enregistrements de session

**Score initial :** P=2, I=3 (zone jaune). Le wrapper setgid empêche déjà l'accès aux recordings d'**autres** utilisateurs ; en revanche, l'utilisateur reste propriétaire de son propre sous-répertoire `2770 user:ob-sessions` et peut supprimer ses propres recordings via `rm`.

**Remédiation implémentée :**

- Wrapper setgid `ob-session-recorder-wrapper` (groupe `ob-sessions`, mode `2755`) : isolation latérale entre utilisateurs (un utilisateur ne peut pas lire ni supprimer les recordings d'un autre)
- Répertoire sessions `/var/lib/open-bastion/sessions` en mode `1770 root:ob-sessions` (sticky bit) : protège uniquement le sous-répertoire utilisateur lui-même contre la suppression, pas les fichiers à l'intérieur
- Sous-répertoires utilisateur en mode `2770 user:ob-sessions` (bit setgid pour héritage du groupe)
- Le wrapper drop explicitement le gid élevé via `setregid()` après création du sous-répertoire et avant exec du script (`exec` ne supprime pas un gid effectif/sauvé déjà acquis)
- Sanitisation de l'environnement (LD_PRELOAD, BASH_ENV, PATH durci) avant exec
- Syslog (`auth.info`) comme journal d'audit indépendant et inaltérable : préserve start/end de session même si l'utilisateur supprime ses recordings
- Watch auditd `-w /var/lib/open-bastion/sessions/ -p wa` (PR2 #113, opt-in via `--enable-audit-trace`) : trace `unlink`, `truncate`, `rename` même si l'effacement réussit

**Score résiduel :** P=2, I=1. L'utilisateur peut techniquement supprimer ses propres recordings, mais l'imputation tient grâce à syslog (timeline) et à auditd (événement d'effacement).

Pistes pour passer à P=1 (sans setuid, contrainte projet) :

1. **Démon collecteur de session privilégié** : remplacer le pty recording local par un démon `ob-session-collector` qui reçoit le flux pty via socket Unix (`SO_PEERCRED`) et écrit dans des fichiers root-owned. L'utilisateur n'a aucune permission sur les fichiers résultants. Détecte la fermeture brutale du recorder via RST socket et marque la session comme `killed_prematurely` côté serveur. Architecture la plus robuste mais coûteuse à déployer/maintenir (nouveau service permanent + canal IPC privilégié).
2. **`chattr +a` (append-only)** : nécessite `CAP_LINUX_IMMUTABLE`, qui n'est pas accordé sans setuid ou file capabilities. Compatible avec la contrainte projet si on accepte les **file capabilities** (`setcap cap_linux_immutable+ep`) plutôt que le setuid root traditionnel.
3. **Forwarding immédiat vers LLNG** : pousser le recording en streaming vers un endpoint LLNG WORM (Write Once Read Many) côté serveur. Roadmap déjà mentionnée dans [doc/session-recording.md](../session-recording.md).

Pistes pour réduire I (déjà à 1, marges d'amélioration limitées) :

1. **Centralisation syslog** : Envoyer les logs vers un serveur distant (SIEM) pour résister à une compromission root du bastion
2. **Signature des sessions** : Signer cryptographiquement les fichiers de session à la clôture (clé privée hors du bastion) pour détecter toute altération a posteriori

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

---

## Pistes d'Amélioration - Containment et Traçabilité

Cette section couvre les nouveaux risques R-S19, R-S20, R-S21 introduits par l'analyse approfondie de l'enregistreur de session. Voir [02-ssh-connection.md](02-ssh-connection.md) pour les fiches complètes.

### R-S19 _(P=1, I=1 si PR1 + PR2 activées, sinon P=3, I=3)_ - Évasion du containment

Pistes pour aller plus loin :

1. **Démon collecteur de session privilégié** : remplacer le pty recording local par un démon `ob-session-collector` qui reçoit le flux pty via socket Unix (`SO_PEERCRED`) et écrit dans des fichiers root-owned. Détecte la fermeture brutale du recorder via RST socket et marque la session comme `killed_prematurely` côté serveur. Architecture déjà décrite dans le brainstorm initial mais non retenue à ce stade pour éviter d'introduire un nouveau service permanent.
2. **Mandatory Access Control** : profil AppArmor / SELinux qui interdit `setsid` aux shells utilisateurs (rompre le canal d'évasion à la racine). Coût opérationnel élevé (rédaction et maintenance du profil par distribution) mais blocage fort.
3. **`KillUserProcesses=yes` rendu obligatoire** : retirer l'opt-in et l'imposer en postinst. Abandonné à cause de la philosophie Debian (pas de modification système globale silencieuse). Pourrait être réintroduit comme paquet `open-bastion-strict` dédié, qui imposerait le hardening sans demande de confirmation.

### R-S20 _(P=1, I=2 si PR1 activée, sinon P=2, I=3)_ - Action différée

Pistes pour réduire I à 1 :

1. **Purge des crontabs pré-existants** : à l'activation de `--enable-hardening`, itérer `/var/spool/cron/crontabs/` et supprimer (avec backup horodaté dans `/var/lib/open-bastion/setup-backups/cron/`) les crontabs des utilisateurs hors `cron.allow`. Documenté comme limite résiduelle dans [02-ssh-connection.md](02-ssh-connection.md). Cette opération doit être idempotente et journalisée pour permettre la restauration si le hardening est désactivé.
2. **Surveillance des systemd timers utilisateurs** : auditer périodiquement `loginctl list-users` et alerter sur tout `Linger=yes` qui apparaîtrait après l'activation initiale du hardening (un administrateur pourrait l'activer manuellement par la suite).
3. **`pam_listfile` sur `crontab` et `at`** : double sécurité au niveau PAM en plus des allow-lists, pour les distributions où `cron.allow` ne serait pas honoré (rare en pratique sur Debian).

### R-S21 _(P=1, I=2 si PR2 activée, sinon P=2, I=3)_ - Action non capturée

Pistes pour réduire I à 1 :

1. **Forwarding remote-syslog des logs auditd** : `audisp-syslog` ou `audisp-remote` poussent les événements auditd vers un collecteur central (rsyslog, journald-remote, SIEM). Préserve la trace même en cas de compromission root du bastion. **Recommandation prioritaire** sur tout déploiement réel : sans collecteur distant, un attaquant root local peut effacer `/var/log/audit/` après ses méfaits.
2. **Étendre les règles auditd** : ajouter `-S sendto -S sendmsg` (volumétrie acceptée pour bastion à faible trafic), `-S io_uring_enter` (rare en pratique), puis activer `-e 2` (locked rules) en production pour empêcher `auditctl -D` à chaud par un attaquant qui aurait obtenu root.
3. **eBPF-based tracing** (Falco, sysdig) : alternative ou complément à auditd qui couvre des événements moins accessibles via syscalls (par ex. opérations sur file descriptors mémoire, écritures `pwrite` sur sockets). Plus coûteux en CPU mais plus expressif.
4. **Signature cryptographique du recording à la clôture** : `gpg --detach-sign` ou similaire avec clé privée hors du bastion (HSM ou serveur de signature distant), pour détecter toute altération a posteriori. Complète R-S18 plutôt que R-S21 stricto sensu, mais participe à la même propriété d'intégrité.
