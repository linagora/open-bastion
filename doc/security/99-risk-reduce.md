# Pistes d'Amélioration - Mode E (Sécurité Maximale)

## Matrice des Risques Résiduels (Mode E)

| Impact ↓ / Probabilité → | 1 - Très improbable                                         | 2 - Peu probable | 3 - Probable | 4 - Très probable |
| ------------------------ | ----------------------------------------------------------- | ---------------- | ------------ | ----------------- |
| **4 - Critique**         | R-S4, R-SA2                                                 | R-SA1            |              |                   |
| **3 - Important**        | R5, R-S5, R-S11, R-S23                                      | R-S6             |              |                   |
| **2 - Limité**           | R-S7, R-S9, R-S10, R-S12, R-S16, R-S17, R-S20, R-S21, R-S22 | R6, R-S8         |              |                   |
| **1 - Négligeable**      | R0, R13, R-S14, R-S15, R-S19                                | R-S3, R-S18      |              |                   |

> **Note :** R-S3 et R-S15 ont été descendus d'un cran sur l'axe Impact grâce au **binding fingerprint SSH** introduit dans le plugin PamAccess ≥ 0.1.16. La vérification est effectuée côté LLNG à la fois sur `/pam/authorize` (à chaque ouverture de session SSH, phase PAM `account`) et sur `/pam/verify` (à chaque utilisation d'un token PAM pour sudo ou ré-authentification) : tant que l'empreinte de la clef SSH n'est pas présente, active et non révoquée dans la session persistante LLNG, ni la session SSH ni l'escalade sudo ne sont autorisées, indépendamment de la fraîcheur de la KRL locale. Voir [02-ssh-connection.md](02-ssh-connection.md) pour les détails.

> **Note (R-S18, R-S19, R-S20, R-S21) :** Les scores résiduels indiqués ci-dessus pour R-S19, R-S20 et R-S21 supposent l'activation **simultanée** du hardening (PR1 #112, `--enable-hardening`) et de la trace auditd (PR2 #113, `--enable-audit-trace`). En l'absence d'activation, R-S19 reste à (P=3, I=3), R-S20 et R-S21 restent à (P=2, I=3) — tous trois en zone jaune. Voir [doc/hardening.md](../hardening.md) et [doc/audit.md](../audit.md) (documentations techniques en anglais) pour les détails opérationnels.

**Zones de risque :**

- Score ≥ 6 : Zone rouge (aucun risque dans cette zone en Mode E avec PR1 + PR2 activées)
- Score 4-5 : Zone jaune → R-S4, R-SA2 (P=1, I=4), R-SA1 (P=2, I=4/3), R6, R-S8 (P=2, I=2), R-S6 (P=2, I=3)
- Score ≤ 3 : Zone verte → Tous les autres risques (incluant R-S18 à P=2, I=1 = score 2)

**Risques éliminés ou ramenés en zone verte par le Mode E (avec PR1 et PR2 activées) :**

- **R-S1** : Supprimé (aucun mot de passe SSH accepté)
- **R-S2** : Descendu à I=1 (clé SSH inutile sans certificat CA)
- **R-S18** : Descendu à (P=1, I=1). Le recording est désormais streamé vers un **puits root activé par socket** (`ob-record-sink`, PR #157) : les fichiers sont root-owned (`root:ob-sessions 0640`) dans une arborescence `0750` où l'utilisateur enregistré n'a aucun accès — la suppression/altération par le non-sudo est **techniquement impossible**. L'enregistreur étant sur le **bastion**, être root sur un backend n'y échappe pas. Le résiduel P=1 couvre seulement root **du bastion** (hôte d'audit, hors périmètre). Le wrapper setgid est supprimé. Voir [section R-S18 ci-dessous](#r-s18-p1-i1---effacement-des-enregistrements-de-session).
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
2. **Shell restreint** : Forcer `ob-ssh` comme unique commande autorisée sur le bastion (`ForceCommand` ou shell restreint)
3. **Durcissement CIS** : Benchmark automatisé + remediation
4. **EDR/monitoring renforcé** : Détection d'intrusion sur le bastion

Pistes pour réduire I à 2 :

1. **Segmentation par zone (credentials d'enrôlement)** : par défaut un `client_id` = un **projet** (toutes ses machines partagent l'allowlist, et les groupes PAM séparent les _politiques_ à l'intérieur du projet — pas les _credentials_). Pour réduire le rayon d'impact d'un bastion compromis, **découper en plusieurs `client_id`** (un par zone de sécurité), chacun avec un `allowed_bastions` distinct par backend → un bastion compromis ne peut voucher que pour les backends de sa zone. C'est un arbitrage : plus d'isolation des credentials, mais autant de RP OIDC à gérer.
2. **Session recording** : Enregistrement de toutes les sessions transitant par le bastion
3. **Réduire `pamAccessBastionVoucherTtl`** (défaut 43200 s = 12 h) : borne la durée pendant laquelle un bastion compromis peut continuer à obtenir des certificats pour les utilisateurs récemment vouchés sans nouvelle connexion de leur part. Compromis ergonomie (les admins doivent se reconnecter plus souvent) vs exposition.

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

## Pistes d'Amélioration - Vouching par certificat (Bastion→Backend)

> Le transport `LLNG_BASTION_JWT` via `SendEnv`/`AcceptEnv` (anciens R-S9 « replay JWT » et R-S10 « rotation JWKS ») a été **remplacé** par le vouching par certificat éphémère : un voucher `(bastion_id, user)` émis par `/pam/authorize`, transporté localement via `pam_putenv`, échangé par `ob-ssh` (via `ob-cert-request`/`ob-cert-daemon` socket-activé, pas de sudoers) contre un certificat ~120 s signé par la CA `ssh-ca` (`/pam/bastion-cert`), épinglé à l'IP du bastion par `source-address`. Voir [02-ssh-connection.md](02-ssh-connection.md) et [doc/design/bastion-cert-vouching.md](../design/bastion-cert-vouching.md).

### R-S9 _(P=1, I=2)_ - Interception ou vol du certificat éphémère bastion

Pistes supplémentaires (non implémentées) :

1. **Réduire `pamAccessBastionCertTtl`** (défaut 120 s → 30-60 s) pour les zones les plus sensibles : raccourcit encore la fenêtre d'exploitation d'un certificat volé dans le tmpfs.
2. **Émission KRL pour les certificats éphémères** : aujourd'hui leur TTL très court remplace la révocation ; en cas de besoin de révocation immédiate sub-120 s, pousser le serial sur la KRL des backends (utile uniquement en réponse à incident).

### R-S10 _(P=1, I=1)_ - Voucher expiré ou rotation/compromission de la CA `ssh-ca`

Pistes supplémentaires (optionnelles) :

1. **Push de notification rotation CA** : lors d'une rotation (ou compromission) de la CA `ssh-ca`, LLNG notifie les backends via webhook pour rafraîchir `TrustedUserCAKeys` immédiatement, au lieu d'attendre le redéploiement.
2. **Monitoring de fraîcheur de `TrustedUserCAKeys`** : alerter si l'empreinte de la CA déployée sur un backend diverge de la CA active côté LLNG.

### R-S22 _(P=1, I=2)_ - Certificat vouché réutilisé vers un autre backend

Le key-id porte `target=<hôte>` mais `ob-ssh-principals` ne vérifie que `bastion=<id>` et `user=<u>`. Pistes (non implémentées) pour épingler le certificat à son backend :

1. **Vérification de `target=` dans `ob-ssh-principals`** : comparer `target=<hôte>` au FQDN local (`hostname -f` ou le token sshd `%h`) et refuser le principal si divergence. C'est la mitigation directe ; coût : robustesse du matching FQDN (alias, CNAME, IP vs nom) à valider.
2. **`target` côté LLNG dans `source-address`** : impossible (source-address épingle l'origine, pas la destination) — c'est bien `ob-ssh-principals` qui doit porter ce contrôle.

### R-S23 _(P=1, I=3)_ - Backend en mode hérité fail-open

`ob-backend-setup` écrit toujours le fichier et `ob-ssh-principals` est fail-closed si le fichier est présent mais illisible. Le résidu ne concerne qu'un backend jamais passé par le setup. Pistes (non implémentées) pour fermer ce mode :

1. **Fichier vide par défaut (postinst)** : faire écrire `/etc/open-bastion/allowed_bastions` vide par le paquet à l'installation, pour que l'« absent » n'arrive jamais (vide = « tout bastion vouché », ce qui reste contraignant : un cert SSO direct sans `bastion=` est refusé).
2. **Mode strict** : option (`ob-backend-setup --strict-vouching` ou clé de conf) où l'absence du fichier = **refus** au lieu du mode hérité, à activer sur les déploiements neufs sans backend legacy.

---

## Pistes d'Amélioration - Cycle de vie des tokens (heartbeat)

### Supervision du rafraîchissement (suite au fix #121)

Le timer `ob-heartbeat` rafraîchit l'access_token (TTL 3600 s) toutes les 5 min ; un échec silencieux du timer fait expirer le token (NSS + `/pam/authorize` cassés ~1 h après — c'était le cas avant #121 à cause du sandbox `ProtectSystem=strict` rendant le token en lecture seule). Pistes (non implémentées) pour détecter une régression future :

1. **Alerte sur échec de `ob-heartbeat.service`** : `OnFailure=` systemd → notification (mail/webhook/SIEM) dès qu'un run du timer échoue, plutôt que de découvrir l'expiration par la perte d'accès.
2. **Monitoring de l'âge du token** : exporter `expires_at - now` (node_exporter textfile, ou un check Nagios/Prometheus) et alerter quand il descend sous ~2× l'intervalle du timer.
3. **Test d'intégration sur fenêtre > TTL** : ajouter un test (CI longue ou lab) qui vérifie le rafraîchissement **via le chemin du timer** (`systemctl start ob-heartbeat.service`, donc avec le sandbox) sur une fenêtre dépassant 3600 s — un `sudo ob-heartbeat` manuel masque les régressions du sandbox. Recoupe R-S17 (lockout).

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

**Séparation des privilèges implémentée (enregistrement de session) :** le recording est streamé vers le puits root `ob-record-sink` (socket-activé, utilisateur dérivé de `SO_PEERCRED`), qui écrit des fichiers **root-owned** (`root:ob-sessions 0640`) dans une arborescence `root:ob-sessions 0750`. L'utilisateur enregistré n'a **aucun** accès (lister/lire/supprimer/tronquer), y compris sur ses propres enregistrements. L'enregistreur vivant sur le **bastion** (point de passage), être root sur un backend n'y échappe pas. Voir R-S18 ci-dessous.

### R-S18 _(P=1, I=1)_ - Effacement des enregistrements de session

**Score initial :** P=2, I=3 (zone jaune). Dans l'ancien modèle, le recorder
tournait sous l'uid de l'utilisateur et écrivait dans son propre sous-répertoire
`2770 user:ob-sessions` : il en était propriétaire et pouvait donc supprimer ou
tronquer ses propres enregistrements via `rm` / `: > fichier`.

**Cadre (important) — où se fait l'enregistrement :** l'enregistreur vit sur le
**bastion**, le point de passage obligé. Une session vers un backend transite
par le pty du bastion, donc **être root sur un backend ne permet pas d'échapper
à l'enregistrement ni d'atteindre les fichiers** : ils sont sur le bastion,
root-owned, et un root de backend n'a aucun accès au système de fichiers du
bastion. Le seul acteur capable d'altérer les traces est **root sur le bastion
lui-même** (l'hôte d'audit), un ensemble réduit et de confiance — voir le modèle
de menace ci-dessous.

**Remédiation implémentée (PR #157, `ob-record-sink`) :** le recording est
désormais **streamé vers un puits root activé par socket** (design retenu
[doc/design/tamper-evident-session-recording.md](../design/tamper-evident-session-recording.md)),
qui correspond exactement à l'option « démon collecteur privilégié » listée
auparavant comme non-retenue :

- Le recorder (sous l'uid utilisateur) n'écrit plus aucun fichier. Il ouvre une
  socket Unix via `ob-record-connect` et y streame le typescript ; `ob-record-sink`
  (root, socket-activé) écrit les fichiers.
- L'utilisateur enregistré est dérivé de `SO_PEERCRED` (vérifié par le noyau,
  jamais de l'en-tête) → pas d'usurpation ni de traversée de chemin.
- Les fichiers sont **root:ob-sessions 0640** dans une arborescence
  `root:ob-sessions 0750` ; l'utilisateur enregistré n'étant **pas** membre de
  `ob-sessions`, il n'a **aucun** droit (lister/lire/`unlink`/tronquer) sur ses
  enregistrements. C'est une frontière d'uid noyau (DAC), la plus robuste.
- **Fail-closed** : si le puits est indisponible, la session est refusée plutôt
  que de retomber sur un fichier user-owned (cf. §9 du design).
- Le wrapper setgid `ob-session-recorder-wrapper` (et son bit setgid) est
  **supprimé** : devenu inutile, il créait justement le sous-répertoire
  user-owned à l'origine du risque.

**Défenses complémentaires conservées :**

- Syslog (`auth.info`) : journal d'audit indépendant (start/end de session).
- Watch auditd `-w /var/lib/open-bastion/sessions/ -p wa` (PR2 #113, opt-in via
  `--enable-audit-trace`).

**Score résiduel :** P=1, I=1. La suppression/altération par l'utilisateur
non-sudo est désormais **techniquement impossible** (il ne possède pas les
fichiers et ne peut pas traverser l'arborescence). Le résiduel P=1 (et non 0)
couvre uniquement **root sur le bastion**, hors périmètre du modèle de menace.

**Modèle de menace :** root sur le bastion est de confiance ; on ne défend que
contre l'utilisateur non privilégié (y compris s'il est root sur un backend).
Se défendre contre root **du bastion** exigerait une expédition distante (WORM),
une signature, ou un média append-only.

Pistes pour réduire encore I (couvrir root du bastion, déjà hors périmètre) :

1. **Centralisation syslog / streaming WORM** : pousser logs et recordings vers
   un serveur distant (SIEM / endpoint LLNG WORM) pour résister à une
   compromission root du bastion. Roadmap dans
   [doc/session-recording.md](../session-recording.md).
2. **Signature des sessions** : signer cryptographiquement les fichiers à la
   clôture (clé privée hors du bastion) pour détecter toute altération a
   posteriori.

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
