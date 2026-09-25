Pistes d'Amélioration - Mode E (Sécurité Maximale)
==================================================

   **Ce document porte l'argumentaire technique des mesures, pas le plan.** Le plan de traitement — une mesure par ligne, avec porteur, priorité, échéance et état — est en :doc:`/security/07-plan-de-traitement`, et les décisions (périmètre, conditions d'emploi, acceptation des résiduels) en :doc:`/security/08-dossier-homologation`. Les sections « Pistes » ci-dessous expliquent **pourquoi** une mesure réduit un risque et ce qu'elle coûte ; le plan dit **qui** la porte et **quand**.

Matrice des Risques Résiduels (Mode E)
--------------------------------------

+--------------------------+----------------------------------------------------------------------------------------------+-----------------------------+--------------+-------------------+
| Impact ↓ / Probabilité → | 1 - Très improbable                                                                          | 2 - Peu probable            | 3 - Probable | 4 - Très probable |
+==========================+==============================================================================================+=============================+==============+===================+
| **4 - Critique**         | R4, R5, R-S4, R-SA2, R-P4                                                                    |                             |              |                   |
+--------------------------+----------------------------------------------------------------------------------------------+-----------------------------+--------------+-------------------+
| **3 - Important**        | R2, R3, R7, R8, R11, R12, R-S5, R-S11, R-S23, R-S24, R-P1, R-P2, R-P5                        | R1, R-S6, R-SA1, R-P3, R-P7 |              |                   |
+--------------------------+----------------------------------------------------------------------------------------------+-----------------------------+--------------+-------------------+
| **2 - Limité**           | R0, R9, R10, R-S7, R-S9, R-S12, R-S13, R-S14, R-S16, R-S17, R-S20, R-S21, R-S22, R-S25, R-P8 | R-S8, R-P6                  |              |                   |
+--------------------------+----------------------------------------------------------------------------------------------+-----------------------------+--------------+-------------------+
| **1 - Négligeable**      | R13, R-S10, R-S15, R-S18, R-S19                                                              | R6, R-S3                    |              |                   |
+--------------------------+----------------------------------------------------------------------------------------------+-----------------------------+--------------+-------------------+

..

   **Note :** R-S3 et R-S15 sont descendus de I=3 à I=1 grâce au **binding fingerprint SSH** introduit dans le plugin PamAccess ≥ 0.1.16. La vérification est effectuée côté LLNG à la fois sur ``/pam/authorize`` (à chaque ouverture de session SSH, phase PAM ``account``) et sur ``/pam/verify`` (à chaque utilisation d'un token PAM pour sudo ou ré-authentification) : tant que l'empreinte de la clef SSH n'est pas présente, active et non révoquée dans la session persistante LLNG, ni la session SSH ni l'escalade sudo ne sont autorisées, indépendamment de la fraîcheur de la KRL locale. Voir :doc:`/security/02-ssh-connection` pour les détails.

   **Note (condition d'emploi du binding fingerprint) :** la réduction ci-dessus suppose que l'empreinte parvienne effectivement à LLNG. Elle est récupérée par le module dans ``/run/open-bastion/ssh-fp``, alimenté par l'``AuthorizedPrincipalsCommand``. Si ce spool disparaît — dérive après mise à jour, entrée ``tmpfiles.d`` manquante — le module appelle ``/pam/authorize`` sans champ ``fingerprint``, que le plugin traite comme optionnel : la mesure disparaît silencieusement, et la durée de vie du voucher bastion n'est plus bornée par l'expiration du certificat SSO. Deux garde-fous depuis la 0.6.3 : l'absence du drop est journalisée en **WARN** (et non plus en DEBUG), et l'option ``fingerprint_required = true`` d'``openbastion.conf`` refuse la session plutôt que de l'autoriser sans binding. **Activer cette option sur les hôtes en mode certificat est une condition d'emploi du score résiduel R-S3 / R-S15** (ne pas l'activer sur les modes token, où il n'y a jamais d'empreinte).

   **Ce que change la montée de version du portail.** La PR amont ``linagora/lemonldap-ng-plugins#86`` (issue ``#55``) ajoute le pendant serveur de cette option : un voucher qu'aucune empreinte ne lie au certificat SSO est plafonné à ``pamAccessBastionVoucherUnboundTtl`` (900 s au lieu de 12 h), et ``pamAccessRequireFingerprint`` refuse carrément le cas non lié. Le mode de défaillance d'un spool absent cesse alors d'être un affaiblissement silencieux pour devenir une **coupure visible** : les rebonds ``ob-ssh`` échouent une quinzaine de minutes après la connexion au bastion, avec ``reason: voucher_expired``. C'est le comportement souhaitable, mais il faut le savoir avant la mise à jour — un spool cassé qui passait inaperçu se manifestera comme une panne. ``fingerprint_required = true`` fait échouer la connexion au bon endroit (à l'ouverture de session, avec un motif audité) plutôt que quinze minutes plus tard sur un rebond.

   **Ce que vaut le spool comme racine de confiance.** Depuis `#249 <https://github.com/linagora/open-bastion/issues/249>`__, le répertoire ``/run/open-bastion/ssh-fp`` est ``0700 root`` et c'est ``ob-fp-daemon``, activé par socket, qui écrit les drops. Le helper ``AuthorizedPrincipalsCommand`` — que ``sshd`` impose de faire tourner sous un compte non privilégié — se contente de déposer via ``ob-fp-submit``. **La racine de confiance n'est donc plus le compte ``nobody``** : celui-ci ne peut plus ni lire les empreintes déposées, ni en écrire.

   Ce que vérifie le démon, dans l'ordre : l'uid déposant vient de ``SO_PEERCRED`` (rempli par le noyau au ``connect(2)``, non forgeable) et doit être l'``AuthorizedPrincipalsCommandUser`` ; puis — et c'est le contrôle qui porte — **l'ancre ``sshd-session`` est dérivée de l'ascendance ``/proc`` du déposant, elle n'est jamais lue dans la requête**. Un client ne peut donc pas désigner la session pour laquelle il dépose : il faut déjà être un descendant de cette ancre, et l'ancre doit être un processus vivant dont l'uid **réel** est root (pas l'uid effectif : ``sshd`` le bascule sur l'utilisateur du helper pendant la commande de principals, #296). ``sshd`` ne place qu'une seule chose non privilégiée à cet endroit, le helper. Forger un binding suppose désormais une exécution de code sous le compte du helper *à l'intérieur de l'arbre de processus de la connexion visée* — strictement plus étroit que « exécution de code sous ``nobody`` n'importe où sur l'hôte ».

   Les durcissements de #235 restent en place et gardent leur utilité : l'uid réel de l'ancre (``/proc/<pid>/status``) doit être **root** (l'ancre est choisie par nom de processus, et ``prctl(PR_SET_NAME)`` accepte quinze caractères — « sshd-session » en fait douze), un drop plus ancien que son processus ancre est refusé (rien ne supprime un drop en fin de session, et le helper ne tourne pas pour une connexion par mot de passe : une réutilisation de PID faisait sinon hériter le binding de l'occupant précédent), et toute authentification de compte de service fondée sur une empreinte venue du spool plutôt que de ``sshd`` est journalisée en **WARN** et tracée dans l'audit.

   **Un hôte mis à jour sans rejouer ``ob-bastion-setup`` / ``ob-backend-setup`` conserve l'ancien répertoire ``0700 nobody`` et donc l'ancienne racine de confiance** — jusqu'au premier dépôt passé par ``ob-fp-daemon``, qui reprend le répertoire. Le module journalise explicitement ce cas (« spool is owned by uid N, not root »).

..

   **Note (R-S18, R-S19, R-S20, R-S21) :** Les scores résiduels indiqués ci-dessus pour R-S19, R-S20 et R-S21 supposent l'activation **simultanée** du hardening (PR1 #112, ``--enable-hardening``) et de la trace auditd (PR2 #113, ``--enable-audit-trace``). En l'absence d'activation, R-S19 reste à (P=3, I=3), R-S20 et R-S21 restent à (P=2, I=3) — tous trois en zone jaune. Voir :doc:`/hardening` et :doc:`/audit` (documentations techniques en anglais) pour les détails opérationnels.

   **Comment lire cette matrice.** Elle consolide les **47 fiches de risque** des trois volets de l'atelier 4 (R0–R13 pour l'enrôlement, R-S3–R-S25 et R-SA1/R-SA2 pour la connexion SSH et les comptes de service, R-P1–R-P8 pour le portail LLNG et ses plugins) et reprend, case par case, le score résiduel **écrit dans chaque fiche** — aucune case n'est une évaluation autonome. ``tests/ebios_matrix_check.py`` le vérifie mécaniquement et échoue si une case s'écarte de sa fiche, si un risque analysé manque, ou si un identifiant y figure sans fiche. R-S1 et R-S2 sont éliminés par la cible Mode E et n'ont donc pas de fiche.

**Zones de risque** — définition unique en :ref:`atelier 1, §1.5.1 <security-04-atelier1-cadrage-socle-151-zones-de-risque>` (score = Vraisemblance × Gravité) **:**

- **Rouge** (score ≥ 9) : aucun risque, en Mode E avec PR1 + PR2 activées
- **Orange** (score 6–8) : R1, R-S6, R-SA1, R-P3, R-P7 — les cinq risques qui requièrent une acceptation formelle, portée par :doc:`/security/08-dossier-homologation`
- **Jaune** (score 4–5) : R4, R5, R-S4, R-S8, R-SA2, R-P4, R-P6
- **Verte** (score ≤ 3) : les 35 autres, dont R6 et R-S3 (P=2, I=1 = 2)

**Risques éliminés ou ramenés en zone verte par le Mode E (avec PR1 et PR2 activées) :**

- **R-S1** : Supprimé (aucun mot de passe SSH accepté)
- **R-S2** : Descendu à I=1 (clé SSH inutile sans certificat CA)
- **R-S18** : Descendu à (P=1, I=1). Le recording est désormais streamé vers un **puits root activé par socket** (``ob-record-sink``, PR #157) : les fichiers sont root-owned (``root:ob-sessions 0640``) dans une arborescence ``0750`` où l'utilisateur enregistré n'a aucun accès — la suppression/altération par le non-sudo est **techniquement impossible**. L'enregistreur étant sur le **bastion**, être root sur un backend n'y échappe pas. Le résiduel P=1 couvre seulement root **du bastion** (hôte d'audit, hors périmètre). Le wrapper setgid est supprimé. Voir :ref:`section R-S18 ci-dessous <security-99-risk-reduce-r-s18-p1-i1---effacement-des-enregistrements-de-session>`.
- **R-S19** : Descendu à (P=1, I=1) grâce à ``KillUserProcesses=yes`` (le cgroup utilisateur est tué à la fin de la session, y compris les processus détachés via ``setsid``) et au pre-flight refusant ``Linger=yes``.
- **R-S20** : Descendu à (P=1, I=2) grâce à ``at.allow`` vide + ``atd`` masqué + ``cron.allow`` root-only + pre-flight ``Linger=yes``. Limite résiduelle (I=2) : crontab pré-existant non purgé.
- **R-S21** : Descendu à (P=1, I=2) grâce aux règles auditd ``-S execve -S execveat`` + watches sur les fichiers sensibles + ``connect()``. Limite résiduelle (I=2) : ``sendto``/``sendmsg`` UDP non-connectés non tracés par défaut.

Voir :doc:`/security/01-enrollment` et :doc:`/security/02-ssh-connection` pour les détails des risques et remédiations.

Voir :doc:`/security/03-offboarding` pour la procédure de révocation des accès administrateurs.

--------------

Pistes d'Amélioration - Enrôlement
----------------------------------

R5 *(P=1, I=4)* - Usurpation du serveur LLNG
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pistes pour réduire la probabilité à quasi-zéro :

1. Rendre le certificate pinning obligatoire (pas juste recommandé)
2. mTLS : Le serveur PAM présente aussi un certificat client
3. DANE (DNSSEC + TLSA) : Validation du certificat via DNS signé

R6 *(P=2, I=1)* - Expiration device_code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pistes pour réduire P à 1 :

1. Notification push quand l'admin approuve (l'opérateur sait que c'est bon)

R1, R4, R7, R11 - Risques liés aux tokens/credentials
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pistes pour réduire I à 1 :

1. Token lié au matériel (TPM/HSM) : Le token ne peut être utilisé que sur la machine qui l'a obtenu
2. Groupes dynamiques basés sur des attributs (département, projet)

R8 *(P=1, I=3)* - Fuite mémoire
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pistes pour réduire P :

1. mlock() pour empêcher le swap des secrets
2. Intégration HSM/TPM pour ne jamais exposer le secret en mémoire utilisateur

--------------

Pistes d'Amélioration - SSH
---------------------------

R-S4 *(P=1, I=4)* - Compromission de la CA SSH
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pistes supplémentaires :

1. CA intermédiaire (limiter l'exposition de la CA racine)
2. Rotation périodique de la CA avec période de transition
3. Monitoring des certificats émis (détection d'anomalies)

R-S6 *(P=2, I=3)* - Compromission du bastion
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pistes pour réduire P à 1 :

1. **Bastion éphémère** : Recréer le bastion régulièrement (immutable infrastructure)
2. **Shell restreint** : Forcer ``ob-ssh`` comme unique commande autorisée sur le bastion (``ForceCommand`` ou shell restreint)
3. **Durcissement CIS** : Benchmark automatisé + remediation
4. **EDR/monitoring renforcé** : Détection d'intrusion sur le bastion

Pistes pour réduire I à 2 :

1. **Segmentation par zone (credentials d'enrôlement)** : par défaut un ``client_id`` = un **projet** (toutes ses machines partagent l'allowlist, et les groupes PAM séparent les *politiques* à l'intérieur du projet — pas les *credentials*). Pour réduire le rayon d'impact d'un bastion compromis, **découper en plusieurs ``client_id``** (un par zone de sécurité), chacun avec un ``allowed_bastions`` distinct par backend → un bastion compromis ne peut voucher que pour les backends de sa zone. C'est un arbitrage : plus d'isolation des credentials, mais autant de RP OIDC à gérer.
2. [STRIKEOUT:Session recording] — **LIVRÉ et actif par défaut.** L'enregistrement de toutes les sessions transitant par le bastion n'est pas une piste : il est activé par défaut (``ob-bastion-setup`` : « Session recording is a core bastion guarantee and is ON by default »), le désactiver demande un ``--disable-session-recorder`` explicite, et il est **fail-closed** — si le puits est injoignable, ``ob-session-recorder`` refuse la session (« Session recording is required but unavailable; access refused »).
3. **Réduire ``pamAccessBastionVoucherTtl``** (défaut 43200 s = 12 h) : borne la durée pendant laquelle un bastion compromis peut continuer à obtenir des certificats pour les utilisateurs récemment vouchés sans nouvelle connexion de leur part. Compromis ergonomie (les admins doivent se reconnecter plus souvent) vs exposition.

R-S8 *(P=2, I=2)* - Session persistante après révocation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pistes pour réduire P à 1 :

1. **Webhook de révocation** : LLNG notifie les serveurs pour tuer les sessions
2. **Agent PAM actif** : Vérification périodique de l'autorisation (toutes les N minutes)
3. **Session courte forcée** : ``TMOUT`` + ``ClientAliveInterval`` agressifs

**Implémentation possible (côté PAM) :**

.. code:: c

   // Vérification périodique dans un thread ou via cron
   // Si utilisateur révoqué → envoyer SIGHUP au processus sshd de l'utilisateur

--------------

Pistes d'Amélioration - Vouching par certificat (Bastion→Backend)
-----------------------------------------------------------------

   Le transport ``LLNG_BASTION_JWT`` via ``SendEnv``/``AcceptEnv`` (anciens R-S9 « replay JWT » et R-S10 « rotation JWKS ») a été **remplacé** par le vouching par certificat éphémère : un voucher ``(bastion_id, user)`` émis par ``/pam/authorize``, transporté localement via ``pam_putenv``, échangé par ``ob-ssh`` (via ``ob-cert-request``/``ob-cert-daemon`` socket-activé, pas de sudoers) contre un certificat ~120 s signé par la CA ``ssh-ca`` (``/pam/bastion-cert``), épinglé à l'IP du bastion par ``source-address``. Voir :doc:`/security/02-ssh-connection` et :doc:`/design/bastion-cert-vouching`.

R-S9 *(P=1, I=2)* - Interception ou vol du certificat éphémère bastion
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pistes supplémentaires (non implémentées) :

1. **Réduire ``pamAccessBastionCertTtl``** (défaut 120 s → 30-60 s) pour les zones les plus sensibles : raccourcit encore la fenêtre d'exploitation d'un certificat volé dans le tmpfs.
2. **Émission KRL pour les certificats éphémères** : aujourd'hui leur TTL très court remplace la révocation ; en cas de besoin de révocation immédiate sub-120 s, pousser le serial sur la KRL des backends (utile uniquement en réponse à incident).

R-S10 *(P=1, I=1)* - Voucher expiré ou rotation/compromission de la CA ``ssh-ca``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pistes supplémentaires (optionnelles) :

1. **Push de notification rotation CA** : lors d'une rotation (ou compromission) de la CA ``ssh-ca``, LLNG notifie les backends via webhook pour rafraîchir ``TrustedUserCAKeys`` immédiatement, au lieu d'attendre le redéploiement.
2. **Monitoring de fraîcheur de ``TrustedUserCAKeys``** : alerter si l'empreinte de la CA déployée sur un backend diverge de la CA active côté LLNG.

.. _security-99-risk-reduce-r-s22-p1-i2---certificat-vouché-réutilisé-vers-un-autre-backend:

R-S22 *(P=1, I=2)* - Certificat vouché réutilisé vers un autre backend
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Le key-id porte ``target=<hôte>`` mais ``ob-ssh-principals`` ne vérifie que ``bastion=<id>`` et ``user=<u>``. Pistes (non implémentées) pour épingler le certificat à son backend :

1. **Vérification de ``target=`` dans ``ob-ssh-principals``** : comparer ``target=<hôte>`` au FQDN local (``hostname -f`` ou le token sshd ``%h``) et refuser le principal si divergence. C'est la mitigation directe ; coût : robustesse du matching FQDN (alias, CNAME, IP vs nom) à valider.
2. **``target`` côté LLNG dans ``source-address``** : impossible (source-address épingle l'origine, pas la destination) — c'est bien ``ob-ssh-principals`` qui doit porter ce contrôle.

.. _security-99-risk-reduce-r-s23-p1-i3---backend-en-mode-hérité-fail-open:

R-S23 *(P=1, I=3)* - Backend en mode hérité fail-open
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``ob-backend-setup`` écrit toujours le fichier et ``ob-ssh-principals`` est fail-closed si le fichier est présent mais illisible. Le résidu ne concerne qu'un backend jamais passé par le setup. Pistes (non implémentées) pour fermer ce mode :

1. **Fichier vide par défaut (postinst)** : faire écrire ``/etc/open-bastion/allowed_bastions`` vide par le paquet à l'installation, pour que l'« absent » n'arrive jamais (vide = « tout bastion vouché », ce qui reste contraignant : un cert SSO direct sans ``bastion=`` est refusé).
2. **Mode strict** : option (``ob-backend-setup --strict-vouching`` ou clé de conf) où l'absence du fichier = **refus** au lieu du mode hérité, à activer sur les déploiements neufs sans backend legacy.

--------------

Pistes d'Amélioration - Cycle de vie des tokens (heartbeat)
-----------------------------------------------------------

Supervision du rafraîchissement (suite au fix #121)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Le timer ``ob-heartbeat`` rafraîchit l'access_token (TTL 3600 s) toutes les 5 min ; un échec silencieux du timer fait expirer le token (NSS + ``/pam/authorize`` cassés ~1 h après — c'était le cas avant #121 à cause du sandbox ``ProtectSystem=strict`` rendant le token en lecture seule). Pistes (non implémentées) pour détecter une régression future :

1. **Alerte sur échec de ``ob-heartbeat.service``** : ``OnFailure=`` systemd → notification (mail/webhook/SIEM) dès qu'un run du timer échoue, plutôt que de découvrir l'expiration par la perte d'accès.
2. **Monitoring de l'âge du token** : exporter ``expires_at - now`` (node_exporter textfile, ou un check Nagios/Prometheus) et alerter quand il descend sous ~2× l'intervalle du timer.
3. **Test d'intégration sur fenêtre > TTL** : ajouter un test (CI longue ou lab) qui vérifie le rafraîchissement **via le chemin du timer** (``systemctl start ob-heartbeat.service``, donc avec le sandbox) sur une fenêtre dépassant 3600 s — un ``sudo ob-heartbeat`` manuel masque les régressions du sandbox. Recoupe R-S17 (lockout).

--------------

Pistes d'Amélioration - Spécifiques au Mode E
---------------------------------------------

R-S15 *(P=1, I=1)* - KRL non à jour
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pistes pour réduire P à quasi-zéro :

1. **Monitoring actif** : Alerte si ``ob-krl-refresh.service`` est en échec, ou si le fichier KRL n'a pas été confirmé depuis plus d'1h
2. **Push de notification** : LLNG notifie les serveurs via webhook lors d'une révocation
3. **Réduction de l'intervalle de rafraîchissement** : Passer de 30 min à 5-10 min pour les environnements critiques (``ob-bastion-setup --max-security --krl-refresh-interval 10``)

R-S16 *(P=1, I=2)* - Escalade sudo
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Le Mode E bloque l'escalade par conception (réauthentification SSO obligatoire). Pistes supplémentaires :

1. **2FA obligatoire** : Exiger un second facteur pour l'obtention du token sudo
2. **Durée de token réduite** : Limiter la validité du token PAM-access à 5 minutes pour les opérations sudo
3. **Audit renforcé** : Logger chaque utilisation de sudo avec le token ID pour traçabilité

**Précision sur la fraîcheur de la réauthentification :** ``sudo`` possède son propre cache d'identifiants (``timestamp_timeout``, 15 min par défaut sur Debian, réarmé à chaque usage). Tant qu'il est valide, ``sudo`` **saute entièrement la phase PAM ``auth``** : ``pam_openbastion`` n'est pas appelé et aucun token LLNG n'est demandé. Ce que cela n'affaiblit pas : le token est à usage unique et consommé côté portail, et la phase ``account`` — donc la vérification d'autorisation — s'exécute en direct à **chaque** ``sudo``, si bien qu'une révocation LLNG prend effet immédiatement. Ce que cela affaiblit : la revendication « chaque élévation est adossée à une authentification SSO *fraîche* ». L'option ``--enable-sudo-fresh-otp`` d'``ob-bastion-setup`` / ``ob-backend-setup`` écrit ``Defaults:%open-bastion-sudo timestamp_timeout=0`` et rétablit la revendication littérale ; elle reste **opt-in** parce qu'elle change la cadence des invites pour tous les utilisateurs SSO. Voir :ref:`pam-modes-how-often-you-are-actually-prompted-sudos-timestamp-cache`.

**Séparation des privilèges implémentée (enregistrement de session) :** le recording est streamé vers le puits root ``ob-record-sink`` (socket-activé, utilisateur dérivé de ``SO_PEERCRED``), qui écrit des fichiers **root-owned** (``root:ob-sessions 0640``) dans une arborescence ``root:ob-sessions 0750``. L'utilisateur enregistré n'a **aucun** accès (lister/lire/supprimer/tronquer), y compris sur ses propres enregistrements. L'enregistreur vivant sur le **bastion** (point de passage), être root sur un backend n'y échappe pas. Voir R-S18 ci-dessous.

.. _security-99-risk-reduce-r-s18-p1-i1---effacement-des-enregistrements-de-session:

R-S18 *(P=1, I=1)* - Effacement des enregistrements de session
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Score initial :** P=2, I=3 (zone jaune). Dans l'ancien modèle, le recorder tournait sous l'uid de l'utilisateur et écrivait dans son propre sous-répertoire ``2770 user:ob-sessions`` : il en était propriétaire et pouvait donc supprimer ou tronquer ses propres enregistrements via ``rm`` / ``: > fichier``.

**Cadre (important) — où se fait l'enregistrement :** l'enregistreur vit sur le **bastion**, le point de passage obligé. Une session vers un backend transite par le pty du bastion, donc **être root sur un backend ne permet pas d'échapper à l'enregistrement ni d'atteindre les fichiers** : ils sont sur le bastion, root-owned, et un root de backend n'a aucun accès au système de fichiers du bastion. Le seul acteur capable d'altérer les traces est **root sur le bastion lui-même** (l'hôte d'audit), un ensemble réduit et de confiance — voir le modèle de menace ci-dessous.

**Remédiation implémentée (PR #157, ``ob-record-sink``) :** le recording est désormais **streamé vers un puits root activé par socket** (design retenu :doc:`/design/tamper-evident-session-recording`), qui correspond exactement à l'option « démon collecteur privilégié » listée auparavant comme non-retenue :

- Le recorder (sous l'uid utilisateur) n'écrit plus aucun fichier. Il ouvre une socket Unix via ``ob-record-connect`` et y streame le typescript ; ``ob-record-sink`` (root, socket-activé) écrit les fichiers.
- L'utilisateur enregistré est dérivé de ``SO_PEERCRED`` (vérifié par le noyau, jamais de l'en-tête) → pas d'usurpation ni de traversée de chemin.
- Les fichiers sont **root:ob-sessions 0640** dans une arborescence ``root:ob-sessions 0750`` ; l'utilisateur enregistré n'étant **pas** membre de ``ob-sessions``, il n'a **aucun** droit (lister/lire/``unlink``/tronquer) sur ses enregistrements. C'est une frontière d'uid noyau (DAC), la plus robuste.
- **Fail-closed** : si le puits est indisponible, la session est refusée plutôt que de retomber sur un fichier user-owned (cf. §9 du design).
- Le wrapper setgid ``ob-session-recorder-wrapper`` (et son bit setgid) est **supprimé** : devenu inutile, il créait justement le sous-répertoire user-owned à l'origine du risque.

**Défenses complémentaires conservées :**

- Syslog (``auth.info``) : journal d'audit indépendant (start/end de session).
- Watch auditd ``-w /var/lib/open-bastion/sessions/ -p wa`` (PR2 #113, opt-in via ``--enable-audit-trace``).

**Score résiduel :** P=1, I=1. La suppression/altération par l'utilisateur non-sudo est désormais **techniquement impossible** (il ne possède pas les fichiers et ne peut pas traverser l'arborescence). Le résiduel P=1 (et non 0) couvre uniquement **root sur le bastion**, hors périmètre du modèle de menace.

**Modèle de menace :** root sur le bastion est de confiance ; on ne défend que contre l'utilisateur non privilégié (y compris s'il est root sur un backend). Se défendre contre root **du bastion** exigerait une expédition distante (WORM), une signature, ou un média append-only.

Pistes pour réduire encore I (couvrir root du bastion, déjà hors périmètre) :

1. **Centralisation syslog / streaming WORM** : pousser logs et recordings vers un serveur distant (SIEM / endpoint LLNG WORM) pour résister à une compromission root du bastion. Roadmap dans :doc:`/session-recording`.
2. **Signature des sessions** : signer cryptographiquement les fichiers à la clôture (clé privée hors du bastion) pour détecter toute altération a posteriori.

.. _security-99-risk-reduce-r-s17-p1-i2---verrouillage-total-lockout:

R-S17 *(P=1, I=2)* - Verrouillage total (lockout)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Avant remédiation, ce risque est en **zone rouge** (P=2, I=4). La remédiation le ramène à P=1/I=2 via :

- Compte de service de secours (``service-accounts.conf``) avec clé stockée en coffre-fort — **pré-configuré par le paquet ``open-bastion-linagora``** (compte ``linagora``, clé RSA, ``sudo_allowed = true``)
- Procédure de recouvrement console documentée et testée — **accès root via ttyS0 pré-configuré** dans ``/etc/securetty`` par le paquet bootstrap (``PermitRootLogin no`` bloque SSH, console OVH reste le filet de sécurité)
- LLNG en haute disponibilité

..

   **Note cache NSS :** Aucun démon de cache NSS externe n'est utilisé. Le module NSS gère son propre cache (mémoire + fichiers sous ``/var/cache/nss_llng``) et PAM invalide directement les entrées concernées lors de la création d'un utilisateur ou d'un changement de groupe, rendant la résolution immédiate. ``nscd`` a été retiré parce qu'il est redondant avec ce cache intégré, et parce qu'il est déprécié en amont et absent des distributions récentes — en dépendre nuisait à l'installabilité du paquet. Le retrait de la dépendance suffit : ``apt autoremove`` récupère ``nscd`` s'il n'est plus utilisé, et un administrateur qui l'exploite délibérément pour ``hosts``/``services`` le conserve. Sur un hôte qui le conserve, PAM continue de lancer ``nscd --invalidate passwd group`` en best-effort : le module NSS ne sert que ``passwd``, alors que ``nscd`` cache aussi le groupe — sans ce fork, un retrait de ``open-bastion-sudo`` resterait servi par ``nscd`` jusqu'à ``positive-time-to-live group`` (3600 s par défaut), différant la révocation sudo d'une heure.

   **Contrepartie en cas de panne LLNG :** le module ne sert jamais d'entrée périmée (elle est supprimée à la lecture) et un échec transitoire renvoie ``NSS_STATUS_UNAVAIL`` sans repli sur le cache. Le tampon de résolution vaut donc exactement ``cache_ttl`` (défaut **300 s**, ``/etc/open-bastion/nss_openbastion.conf``), là où le cache persistant de ``nscd`` couvrait plusieurs dizaines de minutes. Augmenter ``cache_ttl`` (jusqu'à 86400 s) sur les hôtes exposés à ce risque.

   **Trois limites à connaître en régime nominal**, détaillées dans le guide d'administration :

   1. **Seul root remplit le cache** (le jeton serveur LLNG est ``0600 root:root``) : une entrée qui expire sans qu'un processus root ne résolve l'utilisateur n'est pas renouvelée. Dans une session SSH inactive : ``ls -l`` en uid numériques, ``whoami``/``id`` en échec, ``ssh``/``scp`` sortant refusé (« You don't exist, go away! »). Toute résolution root (nouvelle session, ``su``, ``sudo``, ``cron``) répare immédiatement ; l'authentification et l'autorisation ne sont pas affectées.
   2. **Les résultats négatifs ne sont cachés qu'en mémoire, par processus** : le cache fichier n'est peuplé que sur succès, volontairement, car il est alimenté depuis un chemin non authentifié (``sshd`` résout le nom avant l'authentification) et l'y autoriser donnerait à un attaquant distant un moyen de remplir ``/var/cache/nss_llng`` d'inodes. Chaque tentative SSH avec un nom inexistant coûte donc une requête HTTPS ``/pam/userinfo``. ``nscd`` ne couvrait ce cas que partiellement (cache négatif keyé par nom, 20 s). Borner côté connexions (``MaxStartups``, ``fail2ban``/CrowdSec).
   3. **SELinux ``enforcing`` (Rocky/RHEL) non validé** : le cache est écrit depuis le domaine du processus appelant (``sshd_t``, ``sudo_t``, ``crond_t``). Si la politique par défaut le refuse, l'écriture échoue en silence et le cache partagé n'est jamais peuplé — vérifier par ``ausearch -m avc`` avant déploiement.

Pistes pour réduire davantage :

1. **Test de recouvrement périodique** : Simuler un lockout (désactiver LLNG en environnement de test) et valider la procédure console + compte de service de secours au moins une fois par an
2. **Alerte proactive** : Monitorer l'âge du cache offline et alerter quand il atteint 80% du TTL configuré, avant l'expiration
3. **Cache offline étendu pour le compte de secours** : Configurer un TTL offline plus long spécifiquement pour le compte de service de recouvrement
4. **Runbook automatisé** : Script de recouvrement pré-positionné sur le serveur (accessible uniquement via console) pour réactiver l'accès en une commande

--------------

Pistes d'Amélioration - Containment et Traçabilité
--------------------------------------------------

Cette section couvre les nouveaux risques R-S19, R-S20, R-S21 introduits par l'analyse approfondie de l'enregistreur de session. Voir :doc:`/security/02-ssh-connection` pour les fiches complètes.

.. _r-s19-p1-i1-si-pr1--pr2-activées-sinon-p3-i3---évasion-du-containment:

R-S19 *(P=1, I=1 si PR1 + PR2 activées, sinon P=3, I=3)* - Évasion du containment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pistes pour aller plus loin :

1. [STRIKEOUT:Démon collecteur de session privilégié] — **LIVRÉ (PR #157)**, voir :ref:`R-S18 <security-99-risk-reduce-r-s18-p1-i1---effacement-des-enregistrements-de-session>`. Cette piste était listée « non retenue pour éviter d'introduire un nouveau service permanent » : les deux objections sont caduques. Le puits ``ob-record-sink`` est **activé par socket** (``systemd/ob-record.socket``), donc pas un service permanent, et il écrit des fichiers **root-owned** (``src/ob-record-sink.c``, ``openat(..., O_NOFOLLOW, 0640)`` dans une arborescence ``root:ob-sessions 0750``), l'utilisateur étant dérivé de ``SO_PEERCRED``. La détection de fermeture brutale du recorder (``killed_prematurely`` côté serveur, MT34) est livrée avec le correctif de `#287 <https://github.com/linagora/open-bastion/issues/287>`__ : le flux est découpé en trames, et seule la trame de fin, envoyée après une fin de fichier propre, fait passer l'enregistrement à ``completed`` ; un transmetteur tué le laisse ``aborted``.
2. **Mandatory Access Control** : profil AppArmor / SELinux qui interdit ``setsid`` aux shells utilisateurs (rompre le canal d'évasion à la racine). Coût opérationnel élevé (rédaction et maintenance du profil par distribution) mais blocage fort.
3. **``KillUserProcesses=yes`` rendu obligatoire** : retirer l'opt-in et l'imposer en postinst. Abandonné à cause de la philosophie Debian (pas de modification système globale silencieuse). Pourrait être réintroduit comme paquet ``open-bastion-strict`` dédié, qui imposerait le hardening sans demande de confirmation.

R-S20 *(P=1, I=2 si PR1 activée, sinon P=2, I=3)* - Action différée
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pistes pour réduire I à 1 :

1. **Purge des crontabs pré-existants** : à l'activation de ``--enable-hardening``, itérer ``/var/spool/cron/crontabs/`` et supprimer (avec backup horodaté dans ``/var/lib/open-bastion/setup-backups/cron/``) les crontabs des utilisateurs hors ``cron.allow``. Documenté comme limite résiduelle dans :doc:`/security/02-ssh-connection`. Cette opération doit être idempotente et journalisée pour permettre la restauration si le hardening est désactivé.
2. **Surveillance des systemd timers utilisateurs** : auditer périodiquement ``loginctl list-users`` et alerter sur tout ``Linger=yes`` qui apparaîtrait après l'activation initiale du hardening (un administrateur pourrait l'activer manuellement par la suite).
3. **``pam_listfile`` sur ``crontab`` et ``at``** : double sécurité au niveau PAM en plus des allow-lists, pour les distributions où ``cron.allow`` ne serait pas honoré (rare en pratique sur Debian).

R-S21 *(P=1, I=2 si PR2 activée, sinon P=2, I=3)* - Action non capturée
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pistes pour réduire I à 1 :

1. **Forwarding remote-syslog des logs auditd** : ``audisp-syslog`` ou ``audisp-remote`` poussent les événements auditd vers un collecteur central (rsyslog, journald-remote, SIEM). Préserve la trace même en cas de compromission root du bastion. **Recommandation prioritaire** sur tout déploiement réel : sans collecteur distant, un attaquant root local peut effacer ``/var/log/audit/`` après ses méfaits.
2. **Étendre les règles auditd** : ajouter ``-S sendto -S sendmsg`` (volumétrie acceptée pour bastion à faible trafic), ``-S io_uring_enter`` (rare en pratique), puis activer ``-e 2`` (locked rules) en production pour empêcher ``auditctl -D`` à chaud par un attaquant qui aurait obtenu root.
3. **eBPF-based tracing** (Falco, sysdig) : alternative ou complément à auditd qui couvre des événements moins accessibles via syscalls (par ex. opérations sur file descriptors mémoire, écritures ``pwrite`` sur sockets). Plus coûteux en CPU mais plus expressif.
4. **Signature cryptographique du recording à la clôture** : ``gpg --detach-sign`` ou similaire avec clé privée hors du bastion (HSM ou serveur de signature distant), pour détecter toute altération a posteriori. Complète R-S18 plutôt que R-S21 stricto sensu, mais participe à la même propriété d'intégrité.

Pistes d'Amélioration - Comptes de service
------------------------------------------

Les comptes de service (``service-accounts.conf``) s'authentifient par **clé SSH directe**, en **local** sur chaque serveur, hors du modèle SSO/vouching. Ce sont des dérogations volontaires au contrôle centralisé : utiles pour l'automatisation (ansible, sauvegarde, CI/CD), mais ils ouvrent deux écarts à tracer.

R-S24 *(P=1, I=3)* - Sudo de compte de service hors token SSO
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

   **Fiche de risque :** l'analyse complète de R-S24 (vecteurs, facteurs atténuants, remédiation, score résiduel) est en section 6 de :doc:`/security/02-ssh-connection` ; la section ci-dessous n'est que le volet « pistes » du plan de traitement.

Le droit sudo d'un compte de service provient **uniquement** de ``service-accounts.conf`` (``sudo_allowed`` / ``sudo_nopasswd``) : ``pam_openbastion`` l'accorde localement et renvoie un succès **sans aucun appel LLNG**, **y compris en Mode E** où un humain doit présenter un token LLNG frais. Une clé de service avec ``sudo_allowed`` (a fortiori ``sudo_nopasswd``) est donc un **privilège local permanent qui échappe à la porte sudo gouvernée par le SSO**.

Pistes :

1. **Minimiser** : n'accorder ``sudo_allowed`` qu'aux comptes qui en ont réellement besoin ; préférer ``sudo_nopasswd = false`` et des règles ``sudoers`` restreintes à des commandes précises plutôt qu'un sudo total. ``sudo_nopasswd = false`` est réellement utilisable depuis la 0.6.3 : le contrôle d'empreinte ne lisait que ``SSH_USER_AUTH``, absent d'un handle PAM ``sudo``, si bien qu'il échouait toujours et que ``sudo_nopasswd = true`` — c'est-à-dire aucune preuve d'identité — était la seule configuration qui fonctionnait. L'empreinte est désormais reprise du spool des principals, que ``sudo`` hérite par l'arbre de processus.
2. **Inventaire et rotation** : traiter chaque clé de service comme un secret de longue durée (coffre-fort, rotation périodique, révocation à la sortie d'un prestataire/outil). Recoupe le compte de secours de :ref:`R-S17 <security-99-risk-reduce-r-s17-p1-i2---verrouillage-total-lockout>`.
3. **Audit dédié** : journaliser/alerter sur l'usage sudo des comptes de service (auditd ``-k`` distinct), puisqu'il n'apparaît pas dans les logs d'autorisation LLNG.

R-S25 *(P=1, I=2)* - Hop de compte de service via ProxyJump non enregistré
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

   **Fiche de risque :** l'analyse complète de R-S25 (vecteurs, facteurs atténuants, remédiation, score résiduel) est en section 6 de :doc:`/security/02-ssh-connection` ; la section ci-dessous n'est que le volet « pistes » du plan de traitement.

Un compte de service ne peut pas utiliser ``ob-ssh`` (pas de voucher SSO), mais un ``ssh -J bastion compte@backend`` natif fonctionne s'il est configuré des deux côtés et que le bastion autorise le forwarding TCP. Or le ``ForceCommand`` (enregistreur de session) **ne couvre pas le canal ``direct-tcpip``** : un tel hop **n'est pas enregistré** sur le bastion.

Pistes :

1. **Accès direct** : faire pointer les comptes de service directement sur les serveurs cibles (la traçabilité repose alors sur l'auditd/les logs de la cible) plutôt que de les relayer par le bastion.
2. **``AllowTcpForwarding no`` sur le bastion** : interdire explicitement le forwarding pour fermer le canal de hop non enregistré (à arbitrer selon les usages légitimes de forwarding sur le parc).
3. **Ne pas configurer les comptes de service sur le bastion** lui-même quand ils n'y ont pas de tâche locale, pour retirer la première marche du ProxyJump.
