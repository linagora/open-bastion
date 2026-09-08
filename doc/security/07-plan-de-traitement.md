# Atelier 5 — Plan de traitement du risque

> **Méthode :** EBIOS Risk Manager (ANSSI, 2018), atelier 5. Ce document est le
> plan de traitement : une mesure par ligne, avec le risque qu'elle réduit, sa
> nature, sa priorité, son porteur, son échéance et son état. Il remplace la
> liste de « pistes » en texte libre de [99-risk-reduce.md](99-risk-reduce.md),
> qui reste le lieu de l'**argumentaire** technique de chaque mesure.
>
> **Ce document n'est pas complet tant que les colonnes _Porteur_ et _Échéance_
> portent la mention `À COMPLÉTER`.** Ces valeurs relèvent d'une décision
> projet, pas d'une analyse ; elles sont laissées vides plutôt qu'inventées.

## 5.1 Convention

| Colonne      | Valeurs                                                                                                                    |
| ------------ | -------------------------------------------------------------------------------------------------------------------------- |
| **Priorité** | **P0** = requis avant mise en production · **P1** = requis dans le cycle courant · **P2** = amélioration planifiée         |
| **Nature**   | **Produit** = code ou paquet Open Bastion · **Déploiement** = configuration à la pose · **Exploitation** = geste récurrent |
| **Porteur**  | Rôle responsable de la réalisation. `À COMPLÉTER` = à nommer par le projet                                                 |
| **Échéance** | Date cible. `À COMPLÉTER` = à fixer par le projet                                                                          |
| **État**     | **Livré** (avec la référence de PR ou d'issue) · **Ouvert** · **Écarté** (avec le motif)                                   |

Une mesure `Livré` reste dans le plan : elle documente que le risque associé est
traité, et par quoi. C'est ce qui manquait au backlog précédent, où deux mesures
déjà livrées étaient encore proposées comme travaux futurs (voir #215).

## 5.2 Mesures requises avant mise en production (P0)

Ce sont les **conditions d'emploi** : sans elles, les scores résiduels de
l'atelier 4 ne sont pas atteints. Elles sont reprises, avec leur preuve de mise
en œuvre attendue, en [08-dossier-homologation.md](08-dossier-homologation.md).

| Id       | Mesure                                                                                            | Risques                                       | Nature       |  Priorité   | Porteur             | Échéance            | État                                     |
| -------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------- | ------------ | :---------: | ------------------- | ------------------- | ---------------------------------------- | ----------------------------- |
| **MT01** | `locationRules` sur `^/device` restreignant l'approbation d'enrôlement à un groupe d'approbateurs | R0, R7, R-P5                                  | Déploiement  |     P0      | Administrateur LLNG | `À COMPLÉTER`       | **Livré** (doc + démos, #195)            |
| **MT02** | `locationRules` sur `^/ssh/(admin\| certs\, R-P2                                                  | revoke)` restreignant l'administration ssh-ca | R-S4         | Déploiement | P0                  | Administrateur LLNG | `À COMPLÉTER`                            | **Livré** (doc + démos, #195) |
| **MT03** | `allowed_bastions` renseigné sur chaque backend avec les device-ids réellement attendus           | R-S23, R-P1                                   | Déploiement  |     P0      | Équipe Open Bastion | `À COMPLÉTER`       | **Livré** (invite + alerte, #182)        |
| **MT04** | `RequirePKCE = 1` sur le client OIDC d'enrôlement                                                 | R13                                           | Déploiement  |     P0      | Administrateur LLNG | `À COMPLÉTER`       | **Ouvert** — à vérifier sur cible        |
| **MT05** | Compte de service de secours + accès console hors-bande documenté et testé                        | R-S17, R-P3                                   | Déploiement  |     P0      | Équipe exploitation | `À COMPLÉTER`       | **Ouvert**                               |
| **MT06** | KRL déployée sur tous les serveurs, rafraîchie ≤ 30 min, avec alerte de fraîcheur                 | R-S15                                         | Exploitation |     P0      | Équipe exploitation | `À COMPLÉTER`       | Partiel — cron livré, alerte **ouverte** |
| **MT07** | Clé privée de la CA SSH protégée : accès Manager LLNG restreint et tracé                          | R5, R-S4, R-P4                                | Exploitation |     P0      | Administrateur LLNG | `À COMPLÉTER`       | **Ouvert**                               |

## 5.3 Mesures du cycle courant (P1)

| Id       | Mesure                                                                                              | Risques      | Nature       | Priorité | Porteur             | Échéance      | État                                                  |
| -------- | --------------------------------------------------------------------------------------------------- | ------------ | ------------ | :------: | ------------------- | ------------- | ----------------------------------------------------- |
| **MT10** | Enregistrement de session écrit par un puits root, inaccessible à l'utilisateur enregistré          | R-S18, R-S19 | Produit      |    P1    | Équipe Open Bastion | —             | **Livré** (#157, `ob-record-sink`)                    |
| **MT11** | Enregistrement fail-closed : la session est refusée si le puits est injoignable                     | R-S18        | Produit      |    P1    | Équipe Open Bastion | —             | **Livré** — actif par défaut                          |
| **MT12** | Confinement de session (`KillUserProcesses`, `at`/`cron` en allow-list, refus du `linger`)          | R-S19, R-S20 | Déploiement  |    P1    | Équipe exploitation | `À COMPLÉTER` | **Livré** en opt-in (`--enable-hardening`, #112)      |
| **MT13** | Trace auditd de niveau syscall (`execve`, watches, `connect`)                                       | R-S21        | Déploiement  |    P1    | Équipe exploitation | `À COMPLÉTER` | **Livré** en opt-in (`--enable-audit-trace`, #113)    |
| **MT14** | Export des journaux auditd et des enregistrements vers un collecteur distant (WORM ou SIEM)         | R-S18, R-S21 | Exploitation |    P1    | Équipe exploitation | `À COMPLÉTER` | **Ouvert** — recommandation prioritaire               |
| **MT15** | Liaison de l'empreinte de clé SSH à la session SSO, exigible (`fingerprint_required`)               | R-S3, R-S15  | Produit      |    P1    | Équipe Open Bastion | —             | **Livré** (#192)                                      |
| **MT16** | Token LLNG frais à chaque `sudo` (`timestamp_timeout=0` cadré sur le groupe SSO)                    | R-S16        | Déploiement  |    P1    | Équipe exploitation | `À COMPLÉTER` | **Livré** en opt-in (`--enable-sudo-fresh-otp`, #178) |
| **MT17** | Vérification de `target=` par `ob-ssh-principals` contre le FQDN local                              | R-S22        | Produit      |    P1    | Équipe Open Bastion | `À COMPLÉTER` | **Ouvert**                                            |
| **MT18** | Mode strict de vouching : l'absence d'`allowed_bastions` refuse au lieu du mode hérité              | R-S23        | Produit      |    P1    | Équipe Open Bastion | `À COMPLÉTER` | **Ouvert**                                            |
| **MT19** | Alerte sur échec de `ob-heartbeat.service` et sur l'âge du token serveur                            | R-S17, R10   | Exploitation |    P1    | Équipe exploitation | `À COMPLÉTER` | **Ouvert**                                            |
| **MT20** | Rotation et inventaire des clés de comptes de service ; `sudo_allowed` accordé au strict nécessaire | R-S24, R-SA1 | Exploitation |    P1    | Équipe exploitation | `À COMPLÉTER` | **Ouvert**                                            |
| **MT21** | `AllowTcpForwarding no` sur le bastion, ou comptes de service non déclarés sur le bastion           | R-S25        | Déploiement  |    P1    | Équipe exploitation | `À COMPLÉTER` | **Ouvert**                                            |
| **MT22** | Test de recouvrement annuel : simulation de panne LLNG, validation console + compte de secours      | R-S17        | Exploitation |    P1    | Équipe exploitation | `À COMPLÉTER` | **Ouvert**                                            |

## 5.3bis Mesures portant sur le portail LLNG et ses plugins

Le portail est **dans le périmètre** ([08, §1.1](08-dossier-homologation.md#11-ce-qui-est-homologué)),
donc ses défauts sont dans ce plan. Plusieurs mesures sont **amont** : leur
réalisation ne dépend pas de ce dépôt, ce que la colonne Porteur dit.

| Id       | Mesure                                                                                                         | Risques     | Nature       | Priorité | Porteur             | Échéance      | État                                                                                                                                                                                                                                |
| -------- | -------------------------------------------------------------------------------------------------------------- | ----------- | ------------ | :------: | ------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **MT40** | Renseigner `pamAccessServerGroups` (le `server_group` cesse d'être une donnée d'entrée)                        | R-P1        | Déploiement  |    P0    | Administrateur LLNG | `À COMPLÉTER` | **Ouvert — prérequis de publication `0.7.0`**, condition d'emploi CE03 bloquante                                                                                                                                                                                                |
| **MT41** | Liaison d'audience sur les jetons `/pam/*`                                                                     | R-P1        | Amont        |    P1    | Mainteneur plugins  | `À COMPLÉTER` | **Corrigé amont, non publié** — `#50`, PR `#92` ; n'agit que si `pamAccessAllowedRps` est renseigné                                                                                                                                 |
| **MT42** | Contrôle d'autorisation intégré sur `/ssh/admin\|certs\|revoke` (refus par défaut)                             | R-P2        | Amont        |    P1    | Mainteneur plugins  | `À COMPLÉTER` | **Corrigé amont, non publié** — `#58`                                                                                                                                                                                               |
| **MT43** | Écriture atomique de la KRL, verrou étendu aux lecteurs et au cron de reconstruction                           | R-P3        | Amont        |    P0    | Mainteneur plugins  | `À COMPLÉTER` | **Corrigé amont, non publié** — `#59`, PR `#77` ; le verrou entre générateurs existait déjà en `v0.5.2`                                                                                                                             |
| **MT44** | Contrôle de plausibilité de la KRL côté client (`ssh-keygen -Q -l -f` avant déploiement)                       | R-P3        | Produit      |    P0    | Équipe Open Bastion | `À COMPLÉTER` | **Ouvert** — atténue MT43 sans le remplacer                                                                                                                                                                                         |
| **MT45** | Nettoyage du répertoire temporaire de signature (clé de CA en clair dans `/tmp`)                               | R-P4        | Amont        |    P0    | Mainteneur plugins  | `À COMPLÉTER` | **Corrigé amont, non publié** — `#60`                                                                                                                                                                                               |
| **MT46** | Échec fermé sur échec de session synthétique + couverture de tests du plugin device-organization               | R-P6        | Amont        |    P1    | Mainteneur plugins  | `À COMPLÉTER` | **Corrigé amont, non publié** — `#72` (échec fermé, PR `#80`) et `#71` (tests, `2e5e4c4` via PR `#90`)                                                                                                                              |
| **MT47** | Vérification systématique de `ob-bastion-id` après enrôlement                                                  | R-P6        | Exploitation |    P1    | Équipe exploitation | `À COMPLÉTER` | **Ouvert** — condition d'emploi CE19                                                                                                                                                                                                |
| **MT48** | Verrouillage réel du magasin de sessions, ou mises à jour par champ avec comparaison-et-échange                | R-P7        | Amont        |    P1    | Mainteneur plugins  | `À COMPLÉTER` | **Partiellement corrigé amont, non publié** — les courses identifiées sont fermées (PR `#87`, `#88`, `#95`, `#69`), mais la mesure elle-même — verrou réel ou comparaison-et-échange — n'est pas livrée : le motif survit à `0.6.0` |
| **MT49** | Limitation de débit sur `/ssh/sign` au niveau du reverse proxy, et surveillance de la taille de la KRL         | R-P8        | Déploiement  |    P1    | Équipe exploitation | `À COMPLÉTER` | **Ouvert** — condition d'emploi CE17 ; la PR amont `#90` (`#63`) borne `/ssh/sign` côté plugin, ce qui ne remplace ni le reverse proxy ni la surveillance, et l'amont ne purgera pas la KRL (choix assumé, voir R-P8)               |
| **MT50** | Figer et déployer une version minimale des quatre plugins                                                      | R-P1 à R-P8 | Déploiement  |    P0    | Administrateur LLNG | `À COMPLÉTER` | **Ouvert — prérequis de publication `0.7.0`**, condition d'emploi CE16 bloquante ; la cible est `0.6.0` (`v0.5.2` est la dernière publiée)                                                                                                                                      |
| **MT51** | Migrer `ob-bastion-id` de `/pam/bastion-token` (supprimé amont) vers `POST /pam/whoami`                        | R-P6        | Produit      |    P0    | Équipe Open Bastion | `À COMPLÉTER` | **Livré, non publié** — PR [#248](https://github.com/linagora/open-bastion/pull/248), fusionnée dans `main` ; sera publiée avec `0.7.0`                                                                                                                                                            |
| **MT52** | Signer les six endpoints `/pam/*` côté client, pour rendre `pamAccessRequestSigningMode = required` déployable | R-P1, R-P7  | Produit      |    P1    | Équipe Open Bastion | `À COMPLÉTER` | **Livré, non publié** — [#247](https://github.com/linagora/open-bastion/issues/247) fermé par la PR [#252](https://github.com/linagora/open-bastion/pull/252), fusionnée dans `main` ; sera publiée avec `0.7.0`. Le déploiement de `required` reste conditionné à la configuration du portail                                                                                                                |
| **MT53** | Renseigner `pamAccessAllowedRps` et enrôler les bastions sous un `client_id` distinct du projet                | R-P1        | Déploiement  |    P0    | Administrateur LLNG | `À COMPLÉTER` | **Ouvert — prérequis de publication `0.7.0`**, condition d'emploi CE21 bloquante ; une liste vide vaut « pas de changement », donc MT41 n'agit pas du tout tant qu'elle l'est                                                        |

> **MT48 n'est pas une correction ponctuelle.** **Neuf** courses
> lecture-modification-écriture ont été identifiées sur des magasins qui
> n'offrent aucune atomicité : c'est un **motif**, pas neuf bogues. Les PR
> amont `#87`, `#88` et `#95` ferment les courses recensées ; elles ne rendent
> pas le magasin atomique, et la mesure telle qu'elle est écrite ci-dessus
> n'est donc pas livrée par `0.6.0`. Tant que le motif n'est pas traité à la
> racine, toute nouvelle écriture dans la session persistante doit être conçue
> idempotente et tolérante à l'écrasement.

## 5.4 Améliorations planifiées (P2)

| Id       | Mesure                                                                                             | Risques               | Nature      | Priorité | Porteur             | Échéance      | État                             |
| -------- | -------------------------------------------------------------------------------------------------- | --------------------- | ----------- | :------: | ------------------- | ------------- | -------------------------------- |
| **MT30** | `client_id` distincts par zone de sécurité (isolation des credentials d'enrôlement)                | R0, R4, R7, R11, R-S6 | Déploiement |    P2    | Administrateur LLNG | `À COMPLÉTER` | **Ouvert** — arbitrage documenté |
| **MT31** | Réduction de `pamAccessBastionVoucherTtl` sous 12 h                                                | R-S6                  | Déploiement |    P2    | Administrateur LLNG | `À COMPLÉTER` | **Ouvert**                       |
| **MT32** | Réduction de `pamAccessBastionCertTtl` (120 s → 30–60 s) sur les zones sensibles                   | R-S9                  | Déploiement |    P2    | Administrateur LLNG | `À COMPLÉTER` | **Ouvert**                       |
| **MT33** | Signature cryptographique des enregistrements à la clôture (clé hors bastion)                      | R-S18                 | Produit     |    P2    | Équipe Open Bastion | `À COMPLÉTER` | **Ouvert**                       |
| **MT34** | Détection d'un enregistreur tué en cours de session (`killed_prematurely`)                         | R-S19                 | Produit     |    P2    | Équipe Open Bastion | `À COMPLÉTER` | **Ouvert** — reliquat de MT10    |
| **MT35** | Webhook de révocation LLNG → fermeture des sessions ouvertes                                       | R-S8                  | Produit     |    P2    | Équipe Open Bastion | `À COMPLÉTER` | **Ouvert**                       |
| **MT36** | Notification de rotation de CA vers les backends (`TrustedUserCAKeys`) et monitoring de divergence | R-S10                 | Produit     |    P2    | Équipe Open Bastion | `À COMPLÉTER` | **Ouvert**                       |
| **MT37** | Purge des crontabs pré-existants à l'activation du durcissement                                    | R-S20                 | Produit     |    P2    | Équipe Open Bastion | `À COMPLÉTER` | **Ouvert**                       |
| **MT38** | Épinglage de certificat TLS rendu obligatoire vers le portail                                      | R5                    | Déploiement |    P2    | Équipe exploitation | `À COMPLÉTER` | **Ouvert**                       |
| **MT39** | Second facteur exigé pour l'obtention du token `sudo`                                              | R-S16                 | Déploiement |    P2    | Administrateur LLNG | `À COMPLÉTER` | **Ouvert**                       |

## 5.5 Mesures écartées

Une mesure écartée reste tracée : elle a été examinée, et le motif du refus fait
partie de l'analyse.

| Mesure envisagée                                                           | Risques | Motif de l'écart                                                                                                                                   |
| -------------------------------------------------------------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Profil MAC (AppArmor/SELinux) interdisant `setsid` aux shells utilisateurs | R-S19   | Coût de rédaction et de maintenance par distribution jugé supérieur au gain, `KillUserProcesses` couvrant le canal principal                       |
| `KillUserProcesses=yes` imposé par le postinst                             | R-S19   | Modification système globale silencieuse, contraire à la politique Debian. Réexaminable sous forme d'un paquet `open-bastion-strict` dédié         |
| Épinglage de `target=` côté LLNG via `source-address`                      | R-S22   | Techniquement impossible : `source-address` épingle l'origine, pas la destination. Le contrôle doit être porté par `ob-ssh-principals` (voir MT17) |
| Traitement du risque « administrateur du portail LLNG » (SR7)              | tous    | Hors de portée du produit : c'est l'autorité dont dépend le modèle. Traité comme **hypothèse de confiance** en [08](08-dossier-homologation.md)    |

## 5.6 Suivi

| Question                                          | Réponse                                                                                                      |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Qui tient ce plan à jour ?                        | `À COMPLÉTER`                                                                                                |
| À quelle fréquence est-il revu ?                  | `À COMPLÉTER` (recommandation : à chaque version mineure, et après tout incident)                            |
| Comment une mesure livrée est-elle vérifiée ?     | Par la référence de PR portée en colonne État, et par les tests cités dans la fiche de risque correspondante |
| Comment une nouvelle fiche entre-t-elle au plan ? | `tests/ebios_matrix_check.py` échoue si une fiche n'est rattachée à aucun événement redouté (atelier 1)      |

---

Atelier précédent : Atelier 4 — [enrôlement](01-enrollment.md) et
[connexion SSH](02-ssh-connection.md) · Argumentaire technique des mesures :
[99-risk-reduce.md](99-risk-reduce.md) · Décisions :
[08-dossier-homologation.md](08-dossier-homologation.md)
