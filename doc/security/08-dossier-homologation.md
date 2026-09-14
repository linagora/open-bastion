# Dossier d'homologation — périmètre, conditions d'emploi, acceptation

> **Ce document est le seul de l'étude qui engage.** Les ateliers analysent ; ce
> document décide : ce qui est homologué, sous quelles conditions vérifiables, et
> quels risques résiduels sont acceptés, par qui.
>
> **Il n'est pas signé tant que les champs `À COMPLÉTER` subsistent.** Ces
> valeurs — noms, dates, décisions d'acceptation — relèvent de l'autorité
> d'homologation et ne sont pas déduites de l'analyse.

## Identification du dossier

| Champ                        | Valeur                                                                       |
| ---------------------------- | ---------------------------------------------------------------------------- |
| **Objet**                    | Open Bastion — accès SSH d'administration gouverné par LemonLDAP::NG         |
| **Version du dossier**       | 1.0 (première émission)                                                      |
| **Version du produit visée** | `À COMPLÉTER` (version d'Open Bastion et des quatre plugins LLNG homologuée) |
| **Méthode**                  | EBIOS Risk Manager (ANSSI, 2018), ateliers 1 à 5                             |
| **Rédacteur**                | Équipe Open Bastion                                                          |
| **Date d'émission**          | `À COMPLÉTER`                                                                |
| **Autorité d'homologation**  | `À COMPLÉTER` (nom et fonction)                                              |
| **Date de décision**         | `À COMPLÉTER`                                                                |
| **Durée de validité**        | `À COMPLÉTER` (recommandation : 3 ans, ou toute évolution du périmètre)      |

### Composition du dossier

| Pièce                                                                                                                        | Contenu                                                        |
| ---------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| [00-architecture.md](00-architecture.md)                                                                                     | Cible de sécurité, architecture, mécanismes                    |
| [04-atelier1-cadrage-socle.md](04-atelier1-cadrage-socle.md)                                                                 | Périmètre, valeurs métier, biens supports, échelles, ER, socle |
| [05-atelier2-sources-de-risque.md](05-atelier2-sources-de-risque.md)                                                         | Sources de risque, objectifs visés, couples retenus            |
| [06-atelier3-scenarios-strategiques.md](06-atelier3-scenarios-strategiques.md)                                               | Écosystème, scénarios stratégiques                             |
| [01-enrollment.md](01-enrollment.md), [02-ssh-connection.md](02-ssh-connection.md), [09-portail-llng.md](09-portail-llng.md) | Scénarios opérationnels : 47 fiches de risque                  |
| [07-plan-de-traitement.md](07-plan-de-traitement.md)                                                                         | Plan de traitement                                             |
| [99-risk-reduce.md](99-risk-reduce.md)                                                                                       | Matrice résiduelle consolidée et argumentaire des mesures      |
| [03-offboarding.md](03-offboarding.md)                                                                                       | Procédure opérationnelle de révocation                         |
| **Ce document**                                                                                                              | Périmètre d'homologation, conditions d'emploi, acceptation     |

## 1. Périmètre d'homologation

### 1.1 Ce qui est homologué

Le périmètre est celui de l'[atelier 1, §1.1](04-atelier1-cadrage-socle.md#11-objet-et-périmètre-de-létude),
et il **inclut le portail LemonLDAP::NG et sa chaîne de quatre plugins**
(`pam-access`, `ssh-ca`, `oidc-device-authorization`,
`oidc-device-organization`).

Cette inclusion est une décision, et elle a un motif : le portail autorise chaque
session et chaque `sudo`, signe les certificats et détient la clé de CA. Une
homologation qui s'arrêterait au bord du serveur porterait sur la moitié des
décisions de sécurité et laisserait l'autre moitié hors de tout engagement.

Conséquence directe : les constats de sécurité portant sur les plugins font
partie de l'étude et doivent y être intégrés, y compris lorsqu'ils invalident une
revendication de remédiation côté serveur.

### 1.2 Ce qui n'est pas homologué

| Hors périmètre                                            | Attendu de l'exploitant                                               |
| --------------------------------------------------------- | --------------------------------------------------------------------- |
| Système d'exploitation hôte et son durcissement           | Socle durci (CIS / ANSSI-BP-028), mises à jour de sécurité appliquées |
| `sshd` (OpenSSH amont)                                    | Version supportée, correctifs de sécurité appliqués                   |
| Réseau et sa segmentation                                 | Backends joignables uniquement depuis le bastion                      |
| Annuaire LDAP/AD derrière LLNG                            | Cycle de vie des comptes maîtrisé, désactivation effective au départ  |
| Socle LLNG cœur (portail, sessions, Manager) hors plugins | Version supportée, accès Manager restreint et tracé                   |
| Postes de travail des administrateurs                     | Durcissement et protection du matériel d'authentification             |
| **Les modes PAM A à D**                                   | Non couverts : l'étude porte sur la cible Mode E seule                |

### 1.3 Hypothèses de confiance

Ces hypothèses ne sont pas des mesures : ce sont des postulats sans lesquels
l'analyse ne tient pas. Elles sont énoncées pour être contestables.

| Id     | Hypothèse                                                                                                   | Si elle tombe                                                            |
| ------ | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| **H1** | L'administrateur du portail LLNG (SR7) est digne de confiance ; son accès au Manager est restreint et tracé | Le modèle entier tombe : il peut signer un certificat pour n'importe qui |
| **H2** | Root sur le bastion n'est pas dans le modèle de menace de la traçabilité                                    | Les enregistrements de session ne sont plus opposables                   |
| **H3** | La chaîne de distribution APT et sa signature GPG ne sont pas compromises                                   | Un paquet malveillant s'installe avec les droits root                    |
| **H4** | L'annuaire amont reflète fidèlement les habilitations en vigueur                                            | La révocation LLNG ne coupe plus l'accès en pratique                     |

## 2. Conditions d'emploi

Les scores résiduels de l'atelier 4 **supposent** ces conditions. Le produit ne
les impose pas toutes : elles doivent être vérifiées sur la cible, et la preuve
conservée dans le dossier.

| Id       | Condition                                                                            | Risques concernés | Vérification sur cible                                                                                                                                                                                                         | Statut cible                                                       |
| -------- | ------------------------------------------------------------------------------------ | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| **CE01** | `locationRules` sur `^/device` restreignant l'approbation d'enrôlement               | R0, R7, R-P5      | Manager LLNG → vhost portail → règle présente ; test négatif avec un compte non approbateur                                                                                                                                    | `À COMPLÉTER`                                                      |
| **CE02** | `locationRules` sur `^/ssh/(admin\|certs\|revoke)`                                   | R-S4, R-P2        | Idem ; vérifier que `/ssh/revoked` (KRL publique) reste accessible                                                                                                                                                             | `À COMPLÉTER`                                                      |
| **CE03** | `pamAccessServerGroups` renseigné — **bloquante** (voir ci-dessous)                  | R4, R7, R11, R-P1 | Manager LLNG : le mapping d'autorité `client_id → server_group` existe. Tant qu'il est vide, `server_group` est lu dans le corps de la requête                                                                                 | `À COMPLÉTER`                                                      |
| **CE04** | `RequirePKCE = 1` sur le client OIDC d'enrôlement                                    | R13               | Manager LLNG → RP → option PKCE                                                                                                                                                                                                | `À COMPLÉTER`                                                      |
| **CE05** | CrowdSec **et un bouncer** effectivement déployés                                    | R2, R-S12         | Le plugin n'émet qu'une alerte : sans bouncer, aucun blocage. Vérifier la chaîne de bout en bout                                                                                                                               | `À COMPLÉTER`                                                      |
| **CE06** | `allowed_bastions` renseigné sur chaque backend — **bloquante**                      | R-S23, R-P1       | `cat /etc/open-bastion/allowed_bastions` non vide sur chaque backend ; alerte `authpriv` absente des logs                                                                                                                      | `À COMPLÉTER`                                                      |
| **CE07** | Durcissement de confinement activé (`--enable-hardening`)                            | R-S19, R-S20      | Sans lui, R-S19 revient à (P=3, I=3) et R-S20 à (P=2, I=3)                                                                                                                                                                     | `À COMPLÉTER`                                                      |
| **CE08** | Trace auditd activée (`--enable-audit-trace`)                                        | R-S21             | Sans elle, R-S21 revient à (P=2, I=3)                                                                                                                                                                                          | `À COMPLÉTER`                                                      |
| **CE09** | `fingerprint_required = true` sur les hôtes en mode certificat                       | R-S3, R-S15       | Sans lui, la liaison d'empreinte disparaît silencieusement si le spool manque                                                                                                                                                  | `À COMPLÉTER`                                                      |
| **CE10** | Enregistrement de session actif et fail-closed (défaut, non désactivé)               | R-S18             | Absence de `--disable-session-recorder` ; `ob-record.socket` actif                                                                                                                                                             | `À COMPLÉTER`                                                      |
| **CE11** | KRL déployée et rafraîchie ≤ 30 min, avec alerte de fraîcheur                        | R-S15             | `RevokedKeys` dans `sshd_config` ; âge du fichier surveillé                                                                                                                                                                    | `À COMPLÉTER`                                                      |
| **CE12** | Compte de service de secours **et** accès console hors-bande, testés                 | R-S17, R-P3       | Test de recouvrement daté (MT22)                                                                                                                                                                                               | `À COMPLÉTER`                                                      |
| **CE13** | Clé privée de la CA SSH : accès au Manager LLNG restreint et tracé                   | R5, R-S4, R-P4    | La clé est en clair dans la configuration LLNG : c'est l'accès au Manager qui la protège                                                                                                                                       | `À COMPLÉTER`                                                      |
| **CE14** | Journaux auditd et enregistrements exportés vers un collecteur distant               | R-S18, R-S21      | Sans export, root du bastion peut effacer la trace après coup (voir H2)                                                                                                                                                        | `À COMPLÉTER`                                                      |
| **CE15** | `client_secret_mode: prompt` ou secret sous `ansible-vault` ; bundles non versionnés | R0, R3            | Aucun `ob_client_secret` en clair dans un dépôt ou une sauvegarde                                                                                                                                                              | `À COMPLÉTER`                                                      |
| **CE16** | Version minimale des quatre plugins LLNG figée et déployée — **bloquante**           | R-P1 à R-P8       | `À COMPLÉTER` : figer la version au moment de la décision, puis vérifier sur le portail                                                                                                                                        | `À COMPLÉTER`                                                      |
| **CE17** | Limitation de débit sur `/ssh/sign` au niveau du reverse proxy du portail            | R-P8              | Configuration du reverse proxy ; surveillance de la taille de la KRL et du temps de signature                                                                                                                                  | `À COMPLÉTER`                                                      |
| **CE18** | Contrôle de plausibilité de la KRL avant déploiement (`ssh-keygen -Q -l -f`)         | R-P3              | Une KRL tronquée après son en-tête passe le contrôle actuel et fait échouer `sshd` sur toutes les clés                                                                                                                         | `À COMPLÉTER`                                                      |
| **CE19** | `ob-bastion-id` vérifié après chaque enrôlement : un hôte sans device-id est refusé  | R-P6              | Sur échec de session synthétique, le plugin renvoie `PE_OK` et l'hôte obtient un jeton sans identité machine                                                                                                                   | `À COMPLÉTER`                                                      |
| **CE20** | `ssh_key_policy_enabled = true` sur les hôtes en cible de sécurité maximale          | R-S11             | Le défaut du code est `false` (`src/config.c`) ; tant que les plugins ne sont pas en `0.6.0`, `ssh-ca` n'applique aucune contrainte de type ni de taille et ce réglage est le seul contrôle qui refuse RSA < 2048 ou `ssh-dss` | `À COMPLÉTER`                                                      |
| **CE21** | `pamAccessAllowedRps` renseigné, bastions enrôlés sous un `client_id` distinct — **bloquante** | R-P1              | Manager LLNG : la liste n'est pas vide. Une liste vide vaut « pas de changement » (compatibilité de montée de version), donc la liaison d'audience amont n'agit pas du tout tant qu'elle l'est                                 | `À COMPLÉTER`                                                      |

**Quatre de ces conditions sont bloquantes pour la publication de `0.7.0`.**
CE03, CE06, CE16 et CE21 traitent le même risque, R-P1 : tant que
`pamAccessServerGroups` est vide, le `server_group` est lu dans le corps de la
requête, et **tout hôte enrôlé du projet qui est compromis peut se déclarer
bastion** et obtenir un voucher de rebond pour un utilisateur. C'est le
comportement **par défaut** du produit tel qu'il est livré, et
[00-architecture.md](00-architecture.md) recommande précisément la
configuration multi-groupes dans laquelle il se manifeste.

Deux positions étaient tenables : en faire un prérequis, ou l'accepter comme
risque résiduel signé. La seconde a été écartée — un défaut livré qui contredit
la configuration recommandée par l'architecture n'est pas un résiduel, c'est une
condition de mise en service. `0.7.0` ne se déploie donc pas sans elles, et
elles ne sont pas rattrapables après coup : un hôte compromis pendant la fenêtre
a déjà obtenu ses vouchers.

Le produit ne peut ni les poser ni les vérifier. `pamAccessServerGroups` et
`pamAccessAllowedRps` sont des réglages du Manager LLNG, et interroger le
portail sur leur état supposerait une API qui publierait les bastions, les
groupes de serveurs et les RP du projet — ce qu'un SSO n'a pas à offrir. La
seule application possible est donc déclarative, et elle est en place :
`ob-bastion-setup`, `ob-backend-setup`, `ob-desktop-setup` et `ob-post-upgrade`
impriment la consigne à chaque exécution, et `ob-builder` écrit à côté de chaque
artefact une `PORTAL-CHECKLIST.md` pré-remplie avec le `client_id` et le
`server_group` de ce déploiement (`tests/test_ob_portal_prerequisites.sh`).

**CE13 mérite d'être lu deux fois.** La clé privée de la CA SSH est stockée en
clair dans la configuration LLNG. Ce n'est pas un défaut caché : c'est un choix
d'architecture, dont la conséquence est que **l'accès en lecture à la
configuration LLNG équivaut à la possession de la CA**. Le risque R-S4
(compromission de la CA, gravité 4) repose donc entièrement sur la protection de
cet accès.

## 3. Acceptation des risques résiduels

Cinq risques sont en **zone orange** (score 6) après traitement et requièrent
une acceptation formelle. Les sept risques en zone jaune sont listés pour
information ; les 35 risques en zone verte relèvent de la surveillance ordinaire.

Deux des cinq — R-P3 et R-P7 — dépendent d'un correctif **amont** : les
accepter, c'est accepter un délai hors du contrôle direct du projet. Ce délai
n'est plus indéterminé : au 6 septembre 2026, les **quinze** tickets amont
référencés par les fiches du portail sont tous fermés et mergés (inventaire
ticket par ticket en
[09, état des correctifs amont](09-portail-llng.md#matrice-des-risques-du-portail)).
Aucun n'est **publié** : la dernière version étiquetée est `v0.5.2` et ils
sortiront en `0.6.0`. Le résiduel ne change donc pas.

Ce que devient l'acceptation n'est en revanche **pas le même pour les deux
risques**, et le dossier ne doit pas les confondre :

- **R-P3** — l'acceptation porte sur un **délai de publication seul**. La cause
  (écriture non atomique de la KRL) est traitée en amont par la PR `#77` ; à la
  publication de `0.6.0`, avec CE18 côté client, le risque sort de la zone
  orange. C'est la version la plus faible de cette acceptation et la plus facile
  à assumer.
- **R-P7** — l'acceptation porte sur **davantage qu'un délai**. Les PR `#87`,
  `#88` et `#95` ferment les neuf courses recensées, mais la mesure MT48 telle
  qu'elle est écrite — verrouillage réel du magasin de sessions, ou mises à jour
  par champ avec comparaison-et-échange — n'est livrée par aucune d'elles, et la
  fiche R-P7 le dit explicitement : « les correctifs suppriment des courses
  identifiées, ils ne rendent pas le magasin atomique ». Le statut orange de
  R-P7 **survit donc à la publication de `0.6.0`**. MT52, la part produit, est
  livrée depuis (`open-bastion#247`, fermé par la PR `#252`, à publier avec
  `0.7.0`) ; ce qui reste est un travail de conception **amont** sur le magasin
  de sessions, et c'est lui qui maintient le statut orange.

L'autorité d'homologation signe donc, pour R-P7, l'acceptation d'un motif connu
et non refermé — pas celle d'une simple attente de version.

### 3.1 Zone orange — acceptation requise

| Risque    | Libellé                                      | Résiduel | Justification du maintien                                                                                                                                                                                          | Décision      | Approbateur   | Date          |
| --------- | -------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------- | ------------- | ------------- |
| **R1**    | Interception du `user_code` en transmission  | P=2, I=3 | Le canal de transmission du `user_code` à l'opérateur est hors du produit ; l'approbation humaine sur `/device` reste requise (CE01)                                                                               | `À COMPLÉTER` | `À COMPLÉTER` | `À COMPLÉTER` |
| **R-S6**  | Compromission du bastion                     | P=2, I=3 | Réductible à I=2 par des `client_id` distincts par zone (MT30) — arbitrage entre isolation et nombre de RP à gérer                                                                                                 | `À COMPLÉTER` | `À COMPLÉTER` | `À COMPLÉTER` |
| **R-SA1** | Vol de clé de compte de service              | P=2, I=3 | Une clé de service n'est pas gouvernée par LLNG : sa révocation est un geste d'exploitation sur chaque serveur (MT20)                                                                                              | `À COMPLÉTER` | `À COMPLÉTER` | `À COMPLÉTER` |
| **R-P3**  | Corruption de la KRL, indisponibilité flotte | P=2, I=3 | Le correctif est **amont** (écriture atomique de la KRL) : mergé, non publié ; CE18 durcit le contrôle côté client sans supprimer la cause                                                                         | `À COMPLÉTER` | `À COMPLÉTER` | `À COMPLÉTER` |
| **R-P7**  | Concurrence sur le magasin de sessions       | P=2, I=3 | Défaut **systémique** amont (ni verrou ni comparaison-et-échange) : neuf courses identifiées, correctifs partiels mergés (`#87`, `#88`, `#95`), aucun publié ; le motif survit à `0.6.0` (voir le préambule du §3) | `À COMPLÉTER` | `À COMPLÉTER` | `À COMPLÉTER` |

### 3.2 Zone jaune — pour information

| Risque    | Libellé                                          | Résiduel |
| --------- | ------------------------------------------------ | -------- |
| **R4**    | Vol du fichier token après enrôlement            | P=1, I=4 |
| **R5**    | Usurpation du serveur LLNG                       | P=1, I=4 |
| **R-S4**  | Compromission de la CA SSH                       | P=1, I=4 |
| **R-SA2** | Compromission du fichier de comptes de service   | P=1, I=4 |
| **R-S8**  | Session persistante après révocation             | P=2, I=2 |
| **R-P4**  | Exposition de la clé privée de CA sur le portail | P=1, I=4 |
| **R-P6**  | Perte de l'identité machine (`_deviceId`)        | P=2, I=2 |

R4, R5, R-S4, R-SA2 et R-P4 partagent une propriété : leur vraisemblance est
très faible mais leur gravité maximale. Ce sont les points où le modèle
concentre sa confiance — la CA, le portail, les credentials d'enrôlement, les
comptes de service. Aucune mesure produit ne les ramène en gravité 3 ; ce sont
les conditions d'emploi CE13, CE15 et l'hypothèse H1 qui les tiennent.

### 3.3 Décision d'homologation

> **Décision :** `À COMPLÉTER` — homologation accordée / accordée sous réserve /
> refusée.
>
> **Réserves éventuelles :** `À COMPLÉTER`
>
> **Autorité d'homologation :** `À COMPLÉTER` (nom, fonction, signature)
>
> **Date :** `À COMPLÉTER`
>
> **Prochaine revue :** `À COMPLÉTER`

## 4. Conditions de maintien

L'homologation cesse d'être valide si l'une de ces conditions n'est plus tenue :

1. Une condition d'emploi de la section 2 n'est plus vérifiée sur la cible.
2. Le périmètre change : ajout d'un composant, changement de mode PAM, portail
   LLNG remplacé ou plugins retirés.
3. Une nouvelle fiche de risque atteint la zone orange ou rouge sans acceptation.
4. Un incident de sécurité met en défaut une hypothèse de confiance (§1.3).
5. La durée de validité est atteinte.

---

Analyse : [Atelier 1](04-atelier1-cadrage-socle.md) ·
[Atelier 2](05-atelier2-sources-de-risque.md) ·
[Atelier 3](06-atelier3-scenarios-strategiques.md) · Atelier 4
([enrôlement](01-enrollment.md), [SSH](02-ssh-connection.md)) ·
[Plan de traitement](07-plan-de-traitement.md)
