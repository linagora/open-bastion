# Atelier 4 (suite) — Risques du portail LLNG et de ses plugins

> **Méthode :** EBIOS Risk Manager, atelier 4 — scénarios opérationnels. Ce
> document complète [01-enrollment.md](01-enrollment.md) (enrôlement) et
> [02-ssh-connection.md](02-ssh-connection.md) (connexion SSH) en couvrant la
> **moitié serveur** du produit : le portail LemonLDAP::NG et les quatre plugins
> qui portent l'autorisation, l'émission de certificats et l'identité machine.
>
> Le portail et ses plugins sont **dans le périmètre d'homologation**
> ([08, §1.1](08-dossier-homologation.md#11-ce-qui-est-homologué)). Jusqu'ici
> l'étude les traitait comme une frontière de confiance, sans fiche, sans mesure
> et sans condition d'emploi : les mécanismes côté LLNG (`RequirePKCE`,
> `RtActivity`, CrowdSec, `ssh-ca`) étaient invoqués comme des acquis.

## Composants couverts

| Plugin                      | Rôle                                                            | Routes                                                                                                                                                                                  |
| --------------------------- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pam-access`                | Autorisation SSH et `sudo`, vouchers de rebond, cache offline   | `/pam/authorize`, `/pam/verify`, `/pam/bastion-cert`, `/pam/heartbeat`, `/pam/whoami` (ajouté par la PR amont `#94`), `/pam/bastion-token` (supprimé par la PR amont `#86` — voir R-P6) |
| `ssh-ca`                    | Signature des certificats utilisateur, KRL, administration      | `/ssh/sign`, `/ssh/ca`, `/ssh/revoked`, `/ssh/admin`, `/ssh/certs`, `/ssh/revoke`                                                                                                       |
| `oidc-device-authorization` | Flux RFC 8628 d'enrôlement des machines                         | `/device`, `/oauth2/device`                                                                                                                                                             |
| `oidc-device-organization`  | Identité machine (`_deviceId`), rattachement à une organisation | —                                                                                                                                                                                       |

**Version minimale requise :** `À COMPLÉTER` — à figer dans
[08-dossier-homologation.md](08-dossier-homologation.md) au moment de la
décision. Plusieurs mesures décrites ici dépendent de correctifs plugin dont
l'état est suivi dans `linagora/lemonldap-ng-plugins`.

---

## Fiches de risque

### R-P1 - Usurpation de l'appelant sur `/pam/*`

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   2   |
| **Impact**      |   4   |

**Description :** Les routes `/pam/*` n'appliquent **aucune liaison RP/audience**
sur le jeton présenté : le plugin identifie l'appelant par le jeton serveur, mais
ne vérifie pas que ce jeton a été émis pour _ce_ rôle. Quand
`pamAccessServerGroups` est vide — la configuration que
[00-architecture.md](00-architecture.md) recommande pour un projet multi-groupes
— le `server_group` est lu **dans le corps de la requête**. N'importe quel hôte
enrôlé du projet peut donc se déclarer bastion et obtenir un voucher de rebond
de 12 h pour un utilisateur.

**Vecteurs d'attaque :**

- Compromission d'un backend quelconque du projet, puis auto-déclaration en tant
  que bastion sur `/pam/authorize`
- Réutilisation du jeton serveur d'un hôte de moindre valeur (poste de test,
  machine de recette) contre les routes réservées au bastion

**Facteurs atténuants structurels :**

- L'allowlist `allowed_bastions` des backends refuse un voucher émis par un
  device-id inattendu — c'est la **défense résiduelle** de ce risque, et elle est
  vide par défaut (voir R-S23 et la condition d'emploi CE06)
- `pamAccessBastionCertPinSourceAddress` épingle l'adresse source du certificat
  de rebond — **désactivé par défaut**, et jusqu'à
  `linagora/lemonldap-ng-plugins#56` il était **silencieusement omis** quand
  l'adresse observée était absente ou hors format (IPv6 avec zone, par
  exemple) : le certificat partait non épinglé, sans erreur, alors que
  l'administrateur croyait la propriété en vigueur
- Le voucher est borné par `pamAccessBastionVoucherTtl` (12 h par défaut)

**Remédiation configuration :**

1. **Renseigner `pamAccessServerGroups`** (mapping d'autorité `client_id →
server_group`) : le `server_group` cesse alors d'être une donnée d'entrée.
   C'est la mesure directe (condition d'emploi CE03).
2. **Renseigner `allowed_bastions`** sur chaque backend (CE06).
3. **Activer `pamAccessBastionCertPinSourceAddress`**.

**Remédiation plugin (amont) :** liaison d'audience sur les jetons `/pam/*`
et refus d'un `server_group` auto-déclaré. Suivie dans
`linagora/lemonldap-ng-plugins#50` ; **corrigée en amont**, non publiée à ce
jour, par la PR amont `#92`, qui associe une allowlist de RP (`pamAccessAllowedRps`)
au refus du groupe auto-déclaré, une allowlist vide valant « pas de changement »
pour ne pas rompre la montée de version. Le correctif n'agit donc que si
l'exploitant renseigne cette allowlist, ce qui suppose d'enrôler les bastions
sous un `client_id` distinct de celui du projet — la mesure reste une
**configuration**, pas un acquis de la mise à jour.

Deux effets de bord de la PR amont `#86` (issues `#55`, `#56`) touchent
directement cette fiche, sans changer le score :

- un voucher qu'**aucune empreinte** ne lie au certificat SSO de l'utilisateur
  est désormais plafonné à `pamAccessBastionVoucherUnboundTtl` (900 s) au lieu
  des 12 h, ce qui réduit d'autant la fenêtre d'un backend qui se déclare
  bastion **sans** présenter d'empreinte — un attaquant qui fournit l'empreinte
  publique de sa victime reste, lui, dans le cas lié ;
- l'émission est refusée (403, audit `PAM_BASTION_CERT_PIN_UNAVAILABLE`) quand
  le pin est activé et l'adresse inutilisable, ce qui rend la mesure 3 fiable
  au lieu de silencieusement inopérante.

Aucun de ces correctifs n'est publié à ce jour : le score résiduel ci-dessous
suppose toujours la configuration côté exploitant (CE03 + CE06 + CE21).

**Depuis `0.7.0`, cette configuration n'est plus une hypothèse : c'est un
prérequis de publication.** Le comportement par défaut du produit — `allowed_bastions`
vide vaut « accepter n'importe lequel », `pamAccessServerGroups` vide fait lire
le `server_group` dans la requête — contredit la configuration multi-groupes que
[00-architecture.md](00-architecture.md) recommande. Un défaut livré qui
contredit l'architecture recommandée n'est pas un risque résiduel acceptable :
c'est une condition de mise en service. CE03, CE06, CE16 et CE21 sont donc
déclarées **bloquantes** en
[08, §2](08-dossier-homologation.md#2-conditions-demploi).

Le produit ne peut ni poser ni vérifier les trois premières : ce sont des
réglages du Manager LLNG, et les lire depuis un hôte supposerait une API qui
publierait les bastions, les groupes de serveurs et les RP du projet. La seule
application possible est déclarative — `ob-bastion-setup`, `ob-backend-setup`,
`ob-desktop-setup` et `ob-post-upgrade` impriment la consigne à chaque
exécution, et `ob-builder` écrit à côté de chaque artefact une
`PORTAL-CHECKLIST.md` pré-remplie avec le `client_id` et le `server_group` du
déploiement. C'est une notification, pas un contrôle, et la fiche ne prétend
pas l'inverse.

|                 |                                   Score résiduel                                   |
| --------------- | :--------------------------------------------------------------------------------: |
| **Probabilité** |       1 (suppose la compromission préalable d'un hôte enrôlé du même projet)       |
| **Impact**      | 3 (borné à la zone du `client_id` avec CE03 + CE06 ; sans elles, l'impact reste 4) |

---

### R-P2 - Révocation non autorisée de certificats (`ssh-ca`)

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   3   |
| **Impact**      |   3   |

**Description :** Les routes `/ssh/admin`, `/ssh/certs` et `/ssh/revoke` du
plugin `ssh-ca` sont enregistrées en `addAuthRoute` : le cœur LLNG exige une
session SSO valide et **rien d'autre**. Le plugin n'effectue aucun contrôle
d'autorisation — son propre commentaire renvoie aux `locationRules`. Tout compte
SSO authentifié peut donc lister l'intégralité des certificats émis
(énumération : identités, empreintes, identifiants de session) et **révoquer
ceux de n'importe qui**.

**Conséquence :** panne SSH à l'échelle de l'organisation, en une requête, par
un compte sans privilège particulier.

**Vecteurs d'attaque :**

- Compte utilisateur ordinaire compromis (hameçonnage) → révocation de masse
- Utilisateur légitime malveillant (SR3) cherchant à provoquer une indisponibilité

**Facteurs atténuants structurels :** aucun côté plugin. La seule mesure est une
`locationRules` sur le vhost du portail, évaluée par le cœur LLNG avant le
dispatch de route.

**Remédiation configuration :**

```
^/ssh/(admin|certs|revoke)(\?|/|$)   →   $groups =~ /\bob-ssh-admins\b/
```

Attention à ne pas écrire `^/ssh/revoke` seul : cela capture aussi
`/ssh/revoked`, la KRL **publique** que chaque backend télécharge — la
restreindre casserait la propagation des révocations. Voir
la section « Step 3b » de [doc/llng-configuration.md](../llng-configuration.md)
et la condition d'emploi CE02.

**Remédiation plugin (amont) :** contrôle d'autorisation intégré, par défaut
refus tant qu'une règle dédiée n'est pas configurée. `#58` est **corrigée en
amont** : `/ssh/admin`, `/ssh/certs` et `/ssh/revoke` répondent 403 tant que
`sshCaAdminRule` n'est pas renseignée. Le correctif n'est pas encore publié, et
la `locationRules` reste la mesure applicable en attendant — elle garde par
ailleurs son intérêt en défense en profondeur.

|                 |                           Score résiduel                           |
| --------------- | :----------------------------------------------------------------: |
| **Probabilité** |      1 (avec la `locationRules` déployée et vérifiée — CE02)       |
| **Impact**      | 3 (une révocation de masse reste une indisponibilité de la flotte) |

---

### R-P3 - Corruption de la KRL et indisponibilité de la flotte

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   2   |
| **Impact**      |   4   |

**Description :** Les écritures de la KRL par `ssh-ca` sont sérialisées entre
générateurs — `_updateKrl` prend un `flock(LOCK_EX)` sur `<sshCaKrlPath>.lock`
autour de tout le lire-modifier-écrire depuis la PR amont `#13` — mais elles ne
sont **pas atomiques** : `ssh-keygen -u` réécrit le fichier en place. Deux
chemins échappent en outre à ce verrou dans la version publiée : les **lecteurs**
(`/ssh/revoked` et le téléchargement côté open-bastion, qui ne prennent aucun
verrou) et le script cron `sshca-rebuild-krl`, qui réécrit le fichier sans
passer par le verrou du portail. Une KRL tronquée mais dont l'en-tête reste valide est servie telle
quelle ; elle franchit le contrôle de plausibilité d'open-bastion
(`head -c 6 | grep SSHKRL`), est déployée en `RevokedKeys`, et **`sshd` échoue
alors fermé sur toutes les clés**. Le comportement a été reproduit.

**Conséquence :** perte d'accès SSH sur l'ensemble des serveurs qui ont
rafraîchi la KRL — c'est le mécanisme de révocation qui devient le vecteur
d'indisponibilité. Recoupe R-S17 (verrouillage total).

**Vecteurs :**

- Deux révocations concurrentes, ou une révocation pendant un téléchargement
- Disque plein ou processus tué côté portail pendant l'écriture

**Facteurs atténuants structurels :**

- Le contrôle de plausibilité côté client rejette une KRL vide ou sans magie —
  mais pas une KRL tronquée après l'en-tête
- Le compte de service de secours et l'accès console hors-bande (CE12) restent
  le filet

**Remédiation plugin (amont) :** écriture atomique (fichier temporaire dans le
répertoire cible + `rename()`), verrou partagé pris par les lecteurs, extension
du verrou existant au cron `sshca-rebuild-krl`, et refus de servir une KRL que
`ssh-keygen` ne relit pas. `#59` est **corrigée en amont** par la PR `#77`, non
publiée à ce jour ; la mesure côté open-bastion ci-dessous reste
donc la seule effective, et garde de toute façon sa valeur (elle couvre aussi
une KRL corrompue en transit ou au stockage, hors du périmètre du correctif).

**Remédiation configuration (côté open-bastion) :** durcir le contrôle de
plausibilité avant déploiement — vérifier que `ssh-keygen -Q -l -f` accepte le
fichier, et non seulement la présence de la magie, avant de remplacer
`RevokedKeys`.

|                 |                               Score résiduel                                |
| --------------- | :-------------------------------------------------------------------------: |
| **Probabilité** | 2 (le correctif est amont ; le contrôle client ne couvre pas la troncature) |
| **Impact**      |   3 (recouvrement par compte de secours + console, sous réserve de CE12)    |

---

### R-P4 - Exposition de la clé privée de CA sur le portail

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   2   |
| **Impact**      |   4   |

**Description :** Deux expositions cumulées. D'une part la clé privée de la CA
SSH est stockée **en clair** dans la configuration LLNG : l'accès en lecture à
cette configuration équivaut à la possession de la CA. D'autre part, la
signature d'un certificat écrit la clé dans un répertoire temporaire créé avec
`tempdir(CLEANUP => 1)`, qui n'est nettoyé qu'à la **sortie du processus** : un
worker de portail à longue durée de vie accumule un répertoire `/tmp` contenant
la clé non chiffrée **par signature**.

**Conséquence :** compromission de la CA (R-S4, gravité 4) — l'attaquant signe
des certificats pour n'importe quel utilisateur.

**Vecteurs :**

- Lecture de `/tmp` sur l'hôte du portail par un compte local non privilégié
- Accès en lecture à la configuration LLNG (Manager, sauvegarde, réplication)

**Facteurs atténuants structurels :**

- L'hôte du portail est censé être dédié et durci — c'est l'hypothèse de
  confiance H1 de [08, §1.3](08-dossier-homologation.md#13-hypothèses-de-confiance)
- La CA seule ne suffit pas : `/pam/authorize` autorise séparément

**Remédiation plugin (amont) :** nettoyage du répertoire temporaire en fin de
signature, ou signature sans passage par le disque. `#60` est **corrigée en
amont**, non publiée à ce jour. Elle ne réduit pas ce risque au-delà de la
fenêtre d'exposition sur disque : la clé reste en clair dans la configuration
LLNG, et c'est ce qui fixe l'impact 4.

**Remédiation configuration :** restreindre et tracer l'accès au Manager LLNG et
à l'hôte du portail (condition d'emploi CE13) ; à terme, HSM ou service de
signature dédié.

|                 |                              Score résiduel                               |
| --------------- | :-----------------------------------------------------------------------: |
| **Probabilité** |       1 (suppose un accès local à l'hôte du portail — hypothèse H1)       |
| **Impact**      | 4 (la compromission de la CA n'est pas réductible : elle signe pour tous) |

---

### R-P5 - Approbation d'enrôlement par un utilisateur non habilité

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   3   |
| **Impact**      |   3   |

**Description :** Avec `oidcRPMetaDataOptionsAllowDeviceAuthorization = 1`, le
plugin saute la branche de règle : **tout utilisateur SSO authentifié** peut
approuver ou refuser un enrôlement de machine en attente. La valeur `1` n'est pas
une permission, c'est l'absence de restriction. La « two-person rule » sur
laquelle l'étude fait reposer R0 et R7 est une convention de configuration.

**Conséquence :** une machine contrôlée par l'attaquant entre dans le parc avec
des identités et des autorisations (ER7).

**Facteurs atténuants structurels :**

- L'approbation reste un geste **humain** : elle n'est pas automatisable par
  l'attaquant seul, il lui faut un compte SSO
- Le `user_code` doit être connu, donc le flux d'enrôlement doit avoir été initié

**Remédiation configuration :**

```
^/device   →   $groups =~ /\bob-approvers\b/
```

Ne pas ancrer la fin (`^/device$`) : `grant()` compare à `REQUEST_URI`, qui porte
la query string. Condition d'emploi CE01.

**Remédiation plugin (amont) :** documenter que `1` signifie « tout utilisateur
authentifié » et proposer une règle dédiée. `#74` est **corrigée en amont**
(documentation), non publiée à ce jour. C'est une clarification : elle ne
substitue pas de contrôle à la `locationRules`, qui reste la mesure.

|                 |                        Score résiduel                         |
| --------------- | :-----------------------------------------------------------: |
| **Probabilité** |    1 (avec la `locationRules` déployée et vérifiée — CE01)    |
| **Impact**      | 3 (un serveur illégitime enrôlé reste un point d'observation) |

---

### R-P6 - Perte de l'identité machine (`_deviceId`)

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   2   |
| **Impact**      |   3   |

**Description :** Le plugin `oidc-device-organization` construit une session
synthétique pour porter l'identité de la machine (`_deviceId`). En cas d'échec de
cette construction, il retourne `PE_OK` : l'hôte obtient alors un jeton dont le
sujet est l'**administrateur approbateur** et qui ne porte **aucun identifiant de
device**. Le plugin qui porte ce mécanisme n'avait par ailleurs aucun test au
moment de l'analyse.

**Conséquence :** perte d'imputabilité côté portail — les appels `/pam/*` de cet
hôte sont attribués à un humain ; le heartbeat et les mécanismes qui s'appuient
sur le device-id (allowlist `allowed_bastions`, révocation par machine) perdent
leur point d'ancrage.

**Facteurs atténuants structurels :**

- L'hôte reste authentifié : ce n'est pas un contournement d'authentification
  mais une perte d'attribution
- `ob-bastion-id` permet de constater l'absence de device-id après enrôlement —
  mais l'endpoint dont il dépend (`/pam/bastion-token`) est supprimé par la PR
  amont `#86`, **mergée**, et son remplaçant `POST /pam/whoami` l'est aussi
  (PR amont `#94`) ; la migration côté open-bastion est faite dans
  [#248](https://github.com/linagora/open-bastion/pull/248), qui bascule
  `ob-bastion-id` sur le nouvel endpoint avec repli sur l'ancien tant que le
  portail n'a pas migré. Ce facteur atténuant survit donc à la mise à jour du
  portail, à condition de déployer cette version d'`ob-bastion-id` **avant** de
  mettre le portail à jour (voir `UPGRADE-NOTES.md`)

**Remédiation opérationnelle :** vérifier `ob-bastion-id` après chaque
enrôlement et refuser un hôte sans device-id ; surveiller les jetons serveur
dont le sujet est un compte humain.

**Remédiation plugin (amont) :** échec fermé en cas d'échec de la session
synthétique, et couverture de tests. Les deux sont **corrigées en amont, non
publiées** : `#72` par la PR `#80`, et `#71` par le commit `2e5e4c4`, arrivé sur
`main` via la PR `#90` — le plugin porte désormais `t/38-Device-Organization.t`
(PR `#80`) et `t/39-Device-Organization-Identity.t`. La probabilité résiduelle
reste à 2 pour la même raison que R-P3 et R-P7, et pour elle seule : **rien
n'est publié**, et la vérification manuelle d'`ob-bastion-id` après enrôlement
(CE19) est le seul contrôle dont dispose un exploitant aujourd'hui.

|                 |                              Score résiduel                               |
| --------------- | :-----------------------------------------------------------------------: |
| **Probabilité** |   2 (le correctif est amont ; seule la vérification manuelle l'atténue)   |
| **Impact**      | 2 (perte d'attribution et d'ancrage, sans gain d'accès pour un attaquant) |

---

### R-P7 - Concurrence sur le magasin de sessions partagé (défaut systémique)

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   2   |
| **Impact**      |   3   |

**Description :** Ceci n'est pas un défaut isolé mais un **motif** : **neuf**
courses lecture-modification-écriture ont été identifiées à travers les deux
dépôts — limiteur de débit, verrouillage du cache offline, consommation d'OTP,
vouchers, certificats éphémères, `device_code`, statut de device, `_sshCerts`,
KRL — sur des magasins qui n'offrent aucune atomicité. `Common::Session->update` réécrit
l'intégralité du blob de session sans comparaison-et-échange, et les backends de
session utilisent `Lock::Null`. Deux écritures concurrentes sur la même session
ne se sérialisent pas : la dernière gagne, silencieusement.

**Conséquence :** l'écriture d'un certificat éphémère par `pam-access` peut
écraser une révocation écrite par `ssh-ca` — un **fail-open silencieux** sur un
mécanisme de sécurité. Le bug de rotation de voucher déjà rencontré en production
(logins SSH concurrents se cassant mutuellement) relève du même motif.

**Vecteurs :**

- Connexions SSH concurrentes du même utilisateur (cas nominal sur un bastion)
- Révocation concurrente d'une signature de certificat

**Facteurs atténuants structurels :**

- La fenêtre est étroite (millisecondes) et non déclenchable à volonté par un
  attaquant sans accès au portail
- Les effets observés jusqu'ici étaient des refus (fail-closed) plus souvent que
  des acceptations

**Remédiation plugin (amont) :** verrouillage réel du magasin de sessions, ou
mises à jour par champ avec comparaison-et-échange. Suivie dans
`linagora/lemonldap-ng-plugins#54`, `#66`, `#68` et `#69`. `#69` est **corrigée
en amont** ; `#54` et `#66` (une clé de session par enregistrement au lieu d'un
blob partagé) sont traitées par la PR amont `#87`, `#53` et `#68` (consommation
réellement atomique des jetons à usage unique) par la PR amont `#88`, et la PR
amont `#95` va plus loin en donnant à chaque voucher son propre enregistrement
de session plutôt qu'une clé dans un blob réécrit en entier — les trois
**mergées, non publiées**. Le motif de fond, lui, ne disparaît pas : les correctifs
suppriment des courses identifiées, ils ne rendent pas le magasin atomique.

**Remédiation architecturale :** traiter le motif comme tel — toute nouvelle
écriture dans la session persistante doit être conçue comme idempotente et
tolérante à l'écrasement, tant que le magasin ne fournit pas d'atomicité.

|                 |                               Score résiduel                               |
| --------------- | :------------------------------------------------------------------------: |
| **Probabilité** |    2 (correctifs amont mergés, non publiés ; le motif reste structurel)    |
| **Impact**      | 3 (un écrasement peut annuler une révocation — fail-open sur une garantie) |

---

### R-P8 - Déni de service authentifié sur `ssh-ca`

|                 | Score |
| --------------- | :---: |
| **Probabilité** |   2   |
| **Impact**      |   3   |

**Description :** `/ssh/sign` n'a pas de limitation de débit ; la KRL croît sans
borne et son coût de réécriture est superlinéaire. Un compte SSO ordinaire peut
donc, à faible coût, dégrader puis rendre indisponible l'émission de certificats
pour toute l'organisation.

**Facteurs atténuants structurels :**

- L'attaquant doit disposer d'un compte SSO valide (donc traçable)
- La dégradation est progressive et observable (temps de réponse du portail)

**Remédiation configuration :** limitation de débit au niveau du reverse proxy
devant le portail ; surveillance de la taille de la KRL et du temps de signature.

**Remédiation plugin (amont) :** borner `/ssh/sign`. Suivie dans
`linagora/lemonldap-ng-plugins#63` ; **corrigée en amont**, non publiée à ce
jour, par la PR amont `#90` : `sshCaSignMaxPerHour` (20/h, **429**) et
`sshCaMaxCertsPerUser` (20, **409**), comptés dans la session de l'utilisateur.

La KRL, elle, n'est **délibérément pas plafonnée** en amont : refuser
d'enregistrer une révocation parce que le fichier est devenu gros serait un
fail-open silencieux — le certificat resterait utilisable. Borner les deux
entrées borne la KRL sans jamais perdre une révocation. Il n'y a donc **aucune
purge d'entrées expirées à attendre de l'amont**, et la limitation obtenue est
celle du plugin, pas celle du reverse proxy que suppose CE17 : la remédiation
configuration ci-dessus reste entièrement à la charge de l'exploitant (MT49).

|                 |                            Score résiduel                            |
| --------------- | :------------------------------------------------------------------: |
| **Probabilité** |    1 (avec limitation de débit au reverse proxy et surveillance)     |
| **Impact**      | 2 (dégradation détectable, sans perte d'accès aux sessions ouvertes) |

---

## Matrice des risques du portail

### Avant remédiation

| Impact ↓ / Probabilité → | 1 - Très improbable | 2 - Peu probable | 3 - Probable | 4 - Très probable |
| ------------------------ | ------------------- | ---------------- | ------------ | ----------------- |
| **4 - Critique**         |                     | R-P1 R-P3 R-P4   |              |                   |
| **3 - Important**        |                     | R-P6 R-P7 R-P8   | R-P2 R-P5    |                   |
| **2 - Limité**           |                     |                  |              |                   |
| **1 - Négligeable**      |                     |                  |              |                   |

### Après remédiation

| Impact ↓ / Probabilité → | 1 - Très improbable | 2 - Peu probable | 3 - Probable | 4 - Très probable |
| ------------------------ | ------------------- | ---------------- | ------------ | ----------------- |
| **4 - Critique**         | R-P4                |                  |              |                   |
| **3 - Important**        | R-P1 R-P2 R-P5      | R-P3 R-P7        |              |                   |
| **2 - Limité**           | R-P8                | R-P6             |              |                   |
| **1 - Négligeable**      |                     |                  |              |                   |

**Ce que cette matrice dit et que les autres ne disaient pas :** **cinq** des
huit risques du portail dépendent d'une **configuration** que le produit ne pose
pas lui-même (R-P1, R-P2, R-P5, R-P8 et, pour partie, R-P4). Pour R-P8, la
descente de (2,3) à (1,2) suppose la limitation de débit au reverse proxy et la
surveillance de la taille de la KRL — CE17 et MT49, toutes deux `À COMPLÉTER` :
sa zone verte est conditionnelle, exactement comme celle de R-P1 l'est via
CE03. Deux restent en zone orange
et sont portés à l'acceptation formelle en
[08, §3.1](08-dossier-homologation.md#31-zone-orange--acceptation-requise) :
R-P3 (corruption de la KRL) et R-P7 (concurrence sur le magasin de sessions).

**État des correctifs amont au 6 septembre 2026.** L'analyse a été menée contre
le code publié ; depuis, l'amont a bougé, et il a fini de bouger. Les **quinze**
tickets référencés par ces fiches sont **tous fermés et mergés** dans
`linagora/lemonldap-ng-plugins`. L'inventaire est donné en entier, parce que
c'est lui qui fonde l'acceptation formelle en
[08, §3.1](08-dossier-homologation.md#31-zone-orange--acceptation-requise) et
qu'un relecteur doit pouvoir le refaire :

| Ticket amont | Fiche | Fermé par                                |
| ------------ | ----- | ---------------------------------------- |
| `#50`        | R-P1  | PR `#92`                                 |
| `#53`        | R-P7  | PR `#88`                                 |
| `#54`        | R-P7  | PR `#87`                                 |
| `#55`        | R-P1  | PR `#86`                                 |
| `#56`        | R-P1  | PR `#86`                                 |
| `#58`        | R-P2  | PR `#76`                                 |
| `#59`        | R-P3  | PR `#77`                                 |
| `#60`        | R-P4  | PR `#78`                                 |
| `#63`        | R-P8  | PR `#90`                                 |
| `#66`        | R-P7  | PR `#87`                                 |
| `#68`        | R-P7  | PR `#88`                                 |
| `#69`        | R-P7  | PR `#80`                                 |
| `#71`        | R-P6  | commit `2e5e4c4`, arrivé via la PR `#90` |
| `#72`        | R-P6  | PR `#80`                                 |
| `#74`        | R-P5  | PR `#80`                                 |

Le tour d'audit complet couvre les PR `#76` à `#95`.

> **Sur `#71` en particulier.** La PR `#91` porte bien ce correctif, mais sa
> branche de base est `fix/sshca-rate-limit`, pas `main` : elle a été mergée
> dans cette branche intermédiaire, et c'est la PR `#90` qui a amené le commit
> sur `main`. Elle n'a par ailleurs livré qu'un fichier de tests — `t/38` vient
> de la PR `#80`.

**Aucun n'est publié** — la dernière version étiquetée est `v0.5.2`, ces
correctifs sortiront en `0.6.0` — donc **aucun score de cette matrice ne
change** : elle décrit ce qu'un exploitant peut déployer aujourd'hui. Trois
conséquences pratiques :

- l'acceptation de R-P3 et R-P7 porte désormais sur un **délai de publication**,
  pas sur l'absence de correctif — ce qui est une décision différente, et plus
  facile à prendre ;
- la mise à jour du portail qui apportera ces correctifs apporte aussi des
  **ruptures** : `/pam/bastion-token` disparaît (voir R-P6, traité par
  [#248](https://github.com/linagora/open-bastion/pull/248)), un voucher non
  lié à une empreinte tombe de 12 h à 15 min, le scope PAM est désormais
  comparé à l'identique (un RP portant `pam-prod` perd `/pam/*`), et
  `/ssh/admin`, `/ssh/certs` et `/ssh/revoke` refusent tant que
  `sshCaAdminRule` n'est pas renseignée. Cette montée de version doit être
  planifiée, pas subie : la marche à suivre est dans `UPGRADE-NOTES.md` ;
- deux correctifs amont **ouvrent des mesures que le produit ne prend pas
  encore**. `pamAccessAllowedRps` (`#92`) ne mord que si l'exploitant le
  renseigne, ce qui suppose un `client_id` propre aux bastions ; et la
  vérification de signature de requête (`#93`) ne peut pas être portée à
  `required`, parce que le client ne signe que deux des six endpoints `/pam/*`
  — `/pam/heartbeat` en particulier, ce qui ferait tomber la flotte entière
  quelques heures après le basculement, à l'expiration des jetons en main.
  Suivi dans [#247](https://github.com/linagora/open-bastion/issues/247).

---

Atelier 4 (suite) : [enrôlement](01-enrollment.md) ·
[connexion SSH](02-ssh-connection.md) · Traitement :
[07-plan-de-traitement.md](07-plan-de-traitement.md) · Décisions :
[08-dossier-homologation.md](08-dossier-homologation.md)
