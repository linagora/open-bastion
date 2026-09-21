.. _atelier-3--écosystème-et-scénarios-stratégiques:

Atelier 3 — Écosystème et scénarios stratégiques
================================================

   **Méthode :** EBIOS Risk Manager (ANSSI, 2018), atelier 3. On cartographie les parties prenantes de l'écosystème et leur niveau de menace, puis on construit les **scénarios stratégiques** : les chemins de haut niveau par lesquels une source de risque atteint son objectif. Les chemins techniques détaillés sont l'objet de l'atelier 4 (:doc:`enrôlement </security/01-enrollment>`, :doc:`connexion SSH </security/02-ssh-connection>`).

.. _31-cartographie-de-lécosystème:

3.1 Cartographie de l'écosystème
--------------------------------

Le niveau de menace d'une partie prenante combine sa **dépendance** (à quel point le système en dépend), sa **pénétration** (l'accès dont elle dispose), sa **maturité** cyber et sa **confiance**. Échelle : 1 (faible) à 4 (élevé) pour dépendance et pénétration ; 1 (faible) à 4 (élevée) pour maturité et confiance.

+---------------------------------------------------------+------------+-------------+----------+-----------+------------------+
| Partie prenante                                         | Dépendance | Pénétration | Maturité | Confiance | Niveau de menace |
+=========================================================+============+=============+==========+===========+==================+
| **Portail LLNG** (et son exploitant)                    | 4          | 4           | 3        | 4         | **Élevé**        |
+---------------------------------------------------------+------------+-------------+----------+-----------+------------------+
| Annuaire LDAP/AD amont                                  | 4          | 3           | 3        | 4         | Moyen            |
+---------------------------------------------------------+------------+-------------+----------+-----------+------------------+
| Administrateurs internes                                | 3          | 4           | 3        | 3         | **Élevé**        |
+---------------------------------------------------------+------------+-------------+----------+-----------+------------------+
| Prestataires d'infogérance                              | 2          | 3           | 2        | 2         | **Élevé**        |
+---------------------------------------------------------+------------+-------------+----------+-----------+------------------+
| Automatisations (Ansible, CI/CD)                        | 3          | 3           | 2        | 3         | Moyen            |
+---------------------------------------------------------+------------+-------------+----------+-----------+------------------+
| Éditeur / chaîne d'approvisionnement (paquets ``.deb``) | 3          | 2           | 3        | 3         | Moyen            |
+---------------------------------------------------------+------------+-------------+----------+-----------+------------------+
| Hébergeur / fournisseur d'infrastructure                | 3          | 2           | 3        | 3         | Faible           |
+---------------------------------------------------------+------------+-------------+----------+-----------+------------------+
| Postes de travail des administrateurs                   | 3          | 3           | 2        | 2         | **Élevé**        |
+---------------------------------------------------------+------------+-------------+----------+-----------+------------------+

Quatre parties prenantes ressortent en niveau élevé, et ce sont celles que les scénarios stratégiques suivent : le portail (autorité), les administrateurs (accès légitime), les prestataires (accès légitime borné, maturité plus faible) et leurs postes de travail (le maillon que le bastion ne contrôle pas).

.. mermaid::

   flowchart LR
       Poste["Poste admin<br/>(menace élevée)"] --> Bastion
       Presta["Prestataire<br/>(menace élevée)"] --> Bastion
       Admin["Admin interne<br/>(menace élevée)"] --> Bastion
       Auto["Automatisation<br/>(menace moyenne)"] -.clé de service.-> Backend
       LLNG["Portail LLNG<br/>(menace élevée — autorité)"] -->|CA, autorisation, voucher| Bastion
       LLNG -->|autorisation, token sudo| Backend
       LDAP["Annuaire<br/>(menace moyenne)"] --> LLNG
       Bastion["Bastion<br/>point de passage enregistré"] --> Backend["Backends"]
       Paquet["Chaîne APT<br/>(menace moyenne)"] -.paquets signés.-> Bastion
       Paquet -.-> Backend

.. _32-scénarios-stratégiques:

3.2 Scénarios stratégiques
--------------------------

Chaque scénario relie un couple SR/OV de :doc:`l'atelier 2 </security/05-atelier2-sources-de-risque>` à un événement redouté de :doc:`l'atelier 1 </security/04-atelier1-cadrage-socle>`, en passant par des parties prenantes. La gravité est celle de l'ER atteint.

.. _security-06-atelier3-scenarios-strategiques-ss1--rebond-depuis-un-poste-dadministrateur-compromis:

SS1 — Rebond depuis un poste d'administrateur compromis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**SR2 × OV1 → ER1.** L'attaquant compromet le poste de travail d'un administrateur (hameçonnage, chaîne logicielle du poste), y récupère le matériel d'authentification SSH, et se présente au bastion comme cet administrateur.

**Parties prenantes traversées :** poste admin → bastion → backends.

**Ce que l'architecture oppose :** la clé seule ne suffit pas — il faut un certificat signé par la CA LLNG, de durée bornée, révocable par KRL ; le portail réautorise à chaque connexion et l'empreinte de la clé est liée à la session SSO. La session est enregistrée sur le bastion.

**Ce qu'elle n'oppose pas :** si le poste est compromis pendant que le certificat est valide, l'attaquant est cet administrateur. Le contrôle se déplace vers la détection (enregistrement, ``auth.info``) et la révocation.

**Gravité : 4.** Fiches détaillées : R-S3, R-S6, R-S11, R-S22.

.. _ss2--compromission-du-bastion-lui-même:

SS2 — Compromission du bastion lui-même
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**SR2 × OV1 → ER1, ER3, ER4.** Le bastion est le point de passage : qui le contrôle voit passer toutes les sessions et peut demander des certificats de rebond au nom des utilisateurs déjà vouchés.

**Parties prenantes traversées :** bastion → portail LLNG → backends.

**Ce que l'architecture oppose :** le bastion ne détient pas la CA ; il ne peut obtenir un certificat de rebond que pour un utilisateur ayant récemment ouvert une session sur lui (voucher), pour la durée ``pamAccessBastionVoucherTtl`` ; les backends n'acceptent que les bastions de leur ``allowed_bastions`` et le certificat est épinglé sur l'adresse source du bastion.

**Ce qu'elle n'oppose pas :** l'enregistrement de session vit sur le bastion. Root du bastion est hors périmètre de confiance de la traçabilité — c'est une hypothèse explicite, pas une protection.

**Gravité : 4.** Fiches détaillées : R-S6, R-S9, R-S22, R-S23.

.. _ss3--enrôlement-dun-serveur-sous-contrôle-de-lattaquant:

SS3 — Enrôlement d'un serveur sous contrôle de l'attaquant
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**SR2 × OV6 → ER7.** L'attaquant obtient (ou devine, ou intercepte) de quoi enrôler une machine à lui dans le parc : elle reçoit alors des identités, des autorisations, et devient un point d'observation légitime.

**Parties prenantes traversées :** chaîne APT ou credentials d'enrôlement → portail LLNG (``/device``) → parc.

**Ce que l'architecture oppose :** le flux RFC 8628 exige une approbation humaine sur le portail, PKCE rend l'interception du ``device_code`` inutile, CrowdSec limite le brute-force du ``user_code``, et le ``client_secret`` est cloisonnable par zone.

**Ce qu'elle n'oppose pas sans configuration :** l'approbation ``/device`` est ouverte à **tout utilisateur SSO authentifié** tant qu'une ``locationRules`` ne la restreint pas. C'est une **condition d'emploi**, pas une propriété du produit (voir :doc:`/security/08-dossier-homologation`).

**Gravité : 3.** Fiches détaillées : R0, R1, R2, R3, R7, R13.

.. _ss4--administrateur-légitime-agissant-hors-traçabilité:

SS4 — Administrateur légitime agissant hors traçabilité
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**SR3 × OV3 → ER3.** L'administrateur habilité cherche à agir sans que son action soit imputable : contourner le bastion, s'évader du confinement de session, ou différer l'action hors de la session enregistrée.

**Parties prenantes traversées :** admin interne → bastion → backends.

**Ce que l'architecture oppose :** le contournement du bastion est bloqué par ``AuthorizedKeysFile none`` + ``TrustedUserCAKeys`` + ``AuthorizedPrincipalsCommand`` sur les backends ; l'enregistrement est écrit par un puits root auquel l'utilisateur enregistré n'a aucun accès ; le confinement de session et la trace auditd ferment l'évasion et l'action différée.

**Ce qu'elle n'oppose que sous condition :** le confinement (``--enable-hardening``) et la trace auditd (``--enable-audit-trace``) sont **opt-in**. Sans eux, R-S19 à R-S21 restent en zone jaune.

**Gravité : 3.** Fiches détaillées : R-S5, R-S18, R-S19, R-S20, R-S21, R-S25.

.. _ss5--persistance-dun-prestataire-après-la-fin-de-sa-mission:

SS5 — Persistance d'un prestataire après la fin de sa mission
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**SR5 × OV2 → ER2.** L'intervenant garde un moyen d'accès qui survit à la clôture de son compte : session ouverte, certificat encore valide, clé de compte de service qu'il a installée.

**Parties prenantes traversées :** prestataire → portail LLNG → parc.

**Ce que l'architecture oppose :** l'autorisation est revérifiée en direct à chaque connexion et à chaque ``sudo``, donc la désactivation du compte LLNG coupe l'accès immédiatement ; la KRL révoque les certificats ; l'empreinte de la clé est liée à la session SSO.

**Ce qu'elle n'oppose pas :** une session déjà ouverte survit jusqu'à sa fermeture (R-S8), et une clé de **compte de service** n'est pas gouvernée par LLNG du tout — sa révocation est une modification de fichier sur chaque serveur.

**Gravité : 3.** Fiches détaillées : R12, R-S8, R-S15, R-SA1 ; procédure en :doc:`/security/03-offboarding`.

.. _ss6--détournement-dune-clé-dautomatisation:

SS6 — Détournement d'une clé d'automatisation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**SR6 × OV1 → ER1.** Une clé de compte de service — Ansible, sauvegarde, CI — fuit (dépôt, artefact de build, sauvegarde) et donne un accès privilégié permanent qui ne passe par aucune porte SSO.

**Parties prenantes traversées :** automatisation → backends.

**Ce que l'architecture oppose :** le fichier ``service-accounts.conf`` est local à chaque serveur (portée bornée), root-only, et l'empreinte de la clé est vérifiée ; avec ``sudo_nopasswd = false``, l'empreinte est revérifiée à chaque ``sudo``.

**Ce qu'elle n'oppose pas :** le droit ``sudo`` d'un compte de service ne passe pas par LLNG, même en Mode E. C'est un privilège local permanent, assumé et tracé.

**Gravité : 4.** Fiches détaillées : R-S24, R-S25, R-SA1, R-SA2.

.. _security-06-atelier3-scenarios-strategiques-ss7--verrouillage-total-par-erreur-dexploitation:

SS7 — Verrouillage total par erreur d'exploitation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**SR4 × OV5 → ER5.** Une erreur — panne prolongée du portail, cache offline expiré, certificats expirés, aucun compte de secours — rend le parc inaccessible. La source de risque n'a aucune intention : c'est le scénario que la sécurité elle-même crée.

**Parties prenantes traversées :** portail LLNG → bastion et backends.

**Ce que l'architecture oppose :** cache d'autorisation offline, comptes de service de secours, accès console hors-bande documenté, rafraîchissement du token serveur à la demande.

**Ce qu'elle n'oppose pas :** un déploiement sans compte de secours ni accès console **n'est pas récupérable**. C'est une condition d'emploi.

**Gravité : 3.** Fiches détaillées : R6, R9, R10, R-S7, R-S10, R-S14, R-S17.

.. _33-synthèse:

3.3 Synthèse
------------

+----------+--------------+------------+---------+----------------------------------------------------------+
| Scénario | Couple SR/OV | ER atteint | Gravité | Zone de traitement                                       |
+==========+==============+============+=========+==========================================================+
| **SS1**  | SR2 × OV1    | ER1        | 4       | Certificats courts + KRL + binding d'empreinte           |
+----------+--------------+------------+---------+----------------------------------------------------------+
| **SS2**  | SR2 × OV1    | ER1/3/4    | 4       | Voucher borné, ``allowed_bastions``, ``source-address``  |
+----------+--------------+------------+---------+----------------------------------------------------------+
| **SS3**  | SR2 × OV6    | ER7        | 3       | Approbation ``/device`` restreinte, PKCE, CrowdSec       |
+----------+--------------+------------+---------+----------------------------------------------------------+
| **SS4**  | SR3 × OV3    | ER3        | 3       | Puits d'enregistrement root, confinement, auditd         |
+----------+--------------+------------+---------+----------------------------------------------------------+
| **SS5**  | SR5 × OV2    | ER2        | 3       | Réautorisation en direct, KRL, procédure d'offboarding   |
+----------+--------------+------------+---------+----------------------------------------------------------+
| **SS6**  | SR6 × OV1    | ER1        | 4       | Portée locale des clés, empreinte revérifiée, inventaire |
+----------+--------------+------------+---------+----------------------------------------------------------+
| **SS7**  | SR4 × OV5    | ER5        | 3       | Cache offline, compte de secours, console hors-bande     |
+----------+--------------+------------+---------+----------------------------------------------------------+

Les mesures citées ici sont de haut niveau. Leur déclinaison technique, avec scores de vraisemblance et de gravité par chemin d'attaque, est l'objet des **39 fiches de l'atelier 4** (:doc:`enrôlement </security/01-enrollment>`, :doc:`connexion SSH </security/02-ssh-connection>`), et leur ordonnancement celui du :doc:`plan de traitement </security/07-plan-de-traitement>`.

--------------

Atelier précédent : :doc:`Atelier 2 — sources de risque </security/05-atelier2-sources-de-risque>` · Atelier suivant : Atelier 4 — :doc:`enrôlement </security/01-enrollment>` et :doc:`connexion SSH </security/02-ssh-connection>`
