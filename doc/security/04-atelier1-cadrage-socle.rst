.. _atelier-1--cadrage-et-socle-de-sécurité:

Atelier 1 — Cadrage et socle de sécurité
========================================

   **Méthode :** EBIOS Risk Manager (ANSSI, 2018). Cet atelier définit le périmètre étudié, les valeurs métier et biens supports, les événements redoutés avec leur gravité, et le socle de sécurité applicable.

   **Statut du document :** voir :doc:`/security/08-dossier-homologation` pour la version, l'auteur, l'approbateur et le périmètre d'homologation.

.. _11-objet-et-périmètre-de-létude:

.. _security-04-atelier1-cadrage-socle-11-objet-et-périmètre-de-létude:

1.1 Objet et périmètre de l'étude
---------------------------------

Open Bastion est un point de passage SSH d'entreprise : les administrateurs ouvrent leurs sessions à travers un **bastion**, qui les enregistre, et rebondit vers des **backends** ; l'authentification, l'autorisation et l'escalade ``sudo`` sont gouvernées par un portail **LemonLDAP::NG (LLNG)** et sa chaîne de plugins.

.. _security-04-atelier1-cadrage-socle-périmètre-technique-retenu:

Périmètre technique retenu
~~~~~~~~~~~~~~~~~~~~~~~~~~

+-------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------+
| Dans le périmètre                                                                                                                   | Hors périmètre                                               |
+=====================================================================================================================================+==============================================================+
| Module PAM ``pam_openbastion.so`` et module NSS ``libnss_openbastion``                                                              | Le système d'exploitation hôte et son durcissement de base   |
+-------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------+
| Démons et clients : ``ob-cert-daemon``, ``ob-record-sink``, ``ob-ssh``/``ob-scp``/``ob-sftp``                                       | ``sshd`` lui-même (OpenSSH amont)                            |
+-------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------+
| Scripts d'installation et d'enrôlement : ``ob-bastion-setup``, ``ob-backend-setup``, ``ob-enroll``                                  | Le réseau et sa segmentation                                 |
+-------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------+
| Le générateur de déploiements ``ob-builder`` et les artefacts qu'il produit                                                         | L'annuaire (LDAP/AD) derrière LLNG                           |
+-------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------+
| **Le portail LLNG et ses quatre plugins** : ``pam-access``, ``ssh-ca``, ``oidc-device-authorization``, ``oidc-device-organization`` | Le socle LLNG cœur (portail, sessions, Manager) hors plugins |
+-------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------+

Le portail et sa chaîne de plugins sont **dans** le périmètre : c'est lui qui autorise chaque session et chaque ``sudo``, signe les certificats et détient la clé de CA. Une étude qui s'arrêterait au bord du serveur ne dirait rien de la moitié des décisions de sécurité. Cette inclusion est une décision d'homologation, tracée comme telle en :doc:`/security/08-dossier-homologation`.

Cible de sécurité étudiée
~~~~~~~~~~~~~~~~~~~~~~~~~

L'étude porte sur la **cible maximale (Mode E)** décrite en :doc:`/security/00-architecture` : certificats CA obligatoires (``AuthorizedKeysFile none``), autorisation LLNG à chaque connexion, ``sudo`` par token LLNG à usage unique, KRL obligatoire, rebond bastion→backend par certificat éphémère vouché. Les modes moins restrictifs (A à D, voir :doc:`/pam-modes`) réduisent le niveau de garantie ; ils ne sont pas la cible de cette étude et **ne sont pas homologués par elle**.

.. _12-valeurs-métier:

1.2 Valeurs métier
------------------

Les valeurs métier sont ce que l'organisation cherche à protéger, exprimé en termes de finalité et non de technique.

+---------+------------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------+
| Id      | Valeur métier                            | Description                                                                                                       | Nature      |
+=========+==========================================+===================================================================================================================+=============+
| **VM1** | Accès administrateur au SI               | La capacité, pour les seules personnes habilitées, d'administrer les serveurs de production                       | Processus   |
+---------+------------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------+
| **VM2** | Traçabilité des actions d'administration | La preuve de qui a fait quoi, quand, sur quel serveur — opposable en cas d'incident ou de contrôle                | Information |
+---------+------------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------+
| **VM3** | Confidentialité des sessions             | Le contenu des sessions d'administration (secrets manipulés, configurations, données consultées)                  | Information |
+---------+------------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------+
| **VM4** | Continuité de l'exploitation             | La capacité à intervenir sur les serveurs, y compris en situation dégradée (panne du SSO, incident réseau)        | Processus   |
+---------+------------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------+
| **VM5** | Maîtrise du cycle de vie des accès       | L'attribution, la révision et surtout la **révocation** effective des accès, notamment au départ d'un intervenant | Processus   |
+---------+------------------------------------------+-------------------------------------------------------------------------------------------------------------------+-------------+

.. _security-04-atelier1-cadrage-socle-13-biens-supports:

1.3 Biens supports
------------------

+---------+-------------------------------------------------------------------+------------------------+-----------------------+
| Id      | Bien support                                                      | Valeurs métier portées | Détenteur             |
+=========+===================================================================+========================+=======================+
| **BS1** | Clé privée de la CA SSH (détenue par le portail LLNG)             | VM1, VM3, VM5          | Administrateur LLNG   |
+---------+-------------------------------------------------------------------+------------------------+-----------------------+
| **BS2** | Portail LLNG et ses plugins (``/pam/*``, ``/ssh/*``, ``/device``) | VM1, VM5               | Administrateur LLNG   |
+---------+-------------------------------------------------------------------+------------------------+-----------------------+
| **BS3** | Bastion : ``sshd``, ``pam_openbastion``, enregistreur de session  | VM1, VM2, VM3          | Équipe Open Bastion   |
+---------+-------------------------------------------------------------------+------------------------+-----------------------+
| **BS4** | Backends : ``sshd``, ``pam_openbastion``, ``sudo``                | VM1, VM3               | Équipe d'exploitation |
+---------+-------------------------------------------------------------------+------------------------+-----------------------+
| **BS5** | Enregistrements de session (``/var/lib/open-bastion/sessions``)   | VM2                    | Équipe Open Bastion   |
+---------+-------------------------------------------------------------------+------------------------+-----------------------+
| **BS6** | Credentials d'enrôlement (``client_secret``, token serveur)       | VM1, VM5               | Équipe Open Bastion   |
+---------+-------------------------------------------------------------------+------------------------+-----------------------+
| **BS7** | Caches locaux (autorisation offline, NSS)                         | VM1, VM4               | Équipe Open Bastion   |
+---------+-------------------------------------------------------------------+------------------------+-----------------------+
| **BS8** | Comptes de service (``service-accounts.conf`` et leurs clés)      | VM1, VM4               | Équipe d'exploitation |
+---------+-------------------------------------------------------------------+------------------------+-----------------------+
| **BS9** | KRL (liste de révocation des certificats)                         | VM5                    | Administrateur LLNG   |
+---------+-------------------------------------------------------------------+------------------------+-----------------------+

.. _14-échelle-de-gravité:

.. _security-04-atelier1-cadrage-socle-14-échelle-de-gravité:

1.4 Échelle de gravité
----------------------

Cette échelle est celle qu'emploient — implicitement jusqu'ici — les colonnes « Impact » des matrices des ateliers 4 et 5. Elle est désormais explicite : une case de matrice se lit avec elle.

+--------+-----------------+-------------------------------------------------------------------------------------------------------------------------+
| Niveau | Libellé         | Critère                                                                                                                 |
+========+=================+=========================================================================================================================+
| **4**  | **Critique**    | Compromission de l'ensemble du parc administré, ou perte totale et irrécupérable de la traçabilité                      |
+--------+-----------------+-------------------------------------------------------------------------------------------------------------------------+
| **3**  | **Important**   | Compromission d'une zone (un ``server_group``, un projet), ou perte de traçabilité sur un périmètre identifié           |
+--------+-----------------+-------------------------------------------------------------------------------------------------------------------------+
| **2**  | **Limité**      | Compromission d'un serveur, ou dégradation temporaire de la traçabilité ou de la disponibilité, avec détection possible |
+--------+-----------------+-------------------------------------------------------------------------------------------------------------------------+
| **1**  | **Négligeable** | Gêne opérationnelle sans perte de sécurité, ou incident intégralement tracé et réversible                               |
+--------+-----------------+-------------------------------------------------------------------------------------------------------------------------+

.. _15-échelle-de-vraisemblance:

1.5 Échelle de vraisemblance
----------------------------

Employée par les colonnes « Probabilité » des matrices.

+--------+---------------------+--------------------------------------------------------------------------------------------------------------+
| Niveau | Libellé             | Critère                                                                                                      |
+========+=====================+==============================================================================================================+
| **4**  | **Très probable**   | Se produira dans la durée de vie du système sans mesure supplémentaire ; exploitable sans compétence notable |
+--------+---------------------+--------------------------------------------------------------------------------------------------------------+
| **3**  | **Probable**        | Plausible dans l'année ; exploitable par un attaquant motivé disposant d'un accès réseau                     |
+--------+---------------------+--------------------------------------------------------------------------------------------------------------+
| **2**  | **Peu probable**    | Suppose une conjonction de conditions (accès privilégié, erreur de configuration, position réseau)           |
+--------+---------------------+--------------------------------------------------------------------------------------------------------------+
| **1**  | **Très improbable** | Suppose la compromission préalable d'un bien support fortement protégé, ou un attaquant de niveau étatique   |
+--------+---------------------+--------------------------------------------------------------------------------------------------------------+

.. _security-04-atelier1-cadrage-socle-151-zones-de-risque:

1.5.1 Zones de risque
---------------------

Le **score** d'un risque est le produit Vraisemblance × Gravité. Cette définition unique s'applique à toutes les matrices de l'étude ; jusqu'ici, ``01-enrollment.md`` employait un zonage par seuils sur (P, I) et ``99-risk-reduce.md`` un zonage par score, avec des listes qui ne se recoupaient pas.

+------------+-------+-----------------------------------------------------------------------+
| Zone       | Score | Traitement attendu                                                    |
+============+=======+=======================================================================+
| **Verte**  | ≤ 3   | Risque acceptable en l'état ; surveillance ordinaire                  |
+------------+-------+-----------------------------------------------------------------------+
| **Jaune**  | 4 – 5 | Risque à surveiller ; mesure de traitement souhaitable, non bloquante |
+------------+-------+-----------------------------------------------------------------------+
| **Orange** | 6 – 8 | Risque à traiter ; mesure requise ou acceptation formelle motivée     |
+------------+-------+-----------------------------------------------------------------------+
| **Rouge**  | ≥ 9   | Risque inacceptable ; traitement obligatoire avant mise en production |
+------------+-------+-----------------------------------------------------------------------+

L'acceptation formelle des risques en zone orange est portée par :doc:`/security/08-dossier-homologation`.

.. _16-événements-redoutés:

1.6 Événements redoutés
-----------------------

Un événement redouté (ER) porte atteinte à une valeur métier. Il est indépendant du chemin d'attaque : les scénarios sont l'objet des ateliers 3 et 4.

+---------+---------------------------------------------------------------------------------------+---------------+--------------+---------+
| Id      | Événement redouté                                                                     | Valeur métier | Critère DICP | Gravité |
+=========+=======================================================================================+===============+==============+=========+
| **ER1** | Un tiers non habilité obtient un accès administrateur à un ou plusieurs serveurs      | VM1           | I            | **4**   |
+---------+---------------------------------------------------------------------------------------+---------------+--------------+---------+
| **ER2** | Un accès administrateur légitime perdure après la révocation de son titulaire         | VM5           | I            | **3**   |
+---------+---------------------------------------------------------------------------------------+---------------+--------------+---------+
| **ER3** | Une action d'administration n'est pas enregistrée, ou son enregistrement est altéré   | VM2           | I, P         | **3**   |
+---------+---------------------------------------------------------------------------------------+---------------+--------------+---------+
| **ER4** | Le contenu d'une session d'administration est divulgué                                | VM3           | C            | **3**   |
+---------+---------------------------------------------------------------------------------------+---------------+--------------+---------+
| **ER5** | Les administrateurs ne peuvent plus accéder aux serveurs (verrouillage total)         | VM4           | D            | **3**   |
+---------+---------------------------------------------------------------------------------------+---------------+--------------+---------+
| **ER6** | La CA SSH est compromise : l'attaquant peut signer des certificats pour n'importe qui | VM1, VM5      | I, C         | **4**   |
+---------+---------------------------------------------------------------------------------------+---------------+--------------+---------+
| **ER7** | Un serveur non légitime est enrôlé et obtient des identités et des autorisations      | VM1           | I            | **3**   |
+---------+---------------------------------------------------------------------------------------+---------------+--------------+---------+

Correspondance avec les fiches de l'atelier 4 :

+-----+----------------------------------------------------------------------------------------------+----+
| ER  | Fiches de risque associées                                                                   | Nb |
+=====+==============================================================================================+====+
| ER1 | R4, R8, R11, R-S3, R-S6, R-S11, R-S12, R-S13, R-S16, R-S22, R-S23, R-S24, R-SA1, R-SA2, R-P1 | 15 |
+-----+----------------------------------------------------------------------------------------------+----+
| ER2 | R12, R-S8, R-S15, R-P7                                                                       | 4  |
+-----+----------------------------------------------------------------------------------------------+----+
| ER3 | R-S5, R-S18, R-S19, R-S20, R-S21, R-S25, R-P6                                                | 7  |
+-----+----------------------------------------------------------------------------------------------+----+
| ER4 | R-S9                                                                                         | 1  |
+-----+----------------------------------------------------------------------------------------------+----+
| ER5 | R6, R9, R10, R-S7, R-S10, R-S14, R-S17, R-P2, R-P3, R-P8                                     | 10 |
+-----+----------------------------------------------------------------------------------------------+----+
| ER6 | R5, R-S4, R-P4                                                                               | 3  |
+-----+----------------------------------------------------------------------------------------------+----+
| ER7 | R0, R1, R2, R3, R7, R13, R-P5                                                                | 7  |
+-----+----------------------------------------------------------------------------------------------+----+

Les 47 fiches de l'atelier 4 sont rattachées, chacune à un et un seul événement redouté ; ``tests/ebios_matrix_check.py`` vérifie que la table ci-dessus les couvre toutes et n'en invente aucune.

.. _17-socle-de-sécurité:

1.7 Socle de sécurité
---------------------

Le socle est l'ensemble des référentiels applicables et l'état des écarts.

+------------------------------------------------------------+-------------------------------------------------------------+----------------------------------------------------------------------------------------------------+
| Référentiel                                                | Applicabilité                                               | État                                                                                               |
+============================================================+=============================================================+====================================================================================================+
| **Guide ANSSI « Recommandations pour l'admin sécurisée »** | Structurant : bastion, point de passage unique, traçabilité | Conforme sur l'architecture ; écarts tracés en atelier 5                                           |
+------------------------------------------------------------+-------------------------------------------------------------+----------------------------------------------------------------------------------------------------+
| **ISO/IEC 27002:2022** § 8.2 (droits d'accès privilégiés)  | Directement applicable                                      | Conforme : attribution via LLNG, révision par les groupes, révocation immédiate côté portail       |
+------------------------------------------------------------+-------------------------------------------------------------+----------------------------------------------------------------------------------------------------+
| **ISO/IEC 27002:2022** § 8.15 (journalisation)             | Directement applicable                                      | Conforme sous condition d'emploi : enregistrement fail-closed activé, auditd opt-in (PR2)          |
+------------------------------------------------------------+-------------------------------------------------------------+----------------------------------------------------------------------------------------------------+
| **ISO/IEC 27002:2022** § 8.5 (authentification sécurisée)  | Directement applicable                                      | Conforme : certificats CA + réauthentification SSO pour ``sudo``                                   |
+------------------------------------------------------------+-------------------------------------------------------------+----------------------------------------------------------------------------------------------------+
| **Politique de mots de passe de l'organisation**           | Sans objet sur la cible Mode E                              | Aucun mot de passe SSH n'est accepté (``AuthorizedKeysFile none``, PAM ``auth`` fail-closed)       |
+------------------------------------------------------------+-------------------------------------------------------------+----------------------------------------------------------------------------------------------------+
| **Durcissement système (CIS, ANSSI-BP-028)**               | Applicable à l'hôte, hors périmètre de l'étude              | À la charge de l'exploitant ; ``--enable-hardening`` couvre le confinement de session (voir R-S19) |
+------------------------------------------------------------+-------------------------------------------------------------+----------------------------------------------------------------------------------------------------+

Les écarts au socle qui restent ouverts sont portés par le plan de traitement en :doc:`/security/07-plan-de-traitement`, et les hypothèses que le socle suppose vérifiées sont les **conditions d'emploi** de :doc:`/security/08-dossier-homologation`.

--------------

Ateliers suivants : :doc:`Atelier 2 — sources de risque </security/05-atelier2-sources-de-risque>` · :doc:`Atelier 3 — scénarios stratégiques </security/06-atelier3-scenarios-strategiques>` · Atelier 4 — scénarios opérationnels : :doc:`enrôlement </security/01-enrollment>` et :doc:`connexion SSH </security/02-ssh-connection>` · :doc:`Atelier 5 — traitement </security/07-plan-de-traitement>`
