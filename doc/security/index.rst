.. _étude-de-sécurité-open-bastion--ebios-risk-manager:

Étude de sécurité Open Bastion — EBIOS Risk Manager
===================================================

Cette étude suit la méthode **EBIOS Risk Manager** (ANSSI, 2018). Elle porte sur la cible de sécurité maximale d'Open Bastion (Mode E) et **inclut le portail LemonLDAP::NG et ses quatre plugins** dans son périmètre.

Les documents sont en français ; les documentations techniques auxquelles ils renvoient (:doc:`/hardening`, :doc:`/audit`, :doc:`/pam-modes`) sont en anglais.

Plan de lecture
---------------

+---------------------------------+--------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------+
| Atelier                         | Document                                                                                               | Contenu                                                                                                             |
+=================================+========================================================================================================+=====================================================================================================================+
| —                               | :doc:`/security/00-architecture`                                                                       | Cible de sécurité, architecture, mécanismes de défense                                                              |
+---------------------------------+--------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------+
| **1** — Cadrage et socle        | :doc:`/security/04-atelier1-cadrage-socle`                                                             | Périmètre, valeurs métier, biens supports, **échelles**, événements redoutés, socle                                 |
+---------------------------------+--------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------+
| **2** — Sources de risque       | :doc:`/security/05-atelier2-sources-de-risque`                                                         | Sources de risque, objectifs visés, couples SR/OV retenus                                                           |
+---------------------------------+--------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------+
| **3** — Scénarios stratégiques  | :doc:`/security/06-atelier3-scenarios-strategiques`                                                    | Écosystème, niveaux de menace, sept scénarios stratégiques                                                          |
+---------------------------------+--------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------+
| **4** — Scénarios opérationnels | :doc:`/security/01-enrollment` · :doc:`/security/02-ssh-connection` · :doc:`/security/09-portail-llng` | **47 fiches de risque** avec scores initiaux et résiduels, matrices — dont huit pour le portail LLNG et ses plugins |
+---------------------------------+--------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------+
| **5** — Traitement              | :doc:`/security/07-plan-de-traitement` · :doc:`/security/99-risk-reduce`                               | Plan de traitement daté et porté ; matrice résiduelle consolidée et argumentaire                                    |
+---------------------------------+--------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------+
| Décision                        | :doc:`/security/08-dossier-homologation`                                                               | Périmètre d'homologation, **conditions d'emploi**, acceptation des résiduels                                        |
+---------------------------------+--------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------+
| Opérationnel                    | :doc:`/security/03-offboarding`                                                                        | Procédure de révocation des accès administrateurs                                                                   |
+---------------------------------+--------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------+

Deux lectures utiles selon le besoin
------------------------------------

- **« Puis-je déployer ce produit ? »** → lire les **conditions d'emploi** en :ref:`08-dossier-homologation.md, §2 <security-08-dossier-homologation-2-conditions-demploi>`. Ce sont les vingt hypothèses que les scores résiduels supposent vérifiées, et que le produit n'impose pas toutes.
- **« Quel est le risque résiduel ? »** → lire la matrice consolidée en tête de :doc:`/security/99-risk-reduce`, puis les trois risques en zone orange en :ref:`08, §3.1 <security-08-dossier-homologation-31-zone-orange--acceptation-requise>`.

Cohérence vérifiée mécaniquement
--------------------------------

Une matrice de risque n'est pas une affirmation autonome : chaque case doit découler du couple (Vraisemblance, Gravité) écrit dans la fiche correspondante. ``tests/ebios_matrix_check.py`` — exécuté en CI par ``tests/test_ob_ebios_matrices.sh`` — le vérifie et échoue si :

- une case de matrice contredit sa fiche ;
- un risque analysé manque à une matrice, ou y figure sans fiche ;
- un score répété dans un titre de section de ``99-risk-reduce.md`` contredit sa fiche ;
- une fiche n'est rattachée à aucun événement redouté de l'atelier 1 ;
- une liste de zone de risque ne découle pas des scores.

État du dossier
---------------

Le dossier d'homologation porte des champs ``À COMPLÉTER`` : version du produit visée, porteurs, échéances, décisions d'acceptation et signature. Ces valeurs relèvent de l'autorité d'homologation et ne sont pas déduites de l'analyse. Tant qu'ils subsistent, **le dossier est complet en tant qu'analyse, mais non signé.**

.. toctree::
   :caption: Étude EBIOS Risk Manager
   :maxdepth: 2
   :hidden:

   00-architecture
   04-atelier1-cadrage-socle
   05-atelier2-sources-de-risque
   06-atelier3-scenarios-strategiques
   01-enrollment
   02-ssh-connection
   09-portail-llng
   07-plan-de-traitement
   99-risk-reduce
   08-dossier-homologation
   03-offboarding
