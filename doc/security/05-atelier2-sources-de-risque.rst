.. _atelier-2--sources-de-risque-et-objectifs-visés:

Atelier 2 — Sources de risque et objectifs visés
================================================

   **Méthode :** EBIOS Risk Manager (ANSSI, 2018), atelier 2. On identifie **qui** pourrait vouloir porter atteinte aux valeurs métier de :doc:`l'atelier 1 </security/04-atelier1-cadrage-socle>`, **ce qu'il chercherait à obtenir**, et on retient les couples SR/OV (source de risque / objectif visé) les plus pertinents pour la suite de l'étude.

.. _21-sources-de-risque-identifiées:

2.1 Sources de risque identifiées
---------------------------------

+---------+---------------------------------------------+--------------------------------------------------+----------------------------------------------------------+------------------------------+
| Id      | Source de risque                            | Motivation                                       | Ressources                                               | Activité                     |
+=========+=============================================+==================================================+==========================================================+==============================+
| **SR1** | Attaquant externe opportuniste              | Gain financier (rançongiciel, revente d'accès)   | Faibles : outillage public, scans de masse               | Élevée, permanente           |
+---------+---------------------------------------------+--------------------------------------------------+----------------------------------------------------------+------------------------------+
| **SR2** | Attaquant externe ciblé (groupe organisé)   | Espionnage, sabotage, revente d'accès privilégié | Élevées : 0-day possible, temps long, ingénierie sociale | Moyenne, campagne dirigée    |
+---------+---------------------------------------------+--------------------------------------------------+----------------------------------------------------------+------------------------------+
| **SR3** | Administrateur légitime malveillant         | Contournement du contrôle, dissimulation d'actes | Très élevées : accès légitime, connaissance du SI        | Faible mais impact maximal   |
+---------+---------------------------------------------+--------------------------------------------------+----------------------------------------------------------+------------------------------+
| **SR4** | Administrateur légitime maladroit           | Aucune — erreur                                  | Accès légitime                                           | Élevée (l'erreur est banale) |
+---------+---------------------------------------------+--------------------------------------------------+----------------------------------------------------------+------------------------------+
| **SR5** | Prestataire ou intervenant externe          | Dépassement de mandat, persistance après mission | Accès légitime borné dans le temps                       | Moyenne                      |
+---------+---------------------------------------------+--------------------------------------------------+----------------------------------------------------------+------------------------------+
| **SR6** | Compte technique / automatisation détournée | Aucune propre : vecteur pour SR1/SR2             | Clé de longue durée, souvent sans MFA ni rotation        | Moyenne, silencieuse         |
+---------+---------------------------------------------+--------------------------------------------------+----------------------------------------------------------+------------------------------+
| **SR7** | Administrateur du portail LLNG              | Contournement du contrôle depuis l'autorité      | Maximales : détient la CA, décide des autorisations      | Très faible, impact maximal  |
+---------+---------------------------------------------+--------------------------------------------------+----------------------------------------------------------+------------------------------+

SR7 est dans l'étude parce que le portail est **dans le périmètre** (:ref:`atelier 1, §1.1 <security-04-atelier1-cadrage-socle-périmètre-technique-retenu>`) : qui administre LLNG peut signer un certificat pour n'importe qui et s'autoriser n'importe où. C'est un pouvoir concentré, que l'architecture ne cherche pas à contraindre — elle le trace.

.. _22-objectifs-visés:

2.2 Objectifs visés
-------------------

+---------+------------------------------------------------------------------+------------------------------+
| Id      | Objectif visé                                                    | Événements redoutés associés |
+=========+==================================================================+==============================+
| **OV1** | Obtenir un accès administrateur durable au parc                  | ER1, ER6                     |
+---------+------------------------------------------------------------------+------------------------------+
| **OV2** | Conserver un accès après avoir perdu son habilitation            | ER2                          |
+---------+------------------------------------------------------------------+------------------------------+
| **OV3** | Agir sans laisser de trace exploitable                           | ER3                          |
+---------+------------------------------------------------------------------+------------------------------+
| **OV4** | Exfiltrer des secrets manipulés en session                       | ER4                          |
+---------+------------------------------------------------------------------+------------------------------+
| **OV5** | Empêcher l'exploitation (sabotage, extorsion)                    | ER5                          |
+---------+------------------------------------------------------------------+------------------------------+
| **OV6** | Introduire un serveur sous contrôle dans le périmètre administré | ER7                          |
+---------+------------------------------------------------------------------+------------------------------+

.. _security-05-atelier2-sources-de-risque-23-couples-srov-et-pertinence:

2.3 Couples SR/OV et pertinence
-------------------------------

Notation de la pertinence : **F** (forte, retenue pour la suite), **M** (moyenne, couverte mais non structurante), **f** (faible, hors étude).

+-----------------------------------+-------------------+------------------------------+---------------------+---------------+-----------------------------+------------------------+
| SR ↓ / OV →                       | OV1 accès durable | OV2 survivre à la révocation | OV3 agir sans trace | OV4 exfiltrer | OV5 empêcher l'exploitation | OV6 enrôler un serveur |
+===================================+===================+==============================+=====================+===============+=============================+========================+
| **SR1** externe opportuniste      | **F**             | f                            | f                   | M             | M                           | f                      |
+-----------------------------------+-------------------+------------------------------+---------------------+---------------+-----------------------------+------------------------+
| **SR2** externe ciblé             | **F**             | M                            | **F**               | **F**         | M                           | **F**                  |
+-----------------------------------+-------------------+------------------------------+---------------------+---------------+-----------------------------+------------------------+
| **SR3** admin malveillant         | M                 | **F**                        | **F**               | **F**         | M                           | **F**                  |
+-----------------------------------+-------------------+------------------------------+---------------------+---------------+-----------------------------+------------------------+
| **SR4** admin maladroit           | f                 | f                            | f                   | f             | **F**                       | M                      |
+-----------------------------------+-------------------+------------------------------+---------------------+---------------+-----------------------------+------------------------+
| **SR5** prestataire               | M                 | **F**                        | M                   | M             | f                           | f                      |
+-----------------------------------+-------------------+------------------------------+---------------------+---------------+-----------------------------+------------------------+
| **SR6** compte technique détourné | **F**             | **F**                        | **F**               | M             | f                           | f                      |
+-----------------------------------+-------------------+------------------------------+---------------------+---------------+-----------------------------+------------------------+
| **SR7** admin du portail LLNG     | **F**             | **F**                        | **F**               | **F**         | **F**                       | **F**                  |
+-----------------------------------+-------------------+------------------------------+---------------------+---------------+-----------------------------+------------------------+

Couples retenus pour l'atelier 3
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Six couples structurent les scénarios stratégiques :

+---------------+-----------------------------------------------------------------------------------------------------+------------+
| Couple        | Formulation                                                                                         | Traité par |
+===============+=====================================================================================================+============+
| **SR2 × OV1** | Un attaquant ciblé obtient un accès administrateur durable au parc                                  | SS1, SS2   |
+---------------+-----------------------------------------------------------------------------------------------------+------------+
| **SR2 × OV6** | Un attaquant ciblé fait enrôler un serveur sous son contrôle et récupère identités et autorisations | SS3        |
+---------------+-----------------------------------------------------------------------------------------------------+------------+
| **SR3 × OV3** | Un administrateur légitime agit sans laisser de trace exploitable                                   | SS4        |
+---------------+-----------------------------------------------------------------------------------------------------+------------+
| **SR5 × OV2** | Un prestataire conserve un accès après la fin de sa mission                                         | SS5        |
+---------------+-----------------------------------------------------------------------------------------------------+------------+
| **SR6 × OV1** | Une clé d'automatisation détournée donne un accès privilégié permanent, hors du contrôle SSO        | SS6        |
+---------------+-----------------------------------------------------------------------------------------------------+------------+
| **SR4 × OV5** | Une erreur d'exploitation rend le parc inaccessible (verrouillage total)                            | SS7        |
+---------------+-----------------------------------------------------------------------------------------------------+------------+

Couples écartés, et pourquoi
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **SR1 × OV1** est réel mais entièrement couvert par SS1 : l'opportuniste emprunte le même chemin que l'attaquant ciblé, avec moins de moyens. Le traiter séparément n'ajouterait aucune mesure.
- **SR7 × tout** n'est pas écarté mais **n'est pas traitable par le produit** : l'administrateur du portail est l'autorité dont dépend tout le modèle. Il est traité comme une **hypothèse de confiance** en :doc:`/security/08-dossier-homologation` — c'est-à-dire une condition d'emploi (accès Manager restreint et tracé, clé de CA protégée), pas un risque que l'on prétend réduire. Le dire explicitement vaut mieux que de laisser croire que l'architecture s'en protège.
- **SR4 × OV6** (enrôlement d'un serveur par erreur) est couvert par la règle d'approbation ``/device`` : voir R0, R7 et la condition d'emploi correspondante.

--------------

Atelier précédent : :doc:`Atelier 1 — cadrage et socle </security/04-atelier1-cadrage-socle>` · Atelier suivant : :doc:`Atelier 3 — scénarios stratégiques </security/06-atelier3-scenarios-strategiques>`
