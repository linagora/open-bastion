Offboarding d'un administrateur SSH
===================================

Ce document décrit la procédure de révocation des accès lorsqu'un administrateur SSH quitte l'entreprise ou change de service. Il s'applique à l'architecture Mode E (sécurité maximale).

Contexte
--------

Un administrateur SSH (appelé "A" dans ce document) dispose de :

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Accès
     - Description

   * - Compte LLNG
     - Compte LDAP/AD avec appartenance aux groupes autorisés

   * - ``client_secret``
     - Secret du client OIDC utilisé pour les enrôlements

   * - Certificat SSH
     - Certificat signé par la CA LLNG (durée de vie : 1 an)

   * - Accès réseau
     - VPN ou accès réseau interne vers le bastion

   * - Tokens machines
     - Connaissance des ``refresh_token`` des serveurs enrôlés

.. _principe--défense-en-profondeur:

Principe : défense en profondeur
--------------------------------

La sécurité repose sur plusieurs couches indépendantes. La compromission d'une couche ne suffit pas à obtenir un accès :

::

   ┌─────────────────────────────────────────────────────────────┐
   │                    Accès SSH réussi                         │
   └─────────────────────────────────────────────────────────────┘
                               ▲
                               │ Toutes les couches doivent être OK
           ┌───────────────────┼──────────────────────┐
           │                   │                      │
      ┌────┴────┐        ┌─────┴─────┐         ┌──────┴──────┐
      │ Réseau  │        │   LLNG    │         │   SSH CA    │
      │  (VPN)  │        │  (authent │         │  (certificat│
      └─────────┘        │ + autori) │         │  signé+KRL) │
                         └─────┬─────┘         └─────────────┘
                               │
                          ┌────┴────┐
                          │  sudo   │
                          │ (token  │
                          │  LLNG)  │
                          └─────────┘

**Avantage** : La révocation d'une seule couche bloque l'accès, évitant les actions d'urgence sur toutes les couches simultanément.

--------------

Procédure d'offboarding
-----------------------

.. _phase-1--actions-immédiates-jour-j:

Phase 1 : actions immédiates (Jour J)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ces actions bloquent immédiatement tout nouvel accès de A.

.. _11-révocation-llng-priorité-haute:

1.1 Révocation LLNG (PRIORITÉ HAUTE)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Action** : Désactiver le compte de A dans l'annuaire (LDAP/AD)

.. code:: bash

   # Exemple LDAP
   ldapmodify -x -D "cn=admin,dc=example,dc=com" -W <<EOF
   dn: uid=admin-a,ou=people,dc=example,dc=com
   changetype: modify
   replace: nsAccountLock
   nsAccountLock: true
   EOF

**OU** retirer A des groupes autorisés :

.. code:: bash

   ldapmodify -x -D "cn=admin,dc=example,dc=com" -W <<EOF
   dn: cn=ssh-admins-prod,ou=groups,dc=example,dc=com
   changetype: modify
   delete: member
   member: uid=admin-a,ou=people,dc=example,dc=com
   EOF

**Effet** :

- A ne peut plus s'authentifier sur le portail LLNG
- A ne peut plus approuver de nouveaux enrôlements
- ``/pam/authorize`` refusera A pour toute connexion SSH
- A ne peut plus obtenir un nouveau certificat SSH
- Les commandes ``sudo`` nécessitant un token LLNG seront bloquées

.. _security-03-offboarding-12-invalidation-des-sessions-llng-actives:

1.2 Invalidation des sessions LLNG actives
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: bash

   # Supprimer toutes les sessions de A
   lemonldap-ng-sessions search --uid admin-a | \
     xargs -I {} lemonldap-ng-sessions delete {}

.. _13-révocation-accès-réseauvpn:

1.3 Révocation accès réseau/VPN
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Retirer les droits VPN de A auprès de l'équipe réseau.

**Effet** : Même avec des credentials valides, A ne peut plus atteindre le bastion SSH.

--------------

.. _phase-2--révocation-des-certificats-ssh:

Phase 2 : révocation des certificats SSH
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

En Mode E, les certificats SSH ont une durée de vie d'un an. **L'attente de l'expiration naturelle n'est pas une option** : la révocation via KRL est obligatoire.

**Option 1 : Révocation via l'interface d'administration LLNG (recommandée)**

Le plugin SSH CA de LLNG fournit une interface d'administration pour révoquer les certificats :

1. **Accéder à l'interface d'administration** :

   ::

      https://auth.example.com/ssh/admin

2. **Rechercher les certificats de A** :

   - L'endpoint ``/ssh/certs`` permet de lister/rechercher les certificats émis
   - Filtrer par utilisateur pour trouver les certificats de A

3. **Révoquer les certificats** :

   - Utiliser ``/ssh/revoke`` pour ajouter les certificats à la KRL
   - La révocation est immédiate côté LLNG

..

   **Note** : L'accès à l'interface d'administration dépend de la version du plugin. Avant ``0.6.0``, le plugin n'effectue **aucun** contrôle d'autorisation sur ces routes : seule une ``locationRules`` sur ``^/ssh/(admin|certs|revoke)(\\?|/|$)`` les protège. À partir de ``0.6.0``, ``sshCaAdminRule`` les refuse par défaut (403) tant qu'il n'est pas renseigné, et la ``locationRules`` reste utile en défense en profondeur. Voir R-P2 en :doc:`/security/09-portail-llng` et la condition d'emploi CE02 en :doc:`/security/08-dossier-homologation`.

**Option 2 : Révocation manuelle via KRL**

Pour une révocation en ligne de commande :

.. code:: bash

   # Récupérer le serial du dernier certificat de A (depuis les logs LLNG ou /ssh/certs)
   # Puis ajouter à la KRL
   ssh-keygen -k -f /var/lib/lemonldap-ng/ssh/krl -s /path/to/ca_key -z <serial> /dev/null

**Propagation de la KRL aux serveurs** :

La KRL est automatiquement distribuée sur les serveurs en mode E : ``ob-krl-refresh.timer`` (activé par ``ob-bastion-setup --max-security``) lance ``ob-krl-refresh`` toutes les 30 minutes, qui n'installe qu'une KRL valide, par renommage atomique :

.. code:: bash

   # Dernière et prochaine exécution
   systemctl list-timers ob-krl-refresh.timer

Pour une propagation immédiate :

.. code:: bash

   # Sur chaque serveur ou via Ansible
   curl -s https://auth.example.com/ssh/revoked > /etc/ssh/revoked_keys

**Configuration sshd requise** (normalement déjà en place) :

.. code:: bash

   # /etc/ssh/sshd_config
   TrustedUserCAKeys /etc/ssh/open-bastion_ca.pub
   RevokedKeys /etc/ssh/revoked_keys

--------------

.. _phase-3--actions-planifiées-j7-à-j30:

Phase 3 : actions planifiées (J+7 à J+30)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ces actions ne sont pas urgentes mais doivent être planifiées.

.. _security-03-offboarding-31-rotation-du-client_secret:

3.1 Rotation du ``client_secret``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A connaissait le ``client_secret`` du client OIDC. Bien que la révocation LLNG empêche son utilisation malveillante, une rotation est recommandée :

1. **Générer un nouveau secret dans le Manager LLNG** :

   ::

      OIDC → Relying Parties → pam-prod → Options → Client secret → Générer

2. **Mettre à jour la configuration sur tous les serveurs de la zone** :

   .. code:: bash

      # /etc/open-bastion/openbastion.conf
      client_secret = <nouveau_secret>

3. **Redémarrer le service PAM** (si applicable) ou tester une connexion.

**Note** : Cette rotation peut être faite lors de la prochaine fenêtre de maintenance. Elle n'est pas urgente car :

- A ne peut plus s'authentifier sur LLNG (compte désactivé)
- A ne peut plus atteindre les serveurs (VPN révoqué)

.. _32-rotation-périodique-recommandée:

3.2 Rotation périodique recommandée
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Indépendamment des offboardings, planifier une rotation régulière :

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Élément
     - Fréquence recommandée

   * - ``client_secret``
     - Tous les 6 mois

   * - Clé CA SSH
     - Tous les 2 ans (avec période de transition)

   * - Tokens machines
     - Rotation automatique via ``refresh_token``

--------------

Tableau récapitulatif
---------------------

.. list-table::
   :header-rows: 1
   :widths: 8 35 10 48

   * - Phase
     - Action
     - Délai
     - Effet

   * - 1
     - Désactiver compte LLNG
     - Immédiat
     - Bloque ``/pam/authorize`` + nouveaux certificats + sudo

   * - 1
     - Révoquer VPN
     - Immédiat
     - Bloque accès bastion

   * - 2
     - Révoquer certificats via ``/ssh/admin``
     - Immédiat
     - Ajoute à la KRL

   * - 2
     - Propager KRL aux serveurs
     - < 30 min
     - Bloque certificats révoqués

   * - 3
     - Rotation ``client_secret``
     - < 30 jours
     - Limite exposition

--------------

Checklist offboarding administrateur SSH
----------------------------------------

Jour J (immédiat)
~~~~~~~~~~~~~~~~~

- ☐ Compte A désactivé dans l'annuaire LDAP/AD
- ☐ Sessions LLNG de A supprimées
- ☐ Accès VPN de A révoqué
- ☐ Certificats SSH de A révoqués via ``/ssh/admin``
- ☐ Équipe informée de ne pas réactiver le compte

J+1 à J+7
~~~~~~~~~

- ☐ KRL propagée manuellement sur tous les serveurs de la zone
- ☐ Vérification que la KRL est à jour sur chaque serveur (``ssh-keygen -Q -f /etc/ssh/revoked_keys <cert>``)
- ☐ Audit des accès récents de A (logs SSH, logs LLNG)
- ☐ Vérification qu'aucune session persistante n'existe

J+7 à J+30
~~~~~~~~~~

- ☐ Rotation du ``client_secret`` de la zone concernée
- ☐ Documentation mise à jour (liste des administrateurs)
- ☐ Revue des accès des autres administrateurs (principe du moindre privilège)

--------------

Cas particuliers
----------------

A avait accès à plusieurs zones
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Répéter la procédure pour chaque zone (chaque ``client_secret`` distinct).

Suspicion de compromission active
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

En cas de suspicion que A a exfiltré des tokens ou tente activement d'accéder :

1. **Urgence réseau** : Bloquer l'IP de A au niveau firewall
2. **Révocation KRL immédiate** : Propager manuellement la KRL sur tous les serveurs
3. **Rotation immédiate** : ``client_secret`` de toutes les zones accessibles par A
4. **Invalidation tokens** : Utiliser ``/admintokenrevoke`` pour révoquer les ``refresh_token`` des machines

.. code:: bash

   # Révocation d'un refresh_token via l'API admin LLNG
   curl -X POST https://auth.example.com/admintokenrevoke \
     -H "Authorization: Bearer <admin_secret>" \
     -d "token=<refresh_token>" \
     -d "token_hint=refresh_token"

A était le seul administrateur d'une zone
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

S'assurer qu'un autre administrateur a les accès nécessaires AVANT de révoquer A :

- Accès au Manager LLNG
- Accès au ``client_secret`` (ou capacité à en générer un nouveau)
- Certificat SSH valide ou capacité à en obtenir un

--------------

Comptes de service
------------------

Particularité
~~~~~~~~~~~~~

Les comptes de service (ansible, backup, deploy, etc.) **ne passent pas par LLNG** pour l'autorisation. Ce sont des comptes Unix locaux créés par l'exploitant ; sur chaque serveur, leur clé est servie à sshd depuis ``/etc/open-bastion/service-accounts.d/<nom>.pub`` et leur nom est exempté du SSO par ``/etc/open-bastion/service-accounts.conf``.

**Conséquence importante :** La révocation du compte LLNG (Phase 1.1) ne bloque **pas** les comptes de service.

**Ce qui coupe l'accès :** retirer le ``.pub`` de ``service-accounts.d/`` (et toute clé de l'``authorized_keys`` du compte) coupe l'accès SSH dès la connexion suivante ; retirer l'entrée de ``service-accounts.conf`` renvoie en outre le nom vers le portail, qui le refuse. Changer seulement ``key_fingerprint`` **ne coupe rien** : l'empreinte n'est pas comparée lors d'une connexion par clé nue, c'est la clé servie à sshd qui ouvre l'accès. Le compte local lui-même, sa règle ``sudoers`` éventuelle et ses groupes ne sont pas gérés par Open Bastion : l'exploitant les retire (``userdel``, ``/etc/sudoers.d/``). Les sessions déjà ouvertes survivent (``pkill -u <nom>`` pour les fermer).

.. mermaid::

   flowchart TB
       subgraph Revocation["Révocation compte LLNG"]
           R1[Désactiver compte<br/>dans annuaire]
       end

       subgraph OIDC["Utilisateurs OIDC"]
           O1[/pam/authorize/]
           O2[❌ Accès bloqué]
           R1 --> O1 --> O2
       end

       subgraph Service["Comptes de Service"]
           S1[service-accounts.d/nom.pub<br/>+ service-accounts.conf]
           S2[✅ Accès maintenu]
           R1 -.->|Pas d'effet| S1 --> S2
       end

       style O2 fill:#f44336,color:#fff
       style S2 fill:#4caf50,color:#fff

Flux de révocation complet
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. mermaid::

   flowchart LR
       subgraph J0["Jour J - Immédiat"]
           A1[Désactiver compte LLNG]
           A2[Révoquer VPN]
           A3{A avait accès<br/>aux clés service ?}
           A4[Rotation clés service]
       end

       subgraph J1["J+1 à J+7"]
           B1[Vérifier nouvelles clés]
           B2[Supprimer anciennes clés]
           B3[Audit des logs]
       end

       A1 --> A2 --> A3
       A3 -->|Oui| A4
       A3 -->|Non| B3
       A4 --> B1 --> B2 --> B3

Actions requises pour les comptes de service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Si la personne partante avait connaissance d'une clé de service ou pouvait la régénérer :

.. _phase-1--actions-immédiates-jour-j-1:

Phase 1 : actions immédiates (Jour J)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Identifier les comptes de service concernés** :

   .. code:: bash

      # Sur chaque serveur
      sudo cat /etc/open-bastion/service-accounts.conf
      ls -l /etc/open-bastion/service-accounts.d/

2. **Rotation des clés de service** (si A avait accès aux clés privées) :

   .. code:: bash

      # Générer une nouvelle clé
      ssh-keygen -t ed25519 -f /secure/ansible_new_key -C "ansible@$(hostname)"

      # Obtenir le fingerprint
      ssh-keygen -lf /secure/ansible_new_key.pub
      # Exemple: 256 SHA256:NEW_FINGERPRINT ansible@server (ED25519)

3. **Remplacer la clé servie à sshd**, c'est elle qui ouvre l'accès :

   .. code:: bash

      sudo install -m 0644 -o root -g root /secure/ansible_new_key.pub \
          /etc/open-bastion/service-accounts.d/ansible.pub
      # Et retirer l'ancienne clé de ~ansible/.ssh/authorized_keys s'il y en a un

4. **Mettre à jour le fichier de configuration** :

   .. code:: bash

      sudo vim /etc/open-bastion/service-accounts.conf
      # Remplacer key_fingerprint par le nouveau fingerprint

5. **Déployer la nouvelle clé privée** auprès de l'automatisation :

   .. code:: bash

      # Mettre à jour Ansible Vault / HashiCorp Vault
      # Ou déployer via le système de gestion de configuration

6. **Retirer un compte de service qui n'a plus d'usage** (au lieu de 2 à 5) :

   .. code:: bash

      sudo rm /etc/open-bastion/service-accounts.d/obbackup.pub
      sudo vim /etc/open-bastion/service-accounts.conf   # supprimer la section [obbackup]
      sudo rm -f /etc/sudoers.d/obbackup                   # règle sudoers éventuelle
      sudo pkill -u obbackup; sudo userdel -r obbackup

   Avec ``ob-builder``, retirer aussi le compte de la liste ``service_accounts:`` avant la génération suivante.

.. _phase-2--vérification-j1:

Phase 2 : vérification (J+1)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- ☐ Tester que les comptes de service fonctionnent avec les nouvelles clés
- ☐ Supprimer les anciennes clés de tous les systèmes de stockage (Vault, etc.)
- ☐ Vérifier que l'ancienne clé ne permet plus l'accès (``ssh -i ancienne_clé compte@serveur`` doit échouer)

Tableau récapitulatif - Comptes de service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 41 14 45

   * - Action
     - Délai
     - Condition

   * - Rotation clé ansible
     - Immédiat
     - Si A avait accès à la clé

   * - Rotation clé backup
     - Immédiat
     - Si A avait accès à la clé

   * - Rotation clé deploy
     - Immédiat
     - Si A avait accès à la clé

   * - Rotation clé monitoring
     - Immédiat
     - Si A avait accès à la clé

Checklist comptes de service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Jour J (si clés compromises)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- ☐ Identifier les comptes de service sur chaque serveur
- ☐ Générer de nouvelles clés pour les comptes concernés
- ☐ Remplacer les ``.pub`` dans ``service-accounts.d/`` (c'est ce qui coupe l'ancienne clé)
- ☐ Mettre à jour les fingerprints dans service-accounts.conf
- ☐ Supprimer (``userdel``) les comptes qui n'ont plus d'usage, avec leur ``.pub``, leur entrée et leur règle ``sudoers``
- ☐ Déployer les nouvelles clés dans le système de stockage sécurisé
- ☐ Tester le fonctionnement des automatisations

J+7
^^^

- ☐ Supprimer définitivement les anciennes clés
- ☐ Documenter les nouvelles clés (sans exposer le matériel privé)
- ☐ Auditer les logs pour détecter toute utilisation des anciennes clés
