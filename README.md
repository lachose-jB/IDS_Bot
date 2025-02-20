## Surveillance Bot avec Snort

Ce projet est un bot Telegram qui permet aux utilisateurs de configurer et de surveiller des règles de sécurité réseau à l'aide de Snort.
Prérequis

    Python 3.x
    Bibliothèque pyTelegramBotAPI
    Snort installé sur votre système
    Un bot Telegram (vous devez obtenir un token auprès de BotFather)

Installation

    Clonez le dépôt ou téléchargez les fichiers.

    Installez les dépendances nécessaires :

    bash
```bash
    pip install pyTelegramBotAPI
```
Assurez-vous que Snort est installé et correctement configuré sur votre machine.

Remplacez Token_Bot dans le code par le token de votre bot Telegram.

Exécutez le script avec des privilèges élevés (nécessaire pour écrire les règles de Snort) :

```bash

    sudo python3 bot.py
```
Fonctionnalités

    Affichage du menu principal : Commande /menu pour accéder aux options principales.
    Obtenir l'ID utilisateur : Commande /mon_id.
    Obtenir l'ID de l'ordinateur : Commande /ordinateur_id.
    Voir les règles de surveillance : Commande /regle.
    Modifier la configuration : Commande /modifier.
    Démarrer la surveillance : Commande /demarrer_surveillance.
    Arrêter la surveillance : Via le menu ou le bot.

## Configuration des Règles

    Ajout de règles :
        Envoyez la commande /regle.
        Sélectionnez les règles souhaitées dans le menu.

    Supprimer des règles :
        Envoyez la commande /supprimer.
        Sélectionnez les règles à supprimer dans le menu.

    Voir vos règles :
        Envoyez la commande /mes_regles pour afficher les règles actuellement définies.

## Surveillance

    Démarrer la surveillance :
        Une fois les règles définies, utilisez /demarrer_surveillance.
        Le bot appliquera les règles et surveillera les logs de Snort, envoyant des alertes pour chaque intrusion détectée.

## Fichiers et Dossiers

    user_data/ : Contient les règles spécifiques de chaque utilisateur.
    /etc/snort/rules/local.rules : Fichier où les règles Snort sont ajoutées.
    text.txt : Fichier de logs pour Snort (à personnaliser selon vos besoins).

## Utilisation

    Pour démarrer l'interaction avec le bot, utilisez /start.
    Accédez à d'autres commandes via le menu /menu.
    Modifiez et gérez vos règles via /modifier.

## Notes

    Assurez-vous que Snort est correctement configuré pour l'interface réseau utilisée (par défaut wlo1 dans le script).
    Exécutez toujours le script avec les privilèges suffisants pour écrire dans les fichiers de configuration de Snort.

## Avertissement

Ce bot est conçu à des fins éducatives. Utilisez-le de manière responsable et uniquement sur des réseaux autorisés.

Assurez-vous de personnaliser le fichier en fonction de vos besoins spécifiques et des configurations locales.
