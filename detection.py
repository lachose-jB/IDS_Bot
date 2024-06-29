import telebot
from telebot import types
import json
import os
import uuid
import subprocess
import time
TELEGRAM_TOKEN = 'Token_Bot'
bot = telebot.TeleBot(TELEGRAM_TOKEN)

# Dossier pour sauvegarder les règles des utilisateurs
USER_DATA_DIR = 'user_data'
if not os.path.exists(USER_DATA_DIR):
    os.makedirs(USER_DATA_DIR)

# Initialisation du dictionnaire des règles utilisateur et des règles Snort correspondantes
rules = {
    'Détection de scans de ports': 'Alerte lorsque Snort détecte un scan de port',
    'Détection d\'exploits connus': 'Alerte lors de la détection d\'un exploit connu',
    'Détection de tentatives d\'authentification': 'Alerte lors de tentatives d\'authentification suspectes',
    'Détection d\'attaques par déni de service (DDoS)': 'Alerte lors de détection d\'attaques DDoS',
    'Détection de trafic malveillant': 'Alerte lors de la détection de trafic malveillant',
    'Détection de comportements anormaux': 'Alerte lors de la détection de comportements réseau anormaux'
}

snort_rule = {
    'Détection de scans de ports': 'alert tcp any any -> any any (msg:"Scan de port"; sid:1000001;)',
    'Détection d\'exploits connus': 'alert tcp any any -> any any (msg:"Exploit connu détecté"; sid:1000002;)',
    'Détection de tentatives d\'authentification': 'alert tcp any any -> any any (msg:"Tentative d\'authentification suspecte"; sid:1000003;)',
    'Détection d\'attaques par déni de service (DDoS)': 'alert tcp any any -> any any (msg:"Attaque DDoS détectée"; sid:1000004;)',
    'Détection de trafic malveillant': 'alert tcp any any -> any any (msg:"Trafic malveillant détecté"; sid:1000005;)',
    'Détection de comportements anormaux': 'alert tcp any any -> any any (msg:"Comportement réseau anormal détecté"; sid:1000006;)'
}

# Stocker les messages envoyés
message_ids = []

# Dictionnaire pour suivre l'état des utilisateurs
user_states = {}

# Fonction pour envoyer un message et stocker son ID
def send_message_and_store(chat_id, text, **kwargs):
    msg = bot.send_message(chat_id, text, **kwargs)
    message_ids.append((chat_id, msg.message_id))
    return msg

# Fonction pour effacer l'historique des messages
def clear_message_history():
    for chat_id, message_id in message_ids:
        try:
            bot.delete_message(chat_id, message_id)
        except Exception as e:
            print(f"Erreur lors de la suppression du message {message_id}: {e}")
    message_ids.clear()

# Fonction pour générer un token utilisateur unique
def generate_user_token():
    return str(uuid.uuid4())

# Fonction pour sauvegarder les règles utilisateur
def save_user_rules(user_id, rules):
    user_file = os.path.join(USER_DATA_DIR, f'{user_id}.json')
    with open(user_file, 'w') as f:
        json.dump(rules, f)

# Fonction pour charger les règles utilisateur
def load_user_rules(user_id):
    user_file = os.path.join(USER_DATA_DIR, f'{user_id}.json')
    if os.path.exists(user_file):
        with open(user_file, 'r') as f:
            return json.load(f)
    return []

# Message d'accueil
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    user_id = message.from_user.id
    token = generate_user_token()
    send_menu(message)

# Envoi du menu
@bot.message_handler(commands=['menu'])
def send_menu(message):
    menu_text = (
        "Menu Principal :\n"
        "/mon_id - Obtenir l'ID utilisateur\n\n"
        "/ordinateur_id - Obtenir l'ID de l'ordinateur\n\n"
        "/regle - Voir les règles de surveillance\n\n"
        "/modifier - Modifier la configuration\n\n"
    )
    user_id = message.from_user.id
    rule_select = load_user_rules(user_id)
    if rule_select:
        menu_text += "/demarrer_surveillance - Démarrer la surveillance\n\n"
    send_message_and_store(message.chat.id, menu_text)

# ID Utilisateur
@bot.message_handler(commands=['mon_id'])
def get_user_id(message):
    user_id = message.from_user.id
    send_message_and_store(message.chat.id, f"Votre ID utilisateur est : {user_id}")
    send_menu(message)

@bot.message_handler(commands=['ordinateur_id'])
def get_computer_id(message):
    chat_id = message.chat.id
    send_message_and_store(message.chat.id, f"L'ID de votre ordinateur est : {chat_id}")
    send_menu(message)

# Liste des règles générales
@bot.message_handler(commands=['regle'])
def view_rules(message):
    markup = types.ReplyKeyboardMarkup(one_time_keyboard=True)
    for rule in rules:
        markup.add(types.KeyboardButton(rule))
    send_message_and_store(message.chat.id, "Liste des règles que vous pouvez définir. Sélectionnez pour établir la règle de surveillance :", reply_markup=markup)

# Gestion des sélections de règles
@bot.message_handler(func=lambda message: message.text in rules.keys() and user_states.get(message.from_user.id) != 'delete_mode')
def handle_rule_selection(message):
    user_id = message.from_user.id
    rule_select = load_user_rules(user_id)
    rule = message.text
    if rule in rule_select:
        send_message_and_store(message.chat.id, f"La règle '{rule}' est déjà sélectionnée.")
    else:
        rule_select.append(rule)
        save_user_rules(user_id, rule_select)
        snort_rule_to_apply = snort_rule[rule]
        # Ajouter ici le code pour appliquer la règle Snort correspondante
        try:
            with open('/etc/snort/rules/local.rules', 'a') as config_file:
                config_file.write(snort_rule_to_apply + '\n')
            send_message_and_store(message.chat.id, f"Vous avez sélectionné la règle : {rule}\nRègle Snort appliquée : {snort_rule_to_apply}\nQue souhaitez-vous faire maintenant ?", reply_markup=generate_selection_markup())
        except PermissionError:
            send_message_and_store(message.chat.id, "Erreur de permission : impossible d'écrire dans /etc/snort/rules/local.rules. Exécutez le script avec des privilèges élevés.")

def generate_selection_markup():
    markup = types.ReplyKeyboardMarkup(one_time_keyboard=True)
    markup.add(types.KeyboardButton("Ajouter plus de règle"))
    markup.add(types.KeyboardButton("Sauvegarder"))
    return markup

@bot.message_handler(func=lambda message: message.text == "Ajouter plus de règle")
def add_rule(message):
    user_id = message.from_user.id
    rule_select = load_user_rules(user_id)
    markup = types.ReplyKeyboardMarkup(one_time_keyboard=True)
    if len(rule_select) == len(rules):
        send_message_and_store(message.chat.id, "Toutes les règles ont été définies.", reply_markup=generate_final_markup())
    else:
        for rule in rules:
            if rule not in rule_select:
                markup.add(types.KeyboardButton(rule))
        send_message_and_store(message.chat.id, "Sélectionnez une règle à ajouter :", reply_markup=markup)

def generate_final_markup():
    markup = types.ReplyKeyboardMarkup(one_time_keyboard=True)
    markup.add(types.KeyboardButton("DÉMARRER LA SURVEILLANCE"))
    markup.add(types.KeyboardButton("Acceuil"))
    return markup

@bot.message_handler(func=lambda message: message.text == "Sauvegarder")
def save_rules(message):
    send_message_and_store(message.chat.id, "Les règles ont été définies et enregistrées.", reply_markup=generate_final_markup())

@bot.message_handler(func=lambda message: message.text == "Acceuil")
def cancel(message):
    send_menu(message)

@bot.message_handler(func=lambda message: message.text == "DÉMARRER LA SURVEILLANCE")
def start_surveillance(message):
    clear_message_history()
    send_message_and_store(message.chat.id, "La surveillance a démarré.")
    start_user_surveillance(message.chat.id)

# Menu Modifier
@bot.message_handler(commands=['modifier'])
def edit_config(message):
    send_menu_user(message)

def send_menu_user(message):
    menu_user_text = (
        "/mes_regles - Voir mes règles\n\n"
        "/supprimer - Supprimer une règle\n\n"
        "/exit - Quitter le menu\n\n"
    )
    send_message_and_store(message.chat.id, menu_user_text)

@bot.message_handler(commands=['mes_regles'])
def view_user_rules(message):
    user_id = message.from_user.id
    rule_select = load_user_rules(user_id)
    if not rule_select:
        send_message_and_store(message.chat.id, "Vous n'avez pas encore défini de règle.")
    else:
        markup_user = types.ReplyKeyboardMarkup(one_time_keyboard=True)
        for rule in rule_select:
            markup_user.add(types.KeyboardButton(rule))
        send_message_and_store(message.chat.id, "Voici vos règles définies :", reply_markup=markup_user)

@bot.message_handler(commands=['supprimer'])
def handle_supprimer(message):
    user_id = message.from_user.id
    rule_select = load_user_rules(user_id)
    if not rule_select:
        send_message_and_store(message.chat.id, "Vous n'avez pas encore défini de règle pour supprimer.")
        send_menu_user(message)
    else:
        user_states[user_id] = 'delete_mode'
        markup_user = types.ReplyKeyboardMarkup(one_time_keyboard=True)
        for rule in rule_select:
            markup_user.add(types.KeyboardButton(rule))
        send_message_and_store(message.chat.id, "Voici vos règles, sélectionnez pour supprimer :", reply_markup=markup_user)

@bot.message_handler(func=lambda message: user_states.get(message.from_user.id) == 'delete_mode')
def delete_rule(message):
    user_id = message.from_user.id
    rule_select = load_user_rules(user_id)
    rule_user = message.text
    if rule_user in rule_select:
        rule_select.remove(rule_user)
        save_user_rules(user_id, rule_select)
        try:
            # Lire les règles existantes du fichier
            with open('/etc/snort/rules/local.rules', 'r') as config_file:
                lines = config_file.readlines()
            # Filtrer les lignes pour supprimer la règle correspondante
            snort_rule_to_remove = snort_rule[rule_user]
            with open('/etc/snort/rules/local.rules', 'w') as config_file:
                for line in lines:
                    if snort_rule_to_remove not in line:
                        config_file.write(line)
            send_message_and_store(message.chat.id, f"La règle '{rule_user}' a été supprimée avec succès.")
        except PermissionError:
            send_message_and_store(message.chat.id, "Erreur de permission : impossible de modifier /etc/snort/rules/local.rules. Exécutez le script avec des privilèges élevés.")
    else:
        send_message_and_store(message.chat.id, f"La règle '{rule_user}' n'est pas dans vos règles définies.")

    # Réinitialiser l'état de l'utilisateur
    user_states[user_id] = None
    send_menu_user(message)


def parse_snort_log(log_line):
    parts = log_line.split()

    if len(parts) >= 13:
        date_time = parts[0] # date et l'heure
        ip_source = parts[-3].split(":")[0]  # Extraire l'IP source
        message = " ".join(parts[3:-7]) # Extraire le message
        type_intrusion = parts[-4].strip("{}")  # Extraire le type d'intrusion
        port = parts[-3].split(":")[-1]  # Extraire le port

        return {
            'Ip_source': ip_source,
            'Date': date_time,
            'Message': message,
            'Type_intrusion': type_intrusion,
            'Port': port
        }
    else:
        return None

def monitor_snort_log(chat_id):
    log_file = "text.txt"  # Chemin vers le fichier de logs de Snort
    last_position = 0  # Position du dernier octet lu dans le fichier

    # Vérifier si le fichier existe, sinon le créer
    if not os.path.exists(log_file):
        with open(log_file, "w"):
            pass

    while True:
        with open(log_file, "r") as f:
            f.seek(last_position)
            new_data = f.read()
            if new_data:
                # Envoyer les nouveaux événements à chaque ligne
                for line in new_data.split("\n"):
                    if line.strip():
                        log_data = parse_snort_log(line)
                        if log_data:
                            send_snort_log_message(chat_id, log_data)
                last_position = f.tell()  # Mettre à jour la position de lecture
        time.sleep(1)


def send_snort_log_message(chat_id, log_data):
    # Formatage du message selon le format demandé
    log_message = (
        f"Ip_source: {log_data['Ip_source']}\n"
        f"Date: {log_data['Date']}\n"
        f"Message: {log_data['Message']}\n"
        f"Type_intrusion: {log_data['Type_intrusion']}\n"
        f"Port: {log_data['Port']}\n"
    )
    # Envoyer le message formaté
    send_message_and_store(chat_id, log_message)

def start_user_surveillance(chat_id):
    user_id = chat_id
    user_rules = load_user_rules(user_id)
    applicable_snort_rules = [snort_rule[rule] for rule in user_rules]
    
    if applicable_snort_rules:
        # Démarrer Snort avec les règles applicables
        snort_config_path = '/etc/snort/snort.conf'
        with open(snort_config_path, 'a') as config_file:
            for rule in applicable_snort_rules:
                config_file.write(rule + '\n')
        try:
            subprocess.Popen(['sudo', 'snort', '-A', 'console', '-q', '-c', snort_config_path, '-i', 'wlo1'])
            monitor_snort_log(chat_id)
            # Envoyer un message une fois que la surveillance est démarrée
            msg = send_message_and_store(chat_id, "La surveillance a démarré. Utilisez /arreter_surveillance pour arrêter.")
            # Épingler le message
            bot.pin_chat_message(chat_id, msg.message_id, disable_notification=True)
        except Exception as e:
            send_message_and_store(chat_id, f"Erreur lors du démarrage de Snort : {str(e)}")
    else:
        send_message_and_store(chat_id, "Aucune règle définie pour la surveillance.")
    send_message_and_store(chat_id, "/start pour afficher le menu\n\n")


@bot.message_handler(commands=['demarrer_surveillance'])
def start_surveillance(message):
    clear_message_history()
    send_message_and_store(message.chat.id, "La surveillance a démarré.")
    start_user_surveillance(message.chat.id)


# Quitter le menu
@bot.message_handler(commands=['exit'])
def exit_menu(message):
    send_message_and_store(message.chat.id, "Vous avez quitté le menu.")
    send_menu(message)

bot.infinity_polling()
