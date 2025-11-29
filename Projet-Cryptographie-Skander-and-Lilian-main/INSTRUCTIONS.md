# Messagerie Chiffrée - Instructions d'utilisation

## Description
Cette application permet de communiquer de manière sécurisée entre deux ordinateurs sur des réseaux différents (via Internet) avec chiffrement de bout en bout.

## Prérequis
- Python 3.x
- Module `cryptography` installé : `pip install cryptography`

## Configuration réseau pour connexion Internet

### Pour le PC qui CRÉE la messagerie (Serveur) :

1. **Configurer le routeur** :
   - Connectez-vous à l'interface de votre routeur (généralement http://192.168.1.1 ou http://192.168.0.1)
   - Trouvez la section "Port Forwarding" ou "Redirection de port"
   - Créez une règle :
     - Port externe : Le port choisi (ex: 5555)
     - Port interne : Le même port (ex: 5555)
     - IP locale : L'IP de votre PC (trouvez-la avec `ipconfig` dans PowerShell)
     - Protocole : TCP

2. **Obtenir votre IP publique** :
   - Visitez https://whatismyipaddress.com/
   - Notez votre adresse IP publique (ex: 203.0.113.45)

3. **Lancer l'application** :
   - Exécutez `python "UI messagerie.py"`
   - Choisissez "Créer une messagerie privée"
   - Entrez un port (ex: 5555)
   - **Important** : Copiez les informations affichées (IP locale, Port, Clé)
   - **Partagez avec l'autre personne** :
     - Votre IP PUBLIQUE (pas l'IP locale affichée)
     - Le port choisi
     - La clé de chiffrement

### Pour le PC qui REJOINT la messagerie (Client) :

1. **Pas de configuration réseau nécessaire** (pas de port forwarding)

2. **Lancer l'application** :
   - Exécutez `python "UI messagerie.py"`
   - Choisissez "Rejoindre une messagerie privée"
   - Entrez :
     - **IP** : L'IP PUBLIQUE du serveur (fournie par l'autre personne)
     - **Port** : Le port du serveur (ex: 5555)
     - **Clé** : La clé de chiffrement fournie

## Test sur le même réseau local (pour débuter)

Si vous voulez d'abord tester sur le même réseau WiFi/Ethernet :

### Serveur :
1. Créer une messagerie, port 5555
2. Partagez l'IP LOCALE affichée (ex: 192.168.1.10) et la clé

### Client :
1. Rejoindre avec l'IP LOCALE du serveur
2. Port 5555
3. La clé fournie

## Sécurité

- Tous les messages sont chiffrés avec Fernet (AES-128)
- La clé de chiffrement est générée aléatoirement
- Partagez la clé de manière sécurisée (pas par email non chiffré)
- Le serveur doit exposer un port sur Internet (considérez les risques de sécurité)

## Dépannage

### "Impossible de créer le serveur" :
- Le port est peut-être déjà utilisé, essayez un autre port
- Vérifiez que le pare-feu Windows autorise Python

### "Impossible de se connecter" :
- Vérifiez que le port forwarding est correctement configuré sur le routeur du serveur
- Vérifiez l'IP publique du serveur
- Assurez-vous que le pare-feu Windows autorise la connexion entrante sur le port
- Vérifiez que la clé de chiffrement est correcte (case sensitive)

### Configuration du pare-feu Windows :
```powershell
# Autoriser le port 5555 (à exécuter en tant qu'administrateur)
New-NetFirewallRule -DisplayName "Messagerie Chiffrée" -Direction Inbound -Protocol TCP -LocalPort 5555 -Action Allow
```

## Architecture

- **Serveur** : Écoute sur 0.0.0.0 (toutes les interfaces) sur le port choisi
- **Client** : Se connecte à l'IP publique du serveur
- **Chiffrement** : Chaque message est chiffré individuellement avec Fernet
- **Format** : Messages échangés en JSON avec structure {user, message}
