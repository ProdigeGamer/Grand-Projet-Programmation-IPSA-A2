import tkinter as tk
from tkinter import simpledialog
from tkinter import scrolledtext
from tkinter import messagebox
import random
import socket
import threading
import json
from cryptography.fernet import Fernet

root = tk.Tk()
root.withdraw()  

server_socket = None
client_socket = None
connection = None
connected = False
crypto_key = None
fernet = None

nom_utilisateur = simpledialog.askstring("Nom d'utilisateur", "Entrez votre nom d'utilisateur :")

def afficher_message(utilisateur, message, type_msg):
    """Fonction pour afficher les messages avec des bulles style WhatsApp"""
    zone_messages.config(state="normal")
    
    # Insertion du nom d'utilisateur
    if type_msg == "send":
        zone_messages.insert("end", f"{utilisateur}\n", "user_send")
    else:
        zone_messages.insert("end", f"{utilisateur}\n", "user_receive")
    
    # Insertion du message avec la bulle
    if type_msg == "send":
        zone_messages.insert("end", f" {message} \n", "message_send")
    else:
        zone_messages.insert("end", f" {message} \n", "message_receive")
    
    # Séparateur entre les messages
    zone_messages.insert("end", "\n")
    
    zone_messages.config(state="disabled")
    zone_messages.see("end")

# Fonction pour recevoir les messages
def recevoir_messages():
    """Thread pour recevoir les messages du réseau"""
    global connection, connected, fernet
    while connected:
        try:
            data = connection.recv(4096)
            if not data:
                break
            message_data = json.loads(data.decode('utf-8'))
            
            message_chiffre = message_data['message'].encode()
            message_dechiffre = fernet.decrypt(message_chiffre).decode('utf-8')
            afficher_message(message_data['user'], message_dechiffre, "receive")
            
        except Exception as e:
            if connected:
                messagebox.showerror("Erreur", f"Erreur de réception: {str(e)}")
            break

# Fonction pour créer une messagerie privée
def cree_messagerie():
    global server_socket, connection, connected, crypto_key, fernet
    
    # Rien de complexe on demande un valeur pour le port (seulement un integer) avk la fonction simpledialog
    port = simpledialog.askinteger("Port", "Entrez le port à utiliser (ex: 5555):", minvalue=1024, maxvalue=65535)
    if not port:
        return
    
    crypto_key = Fernet.generate_key() # la je créee la clé de chiffrement
    fernet = Fernet(crypto_key)         # on crée l'objet fernet avk la clé
    clee_dacces = crypto_key.decode('utf-8')
    
    popup_cle = tk.Toplevel()
    popup_cle.title("Informations de connexion")
    popup_cle.geometry("450x200")
    
    label = tk.Label(popup_cle, text="Partagez ces informations:", font=("Arial", 12, "bold"))
    label.pack(pady=10)
    
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        info_text = f"IP: {local_ip}\nPort: {port}\nClé: {clee_dacces}"
    except:
        info_text = f"Port: {port}\nClé: {clee_dacces}"
    
    label_info = tk.Label(popup_cle, text=info_text, font=("Arial", 9))
    label_info.pack(pady=10)
    
    def copier_info():
        popup_cle.clipboard_clear()
        popup_cle.clipboard_append(info_text)
        messagebox.showinfo("Copié", "Informations copiées dans le presse-papier !")
    
    bouton_copier = tk.Button(popup_cle, text="Copier les informations", command=copier_info)
    bouton_copier.pack(pady=5)
    
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(1)
        
        messagebox.showinfo("Serveur", f"Serveur en attente de connexion sur le port {port}...")
        popup_cle.destroy()
        
        def attendre_connexion():
            global connection, connected
            connection, addr = server_socket.accept()
            connected = True
            afficher_message("Système", f"Connecté à {addr[0]}:{addr[1]}", "receive")
            threading.Thread(target=recevoir_messages, daemon=True).start()
        
        threading.Thread(target=attendre_connexion, daemon=True).start()
        lancer_messagerie()
        popup.destroy()
        
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de créer le serveur: {str(e)}")
        popup_cle.destroy()

def rejoindre_messagerie():
    global client_socket, connection, connected, crypto_key, fernet
    
    ip = simpledialog.askstring("IP du serveur", "Entrez l'adresse IP du serveur:")
    if not ip:
        return
    
    port = simpledialog.askinteger("Port", "Entrez le port du serveur:", minvalue=1024, maxvalue=65535)
    if not port:
        return
    
    clee_dacces = simpledialog.askstring("Clé de chiffrement", "Entrez la clé de chiffrement partagée:")
    if not clee_dacces:
        return
    
    try:
        crypto_key = clee_dacces.encode('utf-8')
        fernet = Fernet(crypto_key)
        
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip, port))
        connection = client_socket
        connected = True
        
        messagebox.showinfo("Succès", f"Connecté au serveur {ip}:{port}")
        
        threading.Thread(target=recevoir_messages, daemon=True).start()
        
        lancer_messagerie()
        popup.destroy()
        
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de se connecter: {str(e)}")

def lancer_messagerie():
    global zone_messages, entree
    root.deiconify()  
    root.title("Messagerie Privée Chiffrée - Fernet")
    root.geometry('500x600')
    root.configure(bg='#E5DDD5')  # Fond gris clair comme WhatsApp
    
    # Cadre pour la zone de messages
    cadre_messages = tk.Frame(root, bg='#E5DDD5')
    cadre_messages.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Zone de messages avec scrollbar
    zone_messages = tk.Text(cadre_messages, state="disabled", wrap="word", bg='#E5DDD5', 
                           font=("Arial", 11), padx=10, pady=5, borderwidth=0)
    
    # Scrollbar
    scrollbar = tk.Scrollbar(cadre_messages, command=zone_messages.yview)
    zone_messages.configure(yscrollcommand=scrollbar.set)
    
    zone_messages.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    # Messages envoyés (à droite)
    zone_messages.tag_configure("message_send", 
                               background="#DCF8C6",  # vert WhatsApp
                               relief="raised",
                               borderwidth=1,
                               justify="right")
    
    zone_messages.tag_configure("user_send",
                               foreground="blue",
                               justify="right")
    
    # Messages reçus (à gauche)
    zone_messages.tag_configure("message_receive",
                               background="#FFFFFF",  # blanc
                               relief="raised", 
                               borderwidth=1,
                               justify="left")
    
    zone_messages.tag_configure("user_receive",
                               foreground="red",
                               justify="left")
    
    # Zone de saisie
    cadre_saisie = tk.Frame(root, bg='#E5DDD5')
    cadre_saisie.pack(fill="x", padx=10, pady=5)
    
    entree = tk.Entry(cadre_saisie, font=("Arial", 11))
    entree.pack(side="left", fill="x", expand=True, padx=(0, 5))
    
    bouton_envoyer = tk.Button(cadre_saisie, text="Envoyer", command=_envoie, 
                              bg="#00897B", fg="white", font=("Arial", 10, "bold"))
    bouton_envoyer.pack(side="right")
    entree.bind("<Return>", _envoie)

def _envoie(event=None):
    global connection, connected, fernet
    message = entree.get().strip()
    if not message:
        return
    
    if not connected or not connection:
        messagebox.showwarning("Attention", "Pas de connexion établie!")
        return
    
    try:
        message_chiffre = fernet.encrypt(message.encode('utf-8'))
        
        data = json.dumps({
            'user': nom_utilisateur,
            'message': message_chiffre.decode('utf-8')
        })
        connection.send(data.encode('utf-8'))
        
        afficher_message(nom_utilisateur, message, "send")
        entree.delete(0, "end")
        
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur d'envoi: {str(e)}")

zone_messages = None
entree = None

popup = tk.Tk()
popup.title("Choix de la messagerie")
popup.geometry("300x150")

label = tk.Label(popup, text="Que voulez-vous faire ?", font=("Arial", 12))
label.pack(pady=20)

bouton_créer = tk.Button(popup, text="Créer une messagerie privée", command=cree_messagerie)
bouton_créer.pack(pady=5)

bouton_rejoindre = tk.Button(popup, text="Rejoindre une messagerie privée", command=rejoindre_messagerie)
bouton_rejoindre.pack(pady=5)

if not nom_utilisateur:
    nom_utilisateur = "Utilisateur"

def fermer_connexions():
    global connected, connection, server_socket, client_socket
    connected = False
    if connection:
        connection.close()
    if server_socket:
        server_socket.close()
    if client_socket:
        client_socket.close()
    root.quit()

root.protocol("WM_DELETE_WINDOW", fermer_connexions)

root.mainloop()