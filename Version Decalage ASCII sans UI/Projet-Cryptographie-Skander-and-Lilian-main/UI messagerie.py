import tkinter as tk
from tkinter import simpledialog
from tkinter import scrolledtext
from tkinter import messagebox
import random
import socket
import threading
import json

root = tk.Tk()
root.withdraw()  

server_socket = None
client_socket = None
connection = None
connected = False
crypto_key = None

nom_utilisateur = simpledialog.askstring("Nom d'utilisateur", "Entrez votre nom d'utilisateur :")


def encodage(texte, k):
    """Votre fonction de cryptage originale"""
    codage_ascii = []    #liste vide qui va contenir le code ascii de chaque lettre
    result = ""         #variable qui va contenir le texte codé
    for char in texte:    #je fais une boucle for pour mettre chaque lettre en ascii + k
        newchar = ord(char) + k
        codage_ascii.append(newchar)
    for chiffres in codage_ascii: #je fais une boucle for pour convertir le code ascii + k en lettre
        newchar2 = chr(chiffres)
        result += newchar2
    return result

def reconvertir(chiffres, k):
    """Votre fonction de décryptage originale"""
    phrase = ""
    for char in chiffres:  #je fais une boucle for pour convertir le code ascii - k en lettre
        newchar = chr(char - k)
        phrase += newchar
    return phrase

def chiffrer_message(message, k):
    """Adaptation pour l'interface de messagerie"""
    try:
        return encodage(message, k)
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur de chiffrement: {str(e)}")
        return message

def dechiffrer_message(message_chiffre, k):
    """Adaptation pour l'interface de messagerie"""
    try:
        # Convertir la chaîne en liste d'entiers (codes ASCII)
        codes_ascii = [ord(char) for char in message_chiffre]
        return reconvertir(codes_ascii, k)
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur de déchiffrement: {str(e)}")
        return message_chiffre


def recevoir_messages():
    """Thread pour recevoir les messages du réseau"""
    global connection, connected, crypto_key
    while connected:
        try:
            data = connection.recv(4096)
            if not data:
                break
            message_data = json.loads(data.decode('utf-8'))
            
            # Utilisation de votre cryptage pour déchiffrer
            message_dechiffre = dechiffrer_message(message_data['message'], crypto_key)
            
            zone_messages.config(state="normal")
            zone_messages.insert("end", f"{message_data['user']}: {message_dechiffre}\n")
            zone_messages.config(state="disabled")
            zone_messages.see("end")
        except Exception as e:
            if connected:
                messagebox.showerror("Erreur", f"Erreur de réception: {str(e)}")
            break

def cree_messagerie():
    global server_socket, connection, connected, crypto_key
    
    port = simpledialog.askinteger("Port", "Entrez le port à utiliser (ex: 5555):", minvalue=1024, maxvalue=65535)
    if not port:
        return
    
    # on va récuperer le decalage K en table ascii
    K = simpledialog.askinteger("Clé de chiffrement", "Entrez une clé de chiffrement (nombre entier) compris entre -10 et 20:", minvalue=-10, maxvalue=20)
    if K is None:
        return
    
    crypto_key = K  # Stocke la valeur de K pour le chiffrement/déchiffrement
    
    # Génération d'une clé d'accès pour le partage (représentation de votre clé K)
    clee_dacces = str(K)
    
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
            zone_messages.config(state="normal")
            zone_messages.insert("end", f"[SYSTÈME] Connecté à {addr[0]}:{addr[1]}\n")
            zone_messages.config(state="disabled")
            threading.Thread(target=recevoir_messages, daemon=True).start()
        
        threading.Thread(target=attendre_connexion, daemon=True).start()
        lancer_messagerie()
        popup.destroy()
        
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de créer le serveur: {str(e)}")
        popup_cle.destroy()

def rejoindre_messagerie():
    global client_socket, connection, connected, crypto_key
    
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
        # Conversion de la clé en entier pour votre système de cryptage
        crypto_key = int(clee_dacces)
        
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
    root.title("Messagerie Privée Chiffrée - Cryptage Noobs")
    root.geometry('500x600')
    zone_messages = tk.Text(root, state="disabled", wrap="word")
    zone_messages.pack(fill="both", expand=True, padx=10, pady=10)
    entree = tk.Entry(root)
    entree.pack(fill="x", padx=10, pady=5)
    
    bouton_envoyer = tk.Button(root, text="Envoyer", command=_envoie)
    bouton_envoyer.pack(padx=10, pady=5)
    entree.bind("<Return>", _envoie)

def _envoie(event=None):
    global connection, connected, crypto_key
    message = entree.get().strip()
    if not message:
        return
    
    if not connected or not connection:
        messagebox.showwarning("Attention", "Pas de connexion établie!")
        return
    
    try:
        # Utilisation de votre cryptage pour chiffrer
        message_chiffre = chiffrer_message(message, crypto_key)
        
        data = json.dumps({
            'user': nom_utilisateur,
            'message': message_chiffre
        })
        connection.send(data.encode('utf-8'))
        
        zone_messages.config(state="normal")
        zone_messages.insert("end", f"{nom_utilisateur}: {message}\n")
        zone_messages.config(state="disabled")
        zone_messages.see("end")
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