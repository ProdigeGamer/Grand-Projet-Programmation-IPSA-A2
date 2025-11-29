#Code fait en début de seance pour le codage de noobs
def encodage(texte, k):
    """Fonction pour chiffrer un texte avec décalage ASCII"""
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
    """Fonction pour déchiffrer un texte avec décalage ASCII"""
    phrase = ""
    for char in chiffres:  #je fais une boucle for pour convertir le code ascii - k en lettre
        newchar = chr(char - k)
        phrase += newchar
    return phrase




print(reconvertir)