"""
Analyseur réseau - Script de capture
Jour 1 : Capture de paquets avec Scapy
"""

from scapy.all import sniff, wrpcap

def afficher_paquet(paquet):
    """
    Fonction appelée pour chaque paquet capturé.
    Affiche les informations essentielles.
    """
    if paquet.haslayer("IP"):
        ip_src = paquet["IP"].src
        ip_dst = paquet["IP"].dst
        proto = paquet["IP"].proto
        
        protocoles = {1: "ICMP", 6: "TCP", 17: "UDP"}
        nom_proto = protocoles.get(proto, f"Proto{proto}")
        
        print(f"{nom_proto} : {ip_src} → {ip_dst}")
    else:
        print("Paquet non-IP (ex: ARP)")

def capturer_paquets(nombre=10):
    """
    Capture 'nombre' paquets et les sauvegarde.
    """
    print(f"=== CAPTURE DE {nombre} PAQUETS ===")
    print("Appuie sur Ctrl+C pour arrêter plus tôt")
    
    paquets = sniff(count=nombre, prn=afficher_paquet)
    
    nom_fichier = "capture.pcap"
    wrpcap(nom_fichier, paquets)
    print(f"\n✅ {len(paquets)} paquets sauvegardés dans {nom_fichier}")
    
    return paquets

if __name__ == "__main__":
    print("=== ANALYSEUR RÉSEAU - CAPTURE ===")
    
    try:
        saisie = input("Nombre de paquets à capturer (défaut: 10) : ")
        n = int(saisie) if saisie else 10
    except ValueError:
        print("Valeur invalide, utilisation de 10")
        n = 10
    
    capturer_paquets(n)
    print("=== FIN DE LA CAPTURE ===")