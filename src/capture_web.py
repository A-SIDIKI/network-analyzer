"""
Capture spécifique : HTTP, HTTPS, DNS
"""

from scapy.all import sniff, wrpcap

def afficher_paquet(paquet):
    """Affiche les infos des paquets capturés."""
    if paquet.haslayer("IP"):
        ip_src = paquet["IP"].src
        ip_dst = paquet["IP"].dst
        
        # Détection rapide
        proto = ""
        if paquet.haslayer("TCP"):
            sport = paquet["TCP"].sport
            dport = paquet["TCP"].dport
            if sport == 80 or dport == 80:
                proto = "🌐 HTTP"
            elif sport == 443 or dport == 443:
                proto = "🔒 HTTPS"
            else:
                proto = f"TCP:{sport}→{dport}"
        elif paquet.haslayer("UDP"):
            sport = paquet["UDP"].sport
            dport = paquet["UDP"].dport
            if sport == 53 or dport == 53:
                proto = "📧 DNS"
            else:
                proto = f"UDP:{sport}→{dport}"
        
        print(f"{proto} : {ip_src} → {ip_dst}")

print("=== CAPTURE WEB (HTTP/HTTPS/DNS) ===")
print("Appuie sur Ctrl+C pour arrêter")
print("Pendant la capture, ouvre des sites web !")
print()

# Filtrer : seulement HTTP, HTTPS, DNS
paquets = sniff(prn=afficher_paquet, filter="port 80 or port 443 or port 53")

print(f"\n✅ {len(paquets)} paquets sauvegardés")

# Sauvegarder
wrpcap("capture_web.pcap", paquets)
print("💾 Sauvegardé dans capture_web.pcap")