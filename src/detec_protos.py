"""
Analyseur réseau - Détection des protocoles applicatifs
Jour 3 : HTTP, DNS, DHCP
"""

from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import os

def detecter_protocole(paquet):
    """
    Détecte le protocole applicatif d'un paquet.
    Retourne : HTTP, DNS, DHCP, ou AUTRE
    """
    # Vérifier si le paquet a une couche IP
    if not paquet.haslayer(IP):
        return "NON-IP"
    
    # Vérifier le protocole de transport (TCP ou UDP)
    if paquet.haslayer(TCP):
        # HTTP : port 80
        if paquet[TCP].sport == 80 or paquet[TCP].dport == 80:
            return "HTTP"
        
        # DNS sur TCP (rare mais possible pour les grosses requêtes)
        if paquet[TCP].sport == 53 or paquet[TCP].dport == 53:
            return "DNS"
    
    elif paquet.haslayer(UDP):
        # DNS sur UDP (le plus courant)
        if paquet[UDP].sport == 53 or paquet[UDP].dport == 53:
            return "DNS"
        
        # DHCP : ports 67 (serveur) et 68 (client)
        if paquet[UDP].sport == 67 or paquet[UDP].dport == 67 or \
           paquet[UDP].sport == 68 or paquet[UDP].dport == 68:
            return "DHCP"
    
    # Pour les paquets TCP/UDP non identifiés
    if paquet.haslayer(TCP) or paquet.haslayer(UDP):
        return "AUTRE (TCP/UDP)"
    
    return "AUTRE"

def analyser_capture(nom_fichier="capture.pcap"):
    """
    Analyse un fichier .pcap et retourne un DataFrame avec détection.
    """
    print(f"📂 Lecture de {nom_fichier}...")
    
    if not os.path.exists(nom_fichier):
        print(f"❌ Erreur : {nom_fichier} n'existe pas !")
        return None
    
    paquets = rdpcap(nom_fichier)
    print(f"✅ {len(paquets)} paquets chargés")
    
    donnees = []
    
    for paquet in paquets:
        info = {
            "timestamp": float(paquet.time),
            "taille": len(paquet),
            "proto_applicatif": detecter_protocole(paquet)
        }
        
        # Extraire les infos IP
        if paquet.haslayer(IP):
            info["ip_src"] = paquet[IP].src
            info["ip_dst"] = paquet[IP].dst
            info["proto_transport"] = "TCP" if paquet.haslayer(TCP) else "UDP" if paquet.haslayer(UDP) else "AUTRE"
            
            # Extraire les ports si TCP/UDP
            if paquet.haslayer(TCP):
                info["port_src"] = paquet[TCP].sport
                info["port_dst"] = paquet[TCP].dport
            elif paquet.haslayer(UDP):
                info["port_src"] = paquet[UDP].sport
                info["port_dst"] = paquet[UDP].dport
            else:
                info["port_src"] = None
                info["port_dst"] = None
        else:
            info["ip_src"] = "NON-IP"
            info["ip_dst"] = "NON-IP"
            info["proto_transport"] = "NON-IP"
            info["port_src"] = None
            info["port_dst"] = None
        
        donnees.append(info)
    
    df = pd.DataFrame(donnees)
    
    # Convertir le timestamp en format lisible
    df["timestamp_lisible"] = pd.to_datetime(df["timestamp"], unit="s")
    
    return df

def calculer_statistiques_protos(df):
    """
    Calcule les statistiques par protocole applicatif.
    """
    print("\n" + "="*60)
    print("📊 STATISTIQUES PAR PROTOCOLE APPLICATIF")
    print("="*60)
    
    # 1. Répartition des protocoles applicatifs
    print("\n📈 Répartition par protocole applicatif :")
    repartition = df["proto_applicatif"].value_counts()
    print(repartition)
    
    # 2. Pourcentages
    print("\n📊 Pourcentages :")
    pourcentages = (df["proto_applicatif"].value_counts(normalize=True) * 100).round(2)
    for proto, pct in pourcentages.items():
        print(f"   {proto}: {pct}%")
    
    # 3. Détail par protocole
    print("\n🔍 Détail par protocole :")
    
    for proto in df["proto_applicatif"].unique():
        df_proto = df[df["proto_applicatif"] == proto]
        nb_paquets = len(df_proto)
        print(f"\n   {proto}: {nb_paquets} paquets")
        
        if nb_paquets > 0:
            # Top IP source pour ce protocole
            top_src = df_proto["ip_src"].value_counts().head(3)
            if not top_src.empty:
                print(f"      Top IP sources: {dict(top_src)}")
            
            # Top IP destination pour ce protocole
            top_dst = df_proto["ip_dst"].value_counts().head(3)
            if not top_dst.empty:
                print(f"      Top IP destinations: {dict(top_dst)}")
    
    print("\n" + "="*60)

def exporter_csv_avec_protos(df, nom_fichier="protocoles_detectes.csv"):
    """
    Exporte les données en CSV avec les protocoles détectés.
    """
    colonnes = ["timestamp_lisible", "ip_src", "ip_dst", 
                "proto_transport", "port_src", "port_dst", 
                "proto_applicatif", "taille"]
    
    df_export = df[colonnes]
    df_export.to_csv(nom_fichier, index=False, encoding="utf-8")
    
    print(f"\n💾 Données exportées dans {nom_fichier}")
    print(f"   {len(df_export)} lignes exportées")
    print(f"   Colonnes : {', '.join(df_export.columns)}")

def resumer_analyse(df):
    """
    Affiche un résumé de l'analyse.
    """
    print("\n" + "="*60)
    print("📋 RÉSUMÉ DE L'ANALYSE")
    print("="*60)
    
    total = len(df)
    print(f"📦 Total paquets : {total}")
    
    # Compter les protocoles détectés
    comptage = df["proto_applicatif"].value_counts()
    
    # Catégoriser
    protos_connus = comptage.get("HTTP", 0) + comptage.get("DNS", 0) + comptage.get("DHCP", 0)
    
    print(f"   🌐 HTTP : {comptage.get('HTTP', 0)} paquets")
    print(f"   📧 DNS : {comptage.get('DNS', 0)} paquets")
    print(f"   🔧 DHCP : {comptage.get('DHCP', 0)} paquets")
    print(f"   ❓ Autres : {total - protos_connus} paquets")
    
    # Détection active
    if protos_connus > 0:
        print(f"\n✅ Protocoles détectés : {protos_connus/total*100:.1f}% du trafic")
    else:
        print("\n⚠️  Aucun protocole applicatif détecté")
        print("   (Capture peut-être insuffisante ou trafic limité)")
    
    print("="*60)

def main():
    """
    Fonction principale.
    """
    print("=== ANALYSEUR RÉSEAU - DÉTECTION DE PROTOCOLES APPLICATIFS ===")
    
    fichier = input("Fichier .pcap à analyser (défaut: capture.pcap) : ")
    if not fichier:
        fichier = "capture.pcap"
    
    df = analyser_capture(fichier)
    
    if df is not None and not df.empty:
        # Afficher les statistiques
        calculer_statistiques_protos(df)
        
        # Exporter en CSV
        exporter_csv_avec_protos(df)
        
        # Résumé
        resumer_analyse(df)
        
        print("\n✅ Analyse terminée !")
    else:
        print("❌ Aucune donnée à analyser")

if __name__ == "__main__":
    main()