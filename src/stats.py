"""
Analyseur réseau - Script de statistiques
Jour 2 : Analyse de capture avec Pandas
"""

from scapy.all import rdpcap
import pandas as pd
import os

def analyser_capture(nom_fichier="capture.pcap"):
    """
    Analyse un fichier .pcap et retourne un DataFrame Pandas
    avec les statistiques.
    """
    print(f"📂 Lecture de {nom_fichier}...")
    
    # Vérifier si le fichier existe
    if not os.path.exists(nom_fichier):
        print(f"❌ Erreur : {nom_fichier} n'existe pas !")
        return None
    
    # Lire tous les paquets du fichier pcap
    paquets = rdpcap(nom_fichier)
    print(f"✅ {len(paquets)} paquets chargés")
    
    # Créer une liste pour stocker les données
    donnees = []
    
    for paquet in paquets:
        # Informations de base
        info = {
            "timestamp": paquet.time,
            "taille": len(paquet)
        }
        
        # Extraire les infos IP si disponibles
        if paquet.haslayer("IP"):
            info["ip_src"] = paquet["IP"].src
            info["ip_dst"] = paquet["IP"].dst
            info["proto"] = paquet["IP"].proto
            
            # Traduire le protocole en nom
            protocoles = {1: "ICMP", 6: "TCP", 17: "UDP"}
            info["proto_nom"] = protocoles.get(paquet["IP"].proto, "AUTRE")
            
            # Extraire les ports TCP/UDP
            if paquet.haslayer("TCP"):
                info["port_src"] = paquet["TCP"].sport
                info["port_dst"] = paquet["TCP"].dport
                info["proto_detail"] = "TCP"
            elif paquet.haslayer("UDP"):
                info["port_src"] = paquet["UDP"].sport
                info["port_dst"] = paquet["UDP"].dport
                info["proto_detail"] = "UDP"
            else:
                info["port_src"] = None
                info["port_dst"] = None
                info["proto_detail"] = "AUTRE"
        else:
            # Paquet non-IP (ex: ARP)
            info["ip_src"] = "Non-IP"
            info["ip_dst"] = "Non-IP"
            info["proto"] = None
            info["proto_nom"] = "NON-IP"
            info["port_src"] = None
            info["port_dst"] = None
            info["proto_detail"] = "NON-IP"
        
        donnees.append(info)
    
    # Convertir en DataFrame Pandas
    df = pd.DataFrame(donnees)
    
   # Convertir le timestamp en flottant puis en datetime
    df["timestamp_lisible"] = pd.to_datetime(df["timestamp"].astype(float), unit="s")
    
    return df

def calculer_statistiques(df):
    """
    Calcule les statistiques à partir du DataFrame.
    """
    print("\n" + "="*50)
    print("📊 STATISTIQUES DE LA CAPTURE")
    print("="*50)
    
    # 1. Nombre total de paquets
    total = len(df)
    print(f"📦 Total paquets : {total}")
    
    # 2. Répartition par protocole
    print("\n📈 Répartition par protocole :")
    repartition = df["proto_nom"].value_counts()
    print(repartition)
    
    # 3. Top 5 des IP sources
    print("\n🔝 Top 5 IP sources :")
    top_src = df["ip_src"].value_counts().head(5)
    print(top_src)
    
    # 4. Top 5 des IP destinations
    print("\n🔝 Top 5 IP destinations :")
    top_dst = df["ip_dst"].value_counts().head(5)
    print(top_dst)
    
    # 5. Taille moyenne des paquets
    taille_moyenne = df["taille"].mean()
    taille_min = df["taille"].min()
    taille_max = df["taille"].max()
    print(f"\n📏 Statistiques des tailles :")
    print(f"   Moyenne : {taille_moyenne:.2f} octets")
    print(f"   Minimum : {taille_min} octets")
    print(f"   Maximum : {taille_max} octets")
    
    # 6. Ports les plus utilisés (si disponibles)
    ports_utilises = pd.concat([df["port_src"], df["port_dst"]]).dropna()
    if not ports_utilises.empty:
        print("\n🔌 Top 5 ports les plus utilisés :")
        print(ports_utilises.value_counts().head(5))
    
    print("\n" + "="*50)
    
    return {
        "total": total,
        "repartition": repartition,
        "top_src": top_src,
        "top_dst": top_dst,
        "taille_moyenne": taille_moyenne,
        "taille_min": taille_min,
        "taille_max": taille_max
    }

def exporter_csv(df, nom_fichier="statistiques.csv"):
    """
    Exporte les données en CSV.
    """
    # Sélectionner les colonnes à exporter
    colonnes = ["timestamp_lisible", "ip_src", "ip_dst", "proto_nom", 
                "proto_detail", "port_src", "port_dst", "taille"]
    
    df_export = df[colonnes]
    
    # Exporter en CSV
    df_export.to_csv(nom_fichier, index=False, encoding="utf-8")
    print(f"\n💾 Données exportées dans {nom_fichier}")
    
    # Afficher un aperçu
    print(f"   {len(df_export)} lignes exportées")
    print(f"   Colonnes : {', '.join(df_export.columns)}")

def main():
    """
    Fonction principale.
    """
    print("=== ANALYSEUR RÉSEAU - STATISTIQUES ===")
    
    # Demander le fichier à analyser
    fichier = input("Fichier .pcap à analyser (défaut: capture.pcap) : ")
    if not fichier:
        fichier = "capture.pcap"
    
    # Analyser la capture
    df = analyser_capture(fichier)
    
    if df is not None and not df.empty:
        # Calculer les statistiques
        stats = calculer_statistiques(df)
        
        # Exporter en CSV
        exporter_csv(df)
        
        # Résumé
        print("\n✅ Analyse terminée !")
        print(f"   📊 {stats['total']} paquets analysés")
        print(f"   📁 Fichier généré : statistiques.csv")
    else:
        print("❌ Aucune donnée à analyser")

if __name__ == "__main__":
    main()
    