"""
Application Web - Tableau de bord réseau
Jour 4 : Interface Flask pour visualiser les statistiques
"""

from flask import Flask, render_template, jsonify, request
from scapy.all import rdpcap
import pandas as pd
import os
import matplotlib
matplotlib.use('Agg')  # Mode non-interactif (pour serveur web)
import matplotlib.pyplot as plt
import io
import base64

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pcap'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Créer le dossier uploads s'il n'existe pas
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def detecter_protocole(paquet):
    """Détecte le protocole applicatif."""
    if not paquet.haslayer("IP"):
        return "NON-IP"
    
    if paquet.haslayer("TCP"):
        if paquet["TCP"].sport == 80 or paquet["TCP"].dport == 80:
            return "HTTP"
        if paquet["TCP"].sport == 443 or paquet["TCP"].dport == 443:
            return "HTTPS"
        if paquet["TCP"].sport == 53 or paquet["TCP"].dport == 53:
            return "DNS"
    
    elif paquet.haslayer("UDP"):
        if paquet["UDP"].sport == 53 or paquet["UDP"].dport == 53:
            return "DNS"
        if paquet["UDP"].sport == 67 or paquet["UDP"].dport == 67 or \
           paquet["UDP"].sport == 68 or paquet["UDP"].dport == 68:
            return "DHCP"
    
    return "AUTRE"

def analyser_fichier(chemin_fichier):
    """Analyse un fichier .pcap et retourne les statistiques."""
    try:
        paquets = rdpcap(chemin_fichier)
        total = len(paquets)
        
        # Compter les protocoles
        comptage = {"HTTP": 0, "HTTPS": 0, "DNS": 0, "DHCP": 0, "AUTRE": 0, "NON-IP": 0}
        
        for paquet in paquets:
            proto = detecter_protocole(paquet)
            if proto in comptage:
                comptage[proto] += 1
            else:
                comptage["AUTRE"] += 1
        
        # Statistiques supplémentaires
        ip_sources = {}
        ip_destinations = {}
        
        for paquet in paquets:
            if paquet.haslayer("IP"):
                ip_src = paquet["IP"].src
                ip_dst = paquet["IP"].dst
                ip_sources[ip_src] = ip_sources.get(ip_src, 0) + 1
                ip_destinations[ip_dst] = ip_destinations.get(ip_dst, 0) + 1
        
        # Top 5 IP
        top_sources = sorted(ip_sources.items(), key=lambda x: x[1], reverse=True)[:5]
        top_destinations = sorted(ip_destinations.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "total": total,
            "protocoles": comptage,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "success": True
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

def generer_graphique(repartition):
    """Génère un graphique à partir des données."""
    # Filtrer les protocoles avec des paquets > 0
    data = {k: v for k, v in repartition.items() if v > 0}
    
    if not data:
        return None
    
    fig, ax = plt.subplots(figsize=(8, 6))
    
    # Créer le graphique en camembert
    couleurs = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD']
    wedges, texts, autotexts = ax.pie(
        data.values(),
        labels=data.keys(),
        autopct='%1.1f%%',
        colors=couleurs[:len(data)],
        startangle=90
    )
    
    ax.set_title('Répartition des protocoles réseau')
    
    # Sauvegarder en base64 pour l'affichage web
    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight')
    img.seek(0)
    plt.close()
    
    return base64.b64encode(img.getvalue()).decode()

@app.route('/')
def index():
    """Page d'accueil."""
    return render_template('index.html')

@app.route('/analyser', methods=['POST'])
def analyser():
    """Endpoint pour analyser un fichier."""
    if 'fichier' not in request.files:
        return jsonify({"success": False, "error": "Aucun fichier fourni"})
    
    fichier = request.files['fichier']
    
    if fichier.filename == '':
        return jsonify({"success": False, "error": "Nom de fichier vide"})
    
    # Sauvegarder le fichier
    chemin = os.path.join(app.config['UPLOAD_FOLDER'], fichier.filename)
    fichier.save(chemin)
    
    # Analyser
    resultat = analyser_fichier(chemin)
    
    if resultat["success"]:
        # Générer le graphique
        graphique = generer_graphique(resultat["protocoles"])
        resultat["graphique"] = graphique
    
    return jsonify(resultat)

@app.route('/api/stats/<filename>')
def api_stats(filename):
    """API pour récupérer les stats d'un fichier."""
    chemin = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(chemin):
        return jsonify({"success": False, "error": "Fichier introuvable"})
    
    return jsonify(analyser_fichier(chemin))

@app.route('/fichiers')
def fichiers():
    """Liste les fichiers disponibles."""
    fichiers = []
    for f in os.listdir('.'):
        if f.endswith('.pcap'):
            fichiers.append(f)
    return jsonify(fichiers)

if __name__ == '__main__':
    print("🌐 Démarrage du serveur web...")
    print("📊 Tableau de bord disponible sur : http://127.0.0.1:5000")
    print("Appuie sur Ctrl+C pour arrêter")
    app.run(debug=True, host='0.0.0.0', port=5000)