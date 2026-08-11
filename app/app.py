"""
Application Web - Tableau de bord réseau avancé
Avec filtres, timeline, export PDF et capture en direct
"""

from flask import Flask, render_template, jsonify, request, send_file
from scapy.all import rdpcap, sniff, wrpcap
import pandas as pd
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64
import json
from datetime import datetime
import threading
import time
import tempfile

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pcap'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'votre-cle-secrete-ici'

# État de la capture en direct
capture_active = False
paquets_captures = []
capture_lock = threading.Lock()

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
        if paquet["TCP"].sport == 22 or paquet["TCP"].dport == 22:
            return "SSH"
        if paquet["TCP"].sport == 25 or paquet["TCP"].dport == 25:
            return "SMTP"
    
    elif paquet.haslayer("UDP"):
        if paquet["UDP"].sport == 53 or paquet["UDP"].dport == 53:
            return "DNS"
        if paquet["UDP"].sport == 67 or paquet["UDP"].dport == 67 or \
           paquet["UDP"].sport == 68 or paquet["UDP"].dport == 68:
            return "DHCP"
    
    return "AUTRE"

def analyser_fichier(chemin_fichier, filtre=None):
    """Analyse un fichier .pcap avec option de filtrage."""
    try:
        paquets = rdpcap(chemin_fichier)
        total = len(paquets)
        
        # Compter les protocoles
        comptage = {"HTTP": 0, "HTTPS": 0, "DNS": 0, "DHCP": 0, "SSH": 0, "SMTP": 0, "AUTRE": 0, "NON-IP": 0}
        
        # Timeline (groupé par secondes)
        timeline = {}
        ip_sources = {}
        ip_destinations = {}
        ports_utilises = {}
        
        for paquet in paquets:
            proto = detecter_protocole(paquet)
            
            # Appliquer le filtre
            if filtre and filtre != "TOUS" and proto != filtre:
                continue
            
            if proto in comptage:
                comptage[proto] += 1
            else:
                comptage["AUTRE"] += 1
            
            # Timeline
            timestamp = int(paquet.time)
            if timestamp in timeline:
                timeline[timestamp] += 1
            else:
                timeline[timestamp] = 1
            
            # IP
            if paquet.haslayer("IP"):
                ip_src = paquet["IP"].src
                ip_dst = paquet["IP"].dst
                ip_sources[ip_src] = ip_sources.get(ip_src, 0) + 1
                ip_destinations[ip_dst] = ip_destinations.get(ip_dst, 0) + 1
            
            # Ports
            if paquet.haslayer("TCP"):
                ports_utilises[paquet["TCP"].sport] = ports_utilises.get(paquet["TCP"].sport, 0) + 1
                ports_utilises[paquet["TCP"].dport] = ports_utilises.get(paquet["TCP"].dport, 0) + 1
            elif paquet.haslayer("UDP"):
                ports_utilises[paquet["UDP"].sport] = ports_utilises.get(paquet["UDP"].sport, 0) + 1
                ports_utilises[paquet["UDP"].dport] = ports_utilises.get(paquet["UDP"].dport, 0) + 1
        
        # Top 5
        top_sources = sorted(ip_sources.items(), key=lambda x: x[1], reverse=True)[:10]
        top_destinations = sorted(ip_destinations.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ports = sorted(ports_utilises.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Timeline (pour le graphique)
        timeline_items = sorted(timeline.items())
        
        return {
            "total": total,
            "protocoles": comptage,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "top_ports": top_ports,
            "timeline": timeline_items,
            "success": True
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

def generer_graphique_pie(repartition):
    """Génère un graphique en camembert."""
    data = {k: v for k, v in repartition.items() if v > 0}
    if not data:
        return None
    
    fig, ax = plt.subplots(figsize=(8, 6))
    couleurs = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#FF9FF3', '#54A0FF']
    wedges, texts, autotexts = ax.pie(
        data.values(),
        labels=data.keys(),
        autopct='%1.1f%%',
        colors=couleurs[:len(data)],
        startangle=90
    )
    ax.set_title('Répartition des protocoles réseau')
    
    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight')
    img.seek(0)
    plt.close()
    return base64.b64encode(img.getvalue()).decode()

def generer_graphique_timeline(timeline):
    """Génère un graphique de la timeline."""
    if not timeline:
        return None
    
    temps, valeurs = zip(*timeline)
    
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(temps, valeurs, color='#4ECDC4', linewidth=2)
    ax.fill_between(temps, valeurs, alpha=0.3, color='#4ECDC4')
    ax.set_xlabel('Temps (secondes)')
    ax.set_ylabel('Nombre de paquets')
    ax.set_title('Évolution du trafic réseau')
    ax.grid(True, alpha=0.3)
    
    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight')
    img.seek(0)
    plt.close()
    return base64.b64encode(img.getvalue()).decode()

def generer_graphique_ports(top_ports):
    """Génère un graphique des ports les plus utilisés."""
    if not top_ports:
        return None
    
    ports, valeurs = zip(*top_ports[:10])
    
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar([str(p) for p in ports], valeurs, color='#45B7D1')
    ax.set_xlabel('Ports')
    ax.set_ylabel('Nombre de paquets')
    ax.set_title('Top 10 des ports utilisés')
    ax.tick_params(axis='x', rotation=45)
    
    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight')
    img.seek(0)
    plt.close()
    return base64.b64encode(img.getvalue()).decode()

def generer_rapport_pdf(resultat, nom_fichier):
    """Génère un rapport PDF (simplifié)."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
    
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    c = canvas.Canvas(temp_file.name, pagesize=letter)
    
    # Titre
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, 750, f"Rapport d'analyse réseau - {nom_fichier}")
    
    # Date
    c.setFont("Helvetica", 10)
    c.drawString(72, 730, f"Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Statistiques
    y = 680
    c.setFont("Helvetica-Bold", 12)
    c.drawString(72, y, "Statistiques générales")
    y -= 25
    c.setFont("Helvetica", 10)
    c.drawString(72, y, f"Total paquets : {resultat['total']}")
    y -= 20
    
    c.drawString(72, y, "Protocoles détectés :")
    y -= 20
    for proto, count in resultat['protocoles'].items():
        if count > 0:
            c.drawString(72, y, f"  {proto}: {count} paquets")
            y -= 20
    
    c.save()
    return temp_file.name

# Routes Flask

@app.route('/')
def index():
    """Page d'accueil."""
    return render_template('index.html')

@app.route('/analyser', methods=['POST'])
def analyser():
    """Analyse un fichier uploadé."""
    if 'fichier' not in request.files:
        return jsonify({"success": False, "error": "Aucun fichier fourni"})
    
    fichier = request.files['fichier']
    if fichier.filename == '':
        return jsonify({"success": False, "error": "Nom de fichier vide"})
    
    # Sauvegarder
    chemin = os.path.join(app.config['UPLOAD_FOLDER'], fichier.filename)
    fichier.save(chemin)
    
    # Récupérer le filtre
    filtre = request.form.get('filtre', 'TOUS')
    
    # Analyser
    resultat = analyser_fichier(chemin, filtre)
    
    if resultat["success"]:
        # Générer les graphiques
        resultat["graphique_pie"] = generer_graphique_pie(resultat["protocoles"])
        resultat["graphique_timeline"] = generer_graphique_timeline(resultat["timeline"])
        resultat["graphique_ports"] = generer_graphique_ports(resultat["top_ports"])
    
    return jsonify(resultat)

@app.route('/export_pdf', methods=['POST'])
def export_pdf():
    """Exporte les résultats en PDF."""
    data = request.json
    if not data or 'resultat' not in data:
        return jsonify({"success": False, "error": "Données manquantes"})
    
    try:
        pdf_path = generer_rapport_pdf(data['resultat'], data.get('nom', 'analyse'))
        return send_file(pdf_path, as_attachment=True, download_name='rapport_analyse.pdf')
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/capture_start', methods=['POST'])
def capture_start():
    """Démarre une capture en direct."""
    global capture_active, paquets_captures
    
    with capture_lock:
        if capture_active:
            return jsonify({"success": False, "error": "Capture déjà en cours"})
        
        capture_active = True
        paquets_captures = []
        
        def capturer():
            global capture_active, paquets_captures
            def callback(paquet):
                with capture_lock:
                    paquets_captures.append(paquet)
            
            sniff(prn=callback, stop_filter=lambda x: not capture_active)
        
        thread = threading.Thread(target=capturer)
        thread.daemon = True
        thread.start()
        
        return jsonify({"success": True, "message": "Capture démarrée"})

@app.route('/capture_stop', methods=['POST'])
def capture_stop():
    """Arrête la capture en direct."""
    global capture_active, paquets_captures
    
    with capture_lock:
        if not capture_active:
            return jsonify({"success": False, "error": "Aucune capture en cours"})
        
        capture_active = False
        nb_paquets = len(paquets_captures)
        
        # Sauvegarder si des paquets ont été capturés
        if nb_paquets > 0:
            nom_fichier = f"capture_live_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            chemin = os.path.join(app.config['UPLOAD_FOLDER'], nom_fichier)
            wrpcap(chemin, paquets_captures)
        
        return jsonify({
            "success": True,
            "paquets": nb_paquets,
            "fichier": nom_fichier if nb_paquets > 0 else None
        })

@app.route('/capture_status')
def capture_status():
    """Retourne l'état de la capture."""
    global capture_active, paquets_captures
    
    with capture_lock:
        return jsonify({
            "active": capture_active,
            "paquets": len(paquets_captures)
        })

@app.route('/api/stats/<filename>')
def api_stats(filename):
    """API pour récupérer les stats d'un fichier."""
    chemin = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(chemin):
        return jsonify({"success": False, "error": "Fichier introuvable"})
    
    filtre = request.args.get('filtre', 'TOUS')
    return jsonify(analyser_fichier(chemin, filtre))

@app.route('/fichiers')
def fichiers():
    """Liste les fichiers disponibles."""
    fichiers = []
    for f in os.listdir(UPLOAD_FOLDER):
        if f.endswith('.pcap'):
            fichiers.append({
                'nom': f,
                'taille': os.path.getsize(os.path.join(UPLOAD_FOLDER, f)),
                'date': datetime.fromtimestamp(os.path.getmtime(os.path.join(UPLOAD_FOLDER, f))).strftime('%Y-%m-%d %H:%M:%S')
            })
    return jsonify(fichiers)

if __name__ == '__main__':
    print("🌐 Démarrage du serveur web...")
    print("📊 Tableau de bord disponible sur : http://127.0.0.1:5000")
    print("Appuie sur Ctrl+C pour arrêter")
    app.run(debug=True, host='0.0.0.0', port=5000)