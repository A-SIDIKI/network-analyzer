# 🌐 Network Analyzer - Analyseur Réseau

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3.0-green)](https://flask.palletsprojects.com/)
[![Scapy](https://img.shields.io/badge/Scapy-2.5.0-orange)](https://scapy.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Un analyseur de trafic réseau complet avec interface web, développé en Python.

![Tableau de bord](screenshots/dashboard.png)

---

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Technologies utilisées](#-technologies-utilisées)
- [Installation](#-installation)
- [Structure du projet](#-structure-du-projet)
- [Utilisation](#-utilisation)
- [Captures d'écran](#-captures-décran)
- [Prochaine étapes](#-prochaines-étapes)
- [Licence](#-licence)

---

## 🎯 Fonctionnalités

### 🔍 Capture réseau
- Capture de paquets en temps réel avec Scapy
- Filtrage par protocole (HTTP, HTTPS, DNS, DHCP, SSH, SMTP)
- Sauvegarde en fichier `.pcap`

### 📊 Analyse et statistiques
- Répartition des protocoles (graphique en camembert)
- Top 10 des IP sources et destinations
- Top 10 des ports utilisés
- Timeline de l'évolution du trafic
- Export en CSV

### 🌐 Tableau de bord web
- Interface intuitive avec Flask
- Upload de fichiers `.pcap`
- Filtrage interactif
- Capture en direct depuis le navigateur
- Export de rapports en PDF

### 🛡️ Protocoles détectés
| Protocole | Port | Utilité |
|-----------|------|---------|
| 🌐 HTTP | 80 | Navigation web non sécurisée |
| 🔒 HTTPS | 443 | Navigation web sécurisée |
| 📧 DNS | 53 | Résolution de noms de domaines |
| 🔧 DHCP | 67/68 | Attribution d'IP automatique |
| 💻 SSH | 22 | Connexion sécurisée à distance |
| 📨 SMTP | 25 | Envoi d'emails |

---

## 🛠️ Technologies utilisées

| Technologie | Version | Utilisation |
|-------------|---------|-------------|
| **Python** | 3.8+ | Langage principal |
| **Scapy** | 2.5.0 | Capture et manipulation de paquets |
| **Pandas** | 2.0.3 | Analyse de données |
| **Flask** | 2.3.0 | Serveur web |
| **Matplotlib** | 3.7.0 | Génération de graphiques |
| **ReportLab** | 4.0.0 | Export PDF |
| **HTML5/CSS3** | - | Interface utilisateur |

---

## 🚀 Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/A-SIDIKI/network-analyzer.git
cd network-analyzer