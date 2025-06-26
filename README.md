# RedIhm
Simple IHM for redteam engagement.

## Features

- ✅ Upload de fichiers `masscan`/`nmap` au format XML
- 📊 Tableau de bord avec :
  - IPs scannées
  - Ports ouverts (Top 10)
  - Tags personnalisés
  - Checklist & notes par machine
  - Priorité (faible, moyenne, élevée)
- 🔍 Filtres avancés : recherche par IP, tag, priorité
- 🕓 Timeline par IP (actions horodatées)
- ⚡ Interface unique en accordéon (Bootstrap 5)

## Installation

```bash
git clone https://github.com/ton-pseudo/redteam-ihm.git
cd redteam-ihm
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

## 📁 Project Structure

```bash
redihm/
├── app.py                # Application Flask principale
├── templates/
│   └── main.html         # Interface HTML unique
├── uploads/              # Dossier pour les fichiers XML
├── redteam.db            # Base SQLite (créée automatiquement)
├── requirements.txt      # Dépendances Python
```

## Usage

```bash
python app.py
# puis ouvrir http://localhost:5000 dans votre navigateur
```
