# HoneyPot

HoneyPot is a Flask-based honeypot dashboard for simulating and monitoring HTTP, FTP, and SSH activity. It includes banner selection, live logs, file uploads, SQLite-backed activity storage, and optional ML-based threat scoring.

## Features

- Start and stop HTTP, FTP, and SSH honeypots from the dashboard
- Choose from preset service banners or use a custom banner
- View live connection stats and log messages
- Store activity in a local SQLite database and log file
- Upload and browse files served by the dashboard
- Display threat scores using the bundled ML models when available

## Requirements

- Python 3.10+
- pip

## Installation

```bash
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

The app starts on `http://127.0.0.1:5000` and listens on all interfaces by default.

## API Endpoints

- `GET /api/config` - Banner configuration
- `GET /api/status` - Current service status and counters
- `POST /api/start/<service>` - Start a honeypot service
- `POST /api/stop/<service>` - Stop a honeypot service
- `POST /api/log` - Add a log entry
- `GET /api/logs/db` - Read logs from the database
- `GET /api/ml/threat-scores` - View ML threat scoring output
- `POST /api/upload` - Upload a file
- `GET /api/uploads/list` - List uploaded files

## Project Structure

- `app.py` - Flask application and dashboard routes
- `http_honeypot.py` - HTTP honeypot implementation
- `ftp_honeypot.py` - FTP honeypot implementation
- `ssh_honeypot.py` - SSH honeypot implementation
- `db.py` - SQLite persistence helpers
- `ml_*.py` - ML helpers for classification and scoring
- `templates/` - HTML templates
- `static/` - JavaScript and CSS assets
- `uploads/` - Sample and uploaded files

## Notes

- The app creates or updates `honeypot_activity.log` and `honeypot_logs.db` at runtime.
- ML scoring falls back gracefully if the model files are missing or fail to load.
