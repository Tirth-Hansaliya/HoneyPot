from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import logging
import os
from http_honeypot import HTTPHoneypot
from ftp_honeypot import FTPHoneypot
from ssh_honeypot import SSHHoneypot

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
from werkzeug.utils import secure_filename

app.config['SECRET_KEY'] = 'secret!'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins='*')

# Global honeypot instances
honeypots = {
    'http': {'instance': None, 'thread': None, 'running': False, 'port': 8080},
    'ftp': {'instance': None, 'thread': None, 'running': False, 'port': 2121},
    'ssh': {'instance': None, 'thread': None, 'running': False, 'port': 2222}
}

# Stats
stats = {
    'http': 0,
    'ftp': 0,
    'ssh': 0,
    'total': 0
}

def log_callback(message):
    """Callback for honeypots to send logs to frontend"""
    # specific handling for log lines to parse stats
    service = 'unknown'
    if '[HTTP]' in message:
        service = 'http'
    elif '[FTP]' in message:
        service = 'ftp'
    elif '[SSH]' in message:
        service = 'ssh'
    
    if "Connection from" in message:
        if service in stats:
            stats[service] += 1
            stats['total'] = sum(stats[k] for k in ['http', 'ftp', 'ssh'])
            socketio.emit('stats_update', stats)

    # Log to file
    try:
        with open('honeypot_activity.log', 'a') as f:
            f.write(message + '\n')
    except Exception as e:
        print(f"Error writing to log file: {e}")

    socketio.emit('new_log', {'message': message})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    status = {service: data['running'] for service, data in honeypots.items()}
    return jsonify({
        'status': status,
        'stats': stats,
        'ports': {service: data['port'] for service, data in honeypots.items()},
        'uploaded_files': {
            'http': honeypots['http']['instance'].html_file if honeypots['http']['instance'] else None
        }
    })

@app.route('/api/start/<service>', methods=['POST'])
def start_service(service):
    if service not in honeypots:
        return jsonify({'error': 'Invalid service'}), 400
    
    if honeypots[service]['running']:
        return jsonify({'message': f'{service} already running'}), 200

    try:
        data = request.json
        port = int(data.get('port', honeypots[service]['port']))
        
        html_file = data.get('html_file')

        # Instantiate honeypot
        if service == 'http':
            hp = HTTPHoneypot(port=port, log_callback=log_callback, html_file=html_file)
        elif service == 'ftp':
            ftp_files_dir = data.get('ftp_files_dir', 'uploads')
            hp = FTPHoneypot(port=port, log_callback=log_callback, ftp_files_dir=ftp_files_dir)
        elif service == 'ssh':
            hp = SSHHoneypot(port=port, log_callback=log_callback)
            
        honeypots[service]['instance'] = hp
        honeypots[service]['port'] = port
        
        # Start in thread
        thread = threading.Thread(target=hp.start)
        thread.daemon = True
        thread.start()
        
        honeypots[service]['thread'] = thread
        honeypots[service]['running'] = True
        
        socketio.emit('status_update', {'service': service, 'running': True, 'port': port})
        return jsonify({'message': f'{service} started', 'port': port})
        
    except Exception as e:
        logger.error(f"Error starting {service}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop/<service>', methods=['POST'])
def stop_service(service):
    if service not in honeypots:
        return jsonify({'error': 'Invalid service'}), 400
        
    if not honeypots[service]['running']:
        return jsonify({'message': f'{service} is not running'}), 200

    try:
        if honeypots[service]['instance']:
            honeypots[service]['instance'].stop()
            
        honeypots[service]['running'] = False
        honeypots[service]['instance'] = None
        honeypots[service]['thread'] = None
        
        socketio.emit('status_update', {'service': service, 'running': False})
        return jsonify({'message': f'{service} stopped'})
        
    except Exception as e:
        logger.error(f"Error stopping {service}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    global stats
    stats = {'http': 0, 'ftp': 0, 'ssh': 0, 'total': 0}
    socketio.emit('stats_update', stats)
    socketio.emit('clear_logs')
    return jsonify({'message': 'Logs cleared'})

@app.route('/api/log', methods=['POST'])
def log_frontend_message():
    data = request.json
    message = data.get('message')
    if message:
        try:
            with open('honeypot_activity.log', 'a') as f:
                f.write(message + '\n')
            return jsonify({'status': 'logged'}), 200
        except Exception as e:
            print(f"Error writing to log file: {e}")
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'No message'}), 400

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return jsonify({'message': 'File uploaded successfully', 'filepath': filepath}), 200

@app.route('/uploads/<filename>')
def download_file(filename):
    """Serve uploaded files"""
    try:
        from flask import send_from_directory
        return send_from_directory(app.config['UPLOAD_FOLDER'], secure_filename(filename))
    except Exception as e:
        return jsonify({'error': f'File not found: {str(e)}'}), 404

@app.route('/api/uploads/list', methods=['GET'])
def list_uploads():
    """List all uploaded files"""
    try:
        files = []
        upload_dir = app.config['UPLOAD_FOLDER']
        if os.path.exists(upload_dir):
            for filename in os.listdir(upload_dir):
                filepath = os.path.join(upload_dir, filename)
                if os.path.isfile(filepath):
                    files.append({
                        'name': filename,
                        'url': f'/uploads/{filename}',
                        'size': os.path.getsize(filepath)
                    })
        return jsonify({'files': files}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
