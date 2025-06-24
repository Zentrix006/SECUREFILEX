from flask import Flask, render_template, request, send_file, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode
import io


app = Flask(__name__)
CORS(app)

def derive_key(password: str, salt: bytes = b'static_salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # ✅ CORRECT
    	length=32,
    	salt=salt,
    	iterations=100000,
    	backend=default_backend()
	)
    return urlsafe_b64encode(kdf.derive(password.encode()))

def estimate_time(size_bytes):
    return round(size_bytes / (10 * 1024 * 1024), 2)  # ~10MB/sec processing

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/estimate', methods=['POST'])
def estimate():
    size = int(request.form.get('size', 0))
    est = estimate_time(size)
    return {'estimated_time': est}

@app.route('/process', methods=['POST'])
def process_file():
    file = request.files.get('file')
    password = request.form.get('password')
    mode = request.form.get('mode')

    if not file or not password or mode not in ['encrypt', 'decrypt']:
        return jsonify({'error': 'Missing data'}), 400

    key = derive_key(password)
    fernet = Fernet(key)

    file_data = file.read()
    try:
        if mode == 'encrypt':
            processed_data = fernet.encrypt(file_data)
            filename = file.filename + '.afx'
        else:
            if not file.filename.endswith('.afx'):
                return jsonify({'error': 'Invalid file extension'}), 400
            processed_data = fernet.decrypt(file_data)
            filename = file.filename.replace('.afx', '')
    except:
        return jsonify({'error': 'Processing error'}), 400

    return send_file(
        io.BytesIO(processed_data),
        download_name=filename,
        as_attachment=True,
        mimetype='application/octet-stream'
    )

if __name__ == '__main__':
    app.run(debug=True)
