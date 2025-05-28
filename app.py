import os
import yaml
import logging
from flask import Flask, request, jsonify, render_template, send_file, Response, redirect, url_for, session, g, abort
from dotenv import load_dotenv
import requests
from prometheus_client import Counter as PromCounter, Histogram
import time
import json
import mimetypes
import io
from sqlalchemy import create_engine, Column, Integer, String, LargeBinary, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from passlib.hash import bcrypt
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from collections import Counter as PyCounter

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Metrics
REQUEST_COUNT = PromCounter('http_requests_total', 'Total HTTP requests')
REQUEST_LATENCY = Histogram('http_request_duration_seconds', 'HTTP request latency')

# Development mode storage (in-memory)
class DevStorage:
    def __init__(self):
        self.storage = {}
        self.cache = {}

    def put_object(self, Bucket, Key, Body):
        self.storage[Key] = Body
        return True

    def get_object(self, Bucket, Key):
        if Key in self.storage:
            return {'Body': self.storage[Key]}
        raise Exception("Object not found")

    def list_objects(self):
        return list(self.storage.keys())

# Cache management
class CacheManager:
    def __init__(self):
        self.storage = DevStorage()
        self.ibm_config = {
            'bucket_name': 'dev-bucket',
            'region': 'dev-region'
        }
        self.akamai_config = {
            'base_url': 'http://localhost:8080'
        }

    def purge_cache(self, path):
        """Mock cache purge"""
        logger.info(f"Mock: Purging cache for {path}")
        return {"status": "success", "message": "Cache purged"}

    def upload_to_cos(self, file_path, content):
        """Upload content to development storage"""
        try:
            self.storage.put_object(
                Bucket=self.ibm_config['bucket_name'],
                Key=file_path,
                Body=content
            )
            return True
        except Exception as e:
            logger.error(f"Error uploading to storage: {str(e)}")
            return False

cache_manager = CacheManager()

# Database setup
Base = declarative_base()
DB_PATH = 'sqlite:///cdn_app.db'
engine = create_engine(DB_PATH, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    files = relationship('File', back_populates='user')

    def set_password(self, password):
        self.password_hash = bcrypt.hash(password)

    def check_password(self, password):
        return bcrypt.verify(password, self.password_hash)

class File(Base):
    __tablename__ = 'files'
    id = Column(Integer, primary_key=True)
    filename = Column(String(256), nullable=False)
    content_type = Column(String(128))
    user_id = Column(Integer, ForeignKey('users.id'))
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    user = relationship('User', back_populates='files')

# Create tables if not exist
Base.metadata.create_all(engine)

app.secret_key = os.getenv('SECRET_KEY', 'devsecret')

# Helper: get current user
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None
    if user_id is not None:
        db = SessionLocal()
        g.user = db.query(User).filter_by(id=user_id).first()
        db.close()

@app.route('/')
def index():
    if not g.user:
        return redirect(url_for('signup'))
    return render_template('index.html')

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "mode": "development"})

@app.route('/content/list')
def list_content():
    if not g.user:
        return jsonify({"files": []})
    try:
        db = SessionLocal()
        files = db.query(File).filter_by(user_id=g.user.id).order_by(File.uploaded_at.desc()).all()
        file_list = [{
            'id': f.id,
            'filename': f.filename,
            'content_type': f.content_type,
            'uploaded_at': f.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')
        } for f in files]
        db.close()
        return jsonify({"files": file_list})
    except Exception as e:
        logger.error(f"Error listing content: {str(e)}")
        return jsonify({"error": "Failed to list content"}), 500

@app.route('/content/<path:file_path>', methods=['GET'])
@REQUEST_LATENCY.time()
def get_content(file_path):
    REQUEST_COUNT.inc()
    try:
        # Get content from development storage
        response = cache_manager.storage.get_object(
            Bucket=cache_manager.ibm_config['bucket_name'],
            Key=file_path
        )
        content = response['Body']
        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = 'application/octet-stream'
        # If it's a text file, return as JSON
        if mime_type.startswith('text') or mime_type == 'application/json':
            return jsonify({
                'content': content.decode('utf-8', errors='replace'),
                'mime_type': mime_type
            })
        # Otherwise, return as binary
        return Response(content, mimetype=mime_type)
    except Exception as e:
        logger.error(f"Error retrieving content: {str(e)}")
        return jsonify({"error": "Content not found"}), 404

@app.route('/content/<path:file_path>', methods=['PUT'])
def upload_content(file_path):
    if not g.user:
        return jsonify({"error": "Login required"}), 401
    if not request.data:
        return jsonify({"error": "No content provided"}), 400
    try:
        # Upload to development storage
        if cache_manager.upload_to_cos(file_path, request.data):
            # Save file metadata in DB
            db = SessionLocal()
            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = 'application/octet-stream'
            file_entry = File(filename=file_path, content_type=mime_type, user_id=g.user.id)
            db.add(file_entry)
            db.commit()
            db.close()
            # Mock cache purge
            cache_manager.purge_cache(file_path)
            return jsonify({"message": "File uploaded successfully"})
        return jsonify({"error": "Failed to upload file"}), 500
    except Exception as e:
        logger.error(f"Error uploading file: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return render_template('signup.html', error='Username and password are required.')
        db = SessionLocal()
        try:
            if db.query(User).filter_by(username=username).first():
                db.close()
                return render_template('signup.html', error='Username already exists.')
            user = User(username=username)
            user.set_password(password)
            db.add(user)
            db.commit()
            db.close()
            return redirect(url_for('index'))
        except IntegrityError:
            db.rollback()
            db.close()
            return render_template('signup.html', error='Username already exists.')
        except Exception as e:
            db.rollback()
            db.close()
            return render_template('signup.html', error='An error occurred. Please try again.')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = SessionLocal()
        user = db.query(User).filter_by(username=username).first()
        db.close()
        if user and user.check_password(password):
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/file/<int:file_id>', methods=['GET'])
def file_details(file_id):
    if not g.user:
        abort(401)
    db = SessionLocal()
    file = db.query(File).filter_by(id=file_id, user_id=g.user.id).first()
    db.close()
    if not file:
        abort(404)
    return jsonify({
        'id': file.id,
        'filename': file.filename,
        'content_type': file.content_type,
        'uploaded_at': file.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/file/<int:file_id>/delete', methods=['POST'])
def delete_file(file_id):
    if not g.user:
        abort(401)
    db = SessionLocal()
    file = db.query(File).filter_by(id=file_id, user_id=g.user.id).first()
    if not file:
        db.close()
        abort(404)
    # Remove from storage
    try:
        if file.filename in cache_manager.storage.storage:
            del cache_manager.storage.storage[file.filename]
        db.delete(file)
        db.commit()
        db.close()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        db.close()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/file/<int:file_id>/rename', methods=['POST'])
def rename_file(file_id):
    if not g.user:
        abort(401)
    new_name = request.json.get('new_name')
    if not new_name:
        return jsonify({'success': False, 'error': 'New name required'}), 400
    db = SessionLocal()
    file = db.query(File).filter_by(id=file_id, user_id=g.user.id).first()
    if not file:
        db.close()
        abort(404)
    # Rename in storage
    try:
        if file.filename in cache_manager.storage.storage:
            cache_manager.storage.storage[new_name] = cache_manager.storage.storage.pop(file.filename)
        file.filename = new_name
        db.commit()
        db.close()
        return jsonify({'success': True, 'new_name': new_name})
    except Exception as e:
        db.rollback()
        db.close()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/dashboard-data')
def dashboard_data():
    if not g.user:
        return jsonify({"uploads": [], "types": {}})
    db = SessionLocal()
    files = db.query(File).filter_by(user_id=g.user.id).all()
    db.close()
    # Uploads over time (by date)
    uploads = {}
    for f in files:
        date_str = f.uploaded_at.strftime('%Y-%m-%d')
        uploads[date_str] = uploads.get(date_str, 0) + 1
    # File type distribution
    types = PyCounter(f.content_type.split('/')[0] if f.content_type else 'other' for f in files)
    return jsonify({
        "uploads": sorted(uploads.items()),
        "types": dict(types)
    })

if __name__ == '__main__':
    logger.info("Starting application in development mode")
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)), debug=True) 