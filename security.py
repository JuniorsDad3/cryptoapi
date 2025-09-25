import os
import json
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import time
from collections import defaultdict
from datetime import timedelta

SECRET_PASSPHRASE = os.getenv("FILE_ENCRYPTOR_PASSPHRASE", "supersecret123")
SALT = os.getenv("FILE_ENCRYPTOR_SALT", "default_salt").encode()

class FileEncryptor:
    def __init__(self, secret_passphrase: str, salt: bytes):
        # Derive AES-256 key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(secret_passphrase.encode()))
        self.fernet = Fernet(key)
    
    def encrypt_file(self, file_path):
        """Encrypt file with AES-256"""
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        encrypted_data = self.fernet.encrypt(file_data)
        
        encrypted_path = file_path + '.enc'
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        return encrypted_path
    
    def decrypt_stream(self, encrypted_stream):
        """Decrypt stream data"""
        encrypted_data = encrypted_stream.read()
        decrypted_data = self.fernet.decrypt(encrypted_data)
        return decrypted_data
    
    def hash_filename(self, filename):
        """Create secure filename hash"""
        return hashlib.sha256(filename.encode()).hexdigest()[:16]

class SecurityAudit:
    def __init__(self, log_dir='audit_logs'):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
    
    def log_security_event(self, event_type, user_id, details=None, severity="INFO"):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'severity': severity,
            'event_type': event_type,
            'user_id': user_id or 'anonymous',
            'details': details or {},
            'ip_address': '127.0.0.1'  # You might want to get real IP from request
        }
        log_file = os.path.join(self.log_dir, f"security_{datetime.utcnow().strftime('%Y-%m-%d')}.log")
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def get_recent_events(self, user_id, limit=10):
        """Get recent security events for user"""
        # Implementation for retrieving events
        return []
    
    def get_user_events(self, user_id, limit=50):
        """Get all security events for user"""
        # Implementation for retrieving user events
        return []
    
    def get_recent_logins(self, user_id, limit=10):
        """Get recent login events"""
        # Implementation for login history
        return []

class RateLimiter:
    def __init__(self):
        self.attempts = defaultdict(list)  # Use defaultdict for cleaner code

    def limit(self, max_attempts=5, window_seconds=60, by="ip"):
        """
        Rate limit decorator.
        :param max_attempts: Number of allowed attempts in window (ensure this is int)
        :param window_seconds: Time window in seconds
        :param by: "ip" or "user"
        """
        def decorator(f):
            from functools import wraps
            from flask import request, session
            from datetime import datetime, timedelta

            @wraps(f)
            def wrapper(*args, **kwargs):
                # Ensure max_attempts is integer
                try:
                    max_attempts_int = int(max_attempts)
                except (ValueError, TypeError):
                    max_attempts_int = 5  # Default fallback
                
                # Identify client
                if by == "ip":
                    key = request.remote_addr or "unknown_ip"
                else:
                    key = session.get("user_id", "anonymous")

                now = datetime.utcnow()
                window_start = now - timedelta(seconds=window_seconds)
                
                # Keep only recent attempts in window
                self.attempts[key] = [t for t in self.attempts[key] if t > window_start]

                if len(self.attempts[key]) >= max_attempts_int:
                    return "Too many requests. Please try again later.", 429

                self.attempts[key].append(now)
                return f(*args, **kwargs)

            return wrapper
        return decorator

file_encryptor = FileEncryptor(SECRET_PASSPHRASE, SALT)
security_audit = SecurityAudit()
rate_limiter = RateLimiter()
