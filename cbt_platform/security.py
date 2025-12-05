import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import secrets
from datetime import datetime, timedelta
import json

class CustomEncryption:
    def __init__(self, password=None):
        """
        Initialize encryption with a password.
        If no password provided, generates a random key.
        """
        if password:
            self.key = self._derive_key_from_password(password)
        else:
            self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def _derive_key_from_password(self, password):
        """Derive a key from a password using PBKDF2"""
        salt = b'static_salt_for_cbt_platform'  # In production, use dynamic salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_data(self, data):
        """Encrypt sensitive data"""
        if isinstance(data, str):
            data = data.encode()
        return self.cipher.encrypt(data)

    def decrypt_data(self, encrypted_data):
        """Decrypt sensitive data"""
        decrypted_data = self.cipher.decrypt(encrypted_data)
        return decrypted_data.decode()

class SecureSessionManager:
    def __init__(self):
        self.active_sessions = {}
    
    def create_secure_session(self, user_id, role):
        """Create a secure session token"""
        session_token = secrets.token_urlsafe(32)
        timestamp = datetime.now()
        self.active_sessions[session_token] = {
            'user_id': user_id,
            'role': role,
            'created_at': timestamp,
            'last_activity': timestamp,
            'ip_address': None
        }
        return session_token
    
    def validate_session(self, session_token, max_inactive_minutes=30):
        """Validate session and check for timeout"""
        if session_token not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_token]
        time_since_last_activity = datetime.now() - session['last_activity']
        
        if time_since_last_activity > timedelta(minutes=max_inactive_minutes):
            del self.active_sessions[session_token]
            return False
        
        # Update last activity
        session['last_activity'] = datetime.now()
        return True
    
    def destroy_session(self, session_token):
        """Destroy a session"""
        if session_token in self.active_sessions:
            del self.active_sessions[session_token]

class QuestionEncryption:
    def __init__(self):
        self.encryption_key = os.environ.get('CBT_ENCRYPTION_KEY', 'default_key_for_demo')
        self.cipher = CustomEncryption(self.encryption_key)
    
    def encrypt_question(self, question_data):
        """Encrypt question data before storing"""
        json_data = json.dumps(question_data)
        encrypted_data = self.cipher.encrypt_data(json_data)
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt_question(self, encrypted_question_data):
        """Decrypt question data for use"""
        encrypted_bytes = base64.b64decode(encrypted_question_data.encode('utf-8'))
        decrypted_json = self.cipher.decrypt_data(encrypted_bytes)
        return json.loads(decrypted_json)

class ExamProctoring:
    def __init__(self):
        self.active_exams = {}
    
    def start_exam_session(self, user_id, exam_id, duration_minutes):
        """Start a proctored exam session"""
        session_id = secrets.token_urlsafe(16)
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        
        self.active_exams[session_id] = {
            'user_id': user_id,
            'exam_id': exam_id,
            'start_time': datetime.now(),
            'end_time': end_time,
            'status': 'active',
            'violations': []
        }
        
        return session_id
    
    def check_exam_session(self, session_id):
        """Check if exam session is still valid"""
        if session_id not in self.active_exams:
            return {'valid': False, 'reason': 'Session not found'}
        
        session = self.active_exams[session_id]
        
        if datetime.now() > session['end_time']:
            session['status'] = 'expired'
            return {'valid': False, 'reason': 'Exam time expired'}
        
        return {'valid': True, 'time_remaining': session['end_time'] - datetime.now()}
    
    def record_violation(self, session_id, violation_type, details):
        """Record proctoring violation"""
        if session_id in self.active_exams:
            self.active_exams[session_id]['violations'].append({
                'timestamp': datetime.now(),
                'type': violation_type,
                'details': details
            })
    
    def end_exam_session(self, session_id):
        """End exam session and return results"""
        if session_id in self.active_exams:
            session = self.active_exams[session_id]
            session['status'] = 'completed'
            result = {
                'user_id': session['user_id'],
                'exam_id': session['exam_id'],
                'violations': session['violations'],
                'duration': datetime.now() - session['start_time']
            }
            del self.active_exams[session_id]
            return result
        return None

# Global instances
session_manager = SecureSessionManager()
exam_proctor = ExamProctoring()
question_encryption = QuestionEncryption()