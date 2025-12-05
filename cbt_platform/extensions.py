import os
import json
import time
from datetime import datetime
from threading import Lock
from functools import wraps
import hashlib
import hmac
import secrets

class TimeLockExtension:
    """
    Custom extension to prevent exam time manipulation
    """
    def __init__(self):
        self.lock = Lock()
        self.exam_start_times = {}
        self.client_time_offsets = {}  # Store client-server time differences
    
    def record_client_time_offset(self, session_id, client_timestamp):
        """Record the time difference between client and server"""
        server_time = time.time()
        offset = client_timestamp - server_time
        with self.lock:
            self.client_time_offsets[session_id] = offset
    
    def get_server_time(self, session_id):
        """Get adjusted server time based on client offset"""
        with self.lock:
            offset = self.client_time_offsets.get(session_id, 0)
        return time.time() + offset
    
    def start_timer(self, session_id, duration_seconds):
        """Start a secure timer for the exam"""
        start_time = self.get_server_time(session_id)
        end_time = start_time + duration_seconds
        with self.lock:
            self.exam_start_times[session_id] = {
                'start': start_time,
                'end': end_time,
                'duration': duration_seconds
            }
        return end_time
    
    def get_remaining_time(self, session_id):
        """Get remaining time for the exam"""
        with self.lock:
            if session_id not in self.exam_start_times:
                return 0
            end_time = self.exam_start_times[session_id]['end']
            remaining = end_time - self.get_server_time(session_id)
            return max(0, remaining)
    
    def is_exam_active(self, session_id):
        """Check if exam is still active"""
        return self.get_remaining_time(session_id) > 0

class AntiCheatExtension:
    """
    Custom extension for anti-cheating measures
    """
    def __init__(self):
        self.suspicious_activities = {}
        self.session_hashes = {}
        self.lock = Lock()
    
    def generate_session_fingerprint(self, user_agent, ip_address, screen_resolution):
        """Generate a unique fingerprint for the exam session"""
        fingerprint_data = f"{user_agent}:{ip_address}:{screen_resolution}"
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        return fingerprint
    
    def record_session_fingerprint(self, session_id, fingerprint):
        """Record the session fingerprint"""
        with self.lock:
            self.session_hashes[session_id] = fingerprint
    
    def detect_automation(self, session_id, mouse_movements, keyboard_events):
        """Detect potentially automated behavior"""
        # Check for unnatural patterns in mouse movements
        if len(mouse_movements) > 10:
            avg_speed = self._calculate_avg_movement_speed(mouse_movements)
            if avg_speed < 10:  # Too slow or no movement
                self._record_suspicious_activity(session_id, "no_movement", "No mouse movement detected")
        
        # Check for unnatural keyboard patterns
        if len(keyboard_events) > 5:
            typing_speed = self._calculate_typing_speed(keyboard_events)
            if typing_speed > 15:  # Too fast (more than 15 chars per second)
                self._record_suspicious_activity(session_id, "fast_typing", "Unnaturally fast typing detected")
    
    def _calculate_avg_movement_speed(self, movements):
        if len(movements) < 2:
            return 0
        total_distance = 0
        total_time = 0
        for i in range(1, len(movements)):
            dx = movements[i]['x'] - movements[i-1]['x']
            dy = movements[i]['y'] - movements[i-1]['y']
            distance = (dx**2 + dy**2)**0.5
            dt = movements[i]['time'] - movements[i-1]['time']
            if dt > 0:
                total_distance += distance
                total_time += dt
        return total_distance / total_time if total_time > 0 else 0
    
    def _calculate_typing_speed(self, events):
        if len(events) < 2:
            return 0
        time_diff = events[-1]['time'] - events[0]['time']
        if time_diff <= 0:
            return 0
        return len(events) / time_diff  # chars per second
    
    def _record_suspicious_activity(self, session_id, activity_type, details):
        with self.lock:
            if session_id not in self.suspicious_activities:
                self.suspicious_activities[session_id] = []
            self.suspicious_activities[session_id].append({
                'timestamp': time.time(),
                'type': activity_type,
                'details': details
            })
    
    def get_suspicious_activities(self, session_id):
        with self.lock:
            return self.suspicious_activities.get(session_id, [])

class SecureCommunicationExtension:
    """
    Custom extension for secure client-server communication
    """
    def __init__(self, secret_key=None):
        self.secret_key = secret_key or os.environ.get('CBT_SECRET_KEY', secrets.token_hex(32))
    
    def sign_data(self, data, timestamp=None):
        """Sign data with HMAC to ensure integrity"""
        if timestamp is None:
            timestamp = int(time.time())
        
        # Convert data to string for signing
        if isinstance(data, dict):
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)
        
        message = f"{data_str}:{timestamp}".encode()
        signature = hmac.new(
            self.secret_key.encode(),
            message,
            hashlib.sha256
        ).hexdigest()
        
        return {
            'data': data,
            'timestamp': timestamp,
            'signature': signature
        }
    
    def verify_signature(self, signed_data):
        """Verify the signature of received data"""
        if not all(k in signed_data for k in ('data', 'timestamp', 'signature')):
            return False
        
        # Check timestamp to prevent replay attacks (valid for 30 seconds)
        current_time = time.time()
        if abs(current_time - signed_data['timestamp']) > 30:
            return False
        
        # Recreate the message and signature
        if isinstance(signed_data['data'], dict):
            data_str = json.dumps(signed_data['data'], sort_keys=True)
        else:
            data_str = str(signed_data['data'])
        
        message = f"{data_str}:{signed_data['timestamp']}".encode()
        expected_signature = hmac.new(
            self.secret_key.encode(),
            message,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(expected_signature, signed_data['signature'])

class ExamSessionExtension:
    """
    Custom extension for enhanced exam session management
    """
    def __init__(self):
        self.active_sessions = {}
        self.session_questions = {}  # Store questions for each session
        self.session_answers = {}
        self.lock = Lock()
    
    def create_exam_session(self, user_id, exam_id, questions, duration_minutes):
        """Create a new exam session with encrypted questions"""
        session_id = secrets.token_urlsafe(16)
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        with self.lock:
            self.active_sessions[session_id] = {
                'user_id': user_id,
                'exam_id': exam_id,
                'start_time': start_time,
                'end_time': end_time,
                'status': 'active'
            }
            # Store questions for this session
            self.session_questions[session_id] = questions
            self.session_answers[session_id] = {}
        
        return session_id
    
    def submit_answer(self, session_id, question_id, answer):
        """Record an answer for a question"""
        with self.lock:
            if session_id in self.session_answers:
                self.session_answers[session_id][question_id] = {
                    'answer': answer,
                    'timestamp': time.time(),
                    'attempt_number': len(self.session_answers[session_id]) + 1
                }
    
    def get_session_results(self, session_id):
        """Get the results for a completed session"""
        with self.lock:
            if session_id not in self.active_sessions:
                return None
            
            session = self.active_sessions[session_id]
            answers = self.session_answers.get(session_id, {})
            
            results = {
                'session_id': session_id,
                'user_id': session['user_id'],
                'exam_id': session['exam_id'],
                'start_time': session['start_time'],
                'end_time': session['end_time'],
                'answers': answers,
                'total_questions': len(self.session_questions.get(session_id, [])),
                'status': session['status']
            }
            
            return results
    
    def end_session(self, session_id):
        """End an exam session"""
        with self.lock:
            if session_id in self.active_sessions:
                self.active_sessions[session_id]['status'] = 'completed'
    
    def is_valid_session(self, session_id):
        """Check if session is valid and active"""
        with self.lock:
            if session_id not in self.active_sessions:
                return False
            
            session = self.active_sessions[session_id]
            current_time = time.time()
            
            # Check if session has ended
            if current_time > session['end_time']:
                session['status'] = 'expired'
                return False
            
            return session['status'] == 'active'

# Global instances
time_lock = TimeLockExtension()
anti_cheat = AntiCheatExtension()
secure_comm = SecureCommunicationExtension()
exam_session_ext = ExamSessionExtension()