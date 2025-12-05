from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
import os
import json
from datetime import datetime, timedelta

# Import security modules
import sys
sys.path.append('/workspace/cbt_platform')
from security import session_manager, exam_proctor, question_encryption
from extensions import time_lock, anti_cheat, secure_comm, exam_session_ext

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')

# In-memory data storage (in a real app, use a database)
students = {
    'student1': {
        'username': 'student1',
        'password': generate_password_hash('student123'),
        'name': 'John Doe',
        'email': 'john@example.com',
        'role': 'student',
        'exam_sessions': []
    },
    'student2': {
        'username': 'student2',
        'password': generate_password_hash('student123'),
        'name': 'Jane Smith',
        'email': 'jane@example.com',
        'role': 'student',
        'exam_sessions': []
    }
}

admins = {
    'admin': {
        'username': 'admin',
        'password': generate_password_hash('admin123'),
        'name': 'Admin User',
        'role': 'admin'
    }
}

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_type = request.form['user_type']
        
        # Check credentials based on user type
        user = None
        if user_type == 'student':
            if username in students and check_password_hash(students[username]['password'], password):
                user = students[username]
        elif user_type == 'admin':
            if username in admins and check_password_hash(admins[username]['password'], password):
                user = admins[username]
        
        if user:
            # Create secure session using our security module
            session_token = session_manager.create_secure_session(user['username'], user['role'])
            session['session_token'] = session_token
            session['username'] = user['username']
            session['role'] = user['role']
            session['name'] = user['name']
            
            # Record session fingerprint for anti-cheating
            user_agent = request.headers.get('User-Agent', '')
            ip_address = request.environ.get('REMOTE_ADDR', '')
            screen_resolution = request.form.get('screen_resolution', 'unknown')
            fingerprint = anti_cheat.generate_session_fingerprint(user_agent, ip_address, screen_resolution)
            anti_cheat.record_session_fingerprint(session_token, fingerprint)
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid credentials or user type', 'error')
    
    return render_template('login.html')

@app.route('/student_dashboard')
def student_dashboard():
    # Validate session using our security module
    session_token = session.get('session_token')
    if not session_token or not session_manager.validate_session(session_token):
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('login'))
    
    if 'username' not in session or session.get('role') != 'student':
        flash('Please log in as a student', 'error')
        return redirect(url_for('login'))
    
    return render_template('student_dashboard.html', name=session['name'])

@app.route('/admin_dashboard')
def admin_dashboard():
    # Validate session using our security module
    session_token = session.get('session_token')
    if not session_token or not session_manager.validate_session(session_token):
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('login'))
    
    if 'username' not in session or session.get('role') != 'admin':
        flash('Please log in as an admin', 'error')
        return redirect(url_for('login'))
    
    # Get student count for dashboard
    student_count = len(students)
    admin_count = len(admins)
    
    return render_template('admin_dashboard.html', 
                          name=session['name'], 
                          student_count=student_count,
                          admin_count=admin_count)

@app.route('/logout')
def logout():
    # Destroy session using our security module
    session_token = session.get('session_token')
    if session_token:
        session_manager.destroy_session(session_token)
    
    session.clear()
    return redirect(url_for('login'))

# New routes for exam functionality with security features
@app.route('/exams')
def exams():
    # Validate session using our security module
    session_token = session.get('session_token')
    if not session_token or not session_manager.validate_session(session_token):
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('login'))
    
    if 'username' not in session or session.get('role') != 'student':
        flash('Please log in as a student', 'error')
        return redirect(url_for('login'))
    
    # Sample exams data - in a real app, this would come from a database
    exams_data = [
        {'id': 1, 'title': 'Mathematics Exam', 'duration': 60, 'questions_count': 20},
        {'id': 2, 'title': 'Science Exam', 'duration': 45, 'questions_count': 15},
        {'id': 3, 'title': 'English Exam', 'duration': 90, 'questions_count': 25}
    ]
    
    return render_template('exams.html', exams=exams_data, name=session['name'])

@app.route('/start_exam/<int:exam_id>', methods=['GET', 'POST'])
def start_exam(exam_id):
    # Validate session using our security module
    session_token = session.get('session_token')
    if not session_token or not session_manager.validate_session(session_token):
        return jsonify({'error': 'Session expired. Please log in again.'}), 401
    
    if 'username' not in session or session.get('role') != 'student':
        return jsonify({'error': 'Unauthorized access'}), 403
    
    # Sample questions data - in a real app, this would come from a database
    questions = [
        {
            'id': 1,
            'question': 'What is 2 + 2?',
            'options': ['3', '4', '5', '6'],
            'type': 'multiple_choice'
        },
        {
            'id': 2,
            'question': 'What is the capital of France?',
            'options': ['London', 'Berlin', 'Paris', 'Madrid'],
            'type': 'multiple_choice'
        },
        {
            'id': 3,
            'question': 'Solve: 5x + 3 = 18',
            'type': 'text_answer'
        }
    ]
    
    # Encrypt the questions using our security module
    encrypted_questions = []
    for q in questions:
        encrypted_q = question_encryption.encrypt_question(q)
        encrypted_questions.append(encrypted_q)
    
    # Start a secure exam session using our extension
    duration_minutes = 30  # Default duration
    exam_session_id = exam_session_ext.create_exam_session(
        session['username'], 
        exam_id, 
        encrypted_questions, 
        duration_minutes
    )
    
    # Start the time lock for this exam session
    time_lock.start_timer(exam_session_id, duration_minutes * 60)
    
    return render_template('exam.html', 
                          exam_id=exam_id, 
                          questions=questions, 
                          exam_session_id=exam_session_id,
                          name=session['name'])

@app.route('/submit_answer', methods=['POST'])
def submit_answer():
    # Verify the signature of the submitted data using our security module
    signed_data = request.json
    if not secure_comm.verify_signature(signed_data):
        return jsonify({'error': 'Invalid signature'}), 400
    
    data = signed_data['data']
    
    # Validate session using our security module
    session_token = session.get('session_token')
    if not session_token or not session_manager.validate_session(session_token):
        return jsonify({'error': 'Session expired'}), 401
    
    exam_session_id = data.get('exam_session_id')
    question_id = data.get('question_id')
    answer = data.get('answer')
    
    # Validate exam session using our extension
    if not exam_session_ext.is_valid_session(exam_session_id):
        return jsonify({'error': 'Invalid or expired exam session'}), 400
    
    # Submit the answer using our extension
    exam_session_ext.submit_answer(exam_session_id, question_id, answer)
    
    return jsonify({'success': True})

@app.route('/get_time_remaining/<session_id>')
def get_time_remaining(session_id):
    # Validate session using our security module
    session_token = session.get('session_token')
    if not session_token or not session_manager.validate_session(session_token):
        return jsonify({'error': 'Session expired'}), 401
    
    # Check if exam session is valid
    if not exam_session_ext.is_valid_session(session_id):
        return jsonify({'error': 'Invalid or expired exam session'}), 400
    
    # Get remaining time using our time lock extension
    remaining_seconds = time_lock.get_remaining_time(session_id)
    minutes = int(remaining_seconds // 60)
    seconds = int(remaining_seconds % 60)
    
    return jsonify({'minutes': minutes, 'seconds': seconds})

@app.route('/end_exam/<session_id>', methods=['POST'])
def end_exam(session_id):
    # Validate session using our security module
    session_token = session.get('session_token')
    if not session_token or not session_manager.validate_session(session_token):
        return jsonify({'error': 'Session expired'}), 401
    
    # End the exam session using our extension
    exam_session_ext.end_session(session_id)
    
    # Get results
    results = exam_session_ext.get_session_results(session_id)
    
    return jsonify({'success': True, 'results': results})

# API endpoint for anti-cheat monitoring
@app.route('/monitor_activity', methods=['POST'])
def monitor_activity():
    # Validate session using our security module
    session_token = session.get('session_token')
    if not session_token or not session_manager.validate_session(session_token):
        return jsonify({'error': 'Session expired'}), 401
    
    data = request.json
    
    # Record client time offset for time manipulation detection
    if 'client_timestamp' in data:
        time_lock.record_client_time_offset(session.get('session_token'), data['client_timestamp'])
    
    # Detect suspicious activities using our anti-cheat extension
    if 'mouse_movements' in data and 'keyboard_events' in data:
        anti_cheat.detect_automation(
            session.get('session_token'), 
            data['mouse_movements'], 
            data['keyboard_events']
        )
    
    # Record any violations
    violations = anti_cheat.get_suspicious_activities(session.get('session_token'))
    
    return jsonify({'success': True, 'violations': violations})

if __name__ == '__main__':
    app.run(debug=True)