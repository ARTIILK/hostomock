# Enhanced CBT Platform with Security Features

This is a Computer-Based Testing (CBT) platform with advanced security features and custom encryption protocols to ensure exam integrity and prevent cheating.

## Features

### Security Features
- **Custom Encryption**: Questions and sensitive data are encrypted using Fernet symmetric encryption with PBKDF2 key derivation
- **Secure Session Management**: Time-based session validation with automatic timeout
- **Anti-Cheat Monitoring**: 
  - Mouse movement and keyboard event tracking
  - Tab switching detection
  - Suspicious activity logging
  - Prevention of developer tools and right-click
- **Secure Communication**: HMAC-based message signing to prevent tampering
- **Time Lock Extension**: Prevents time manipulation and ensures accurate exam duration
- **Session Fingerprinting**: Tracks user agent, IP, and screen resolution to detect session hijacking

### Core Functionality
- Student and admin login with role-based access
- Exam selection interface
- Timed exam sessions with progress tracking
- Multiple question types (multiple choice, text answers)
- Real-time exam timer
- Answer submission with server-side validation

## Architecture

### Security Modules
- `security.py`: Core encryption, session management, and exam proctoring
- `extensions.py`: Additional security extensions including time lock, anti-cheat, and secure communication

### Key Components
- **CustomEncryption**: Handles encryption of questions and sensitive data
- **SecureSessionManager**: Manages user sessions with time-based validation
- **ExamProctoring**: Tracks exam sessions and violations
- **TimeLockExtension**: Ensures accurate timing and prevents manipulation
- **AntiCheatExtension**: Monitors for suspicious activities
- **SecureCommunicationExtension**: Signs and verifies data integrity

## Installation and Setup

1. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   ./run.sh
   ```
   
   Or manually:
   ```bash
   cd /workspace/app
   python app.py
   ```

3. Access the application at: http://127.0.0.1:5000

## Default Credentials

- **Student 1**: username: `student1`, password: `student123`
- **Student 2**: username: `student2`, password: `student123`
- **Admin**: username: `admin`, password: `admin123`

## Security Protocols

### Encryption
- Questions are encrypted before storage using PBKDF2-derived keys
- All communication is signed with HMAC for integrity verification
- Session tokens are cryptographically secure

### Anti-Cheat Measures
- Mouse movement patterns are analyzed for automation detection
- Keyboard input patterns are monitored for unusual speed
- Tab switching is detected and logged
- Developer tools (F12, Ctrl+Shift+I) are blocked
- Right-click is disabled during exams

### Session Security
- Sessions expire after 30 minutes of inactivity
- Each session is tied to specific browser fingerprint
- Time synchronization prevents client-side manipulation
- All actions are logged for audit trails

## Usage

1. Navigate to http://127.0.0.1:5000
2. Select user type (Student/Admin) and enter credentials
3. Students can view available exams and start them
4. Admins can access the dashboard to monitor users

During exams:
- Do not refresh the page or close the browser
- The exam timer counts down in real-time
- Progress is saved automatically
- Suspicious activities are monitored

## Custom Extensions

### TimeLockExtension
- Prevents time manipulation by synchronizing client and server time
- Tracks actual exam duration
- Enforces strict time limits

### AntiCheatExtension
- Generates unique session fingerprints
- Detects automated behavior patterns
- Logs all suspicious activities

### SecureCommunicationExtension
- Signs all data exchanges with HMAC
- Prevents replay attacks with timestamp validation
- Ensures data integrity

### ExamSessionExtension
- Manages exam sessions with encryption
- Tracks answers and timestamps
- Provides detailed results

## Security Best Practices Implemented

1. **Input Validation**: All user inputs are validated server-side
2. **Session Management**: Secure, time-limited sessions with proper cleanup
3. **Data Encryption**: Sensitive data is encrypted at rest and in transit
4. **Activity Monitoring**: Continuous monitoring for suspicious behavior
5. **Secure Communication**: Signed data exchanges to prevent tampering
6. **Access Control**: Role-based access with proper authentication

## Notes

- This is a demonstration platform with security features
- In production, use proper database storage instead of in-memory storage
- Use environment variables for sensitive configuration
- Consider using HTTPS for production deployment
- Regular security audits are recommended