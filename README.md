# Examination Portal Flask Application

A Flask web application with a dynamic login page that serves both students attempting examinations and administrators managing the system.

## Features

- **Dynamic Login**: Single login page for both students and administrators
- **Role-based Access**: Different dashboards based on user role
- **Secure Authentication**: Password hashing for security
- **Responsive Design**: Works on desktop and mobile devices

## Default Credentials

### Students
- Username: `student1`, Password: `student123`
- Username: `student2`, Password: `student123`

### Administrator
- Username: `admin`, Password: `admin123`

## Project Structure

```
/workspace/
├── app/
│   ├── app.py              # Main Flask application
│   ├── templates/          # HTML templates
│   │   ├── login.html      # Login page
│   │   ├── student_dashboard.html  # Student dashboard
│   │   └── admin_dashboard.html    # Admin dashboard
│   └── static/
│       └── css/
│           └── style.css   # Styling
├── requirements.txt        # Python dependencies
└── run.sh                  # Script to run the application
```

## How to Run

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
./run.sh
```

Or alternatively:
```bash
cd app
python app.py
```

3. Open your browser and navigate to `http://127.0.0.1:5000`

## Functionality

- **Login Page**: Users select their role (Student/Admin) and enter credentials
- **Student Dashboard**: Students can view available exams, results, and manage profile
- **Admin Dashboard**: Administrators can manage students, exams, view results, and system settings
- **Session Management**: Secure session handling with role-based redirects
- **Logout Feature**: Secure logout functionality

## Security Features

- Passwords are securely hashed using Werkzeug's security functions
- Session-based authentication
- Role validation on protected routes
- Input validation on login form

## Customization

To add more students or administrators, modify the dictionaries in `app.py`:

```python
students = {
    'student1': {
        'username': 'student1',
        'password': generate_password_hash('student123'),
        'name': 'John Doe',
        'email': 'john@example.com',
        'role': 'student'
    },
    # Add more students here
}

admins = {
    'admin': {
        'username': 'admin',
        'password': generate_password_hash('admin123'),
        'name': 'Admin User',
        'role': 'admin'
    },
    # Add more admins here
}
```