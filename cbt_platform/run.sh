#!/bin/bash

# Install required packages
pip install -r requirements.txt

# Run the Flask application
cd /workspace/app
export FLASK_APP=app.py
export FLASK_ENV=development
python app.py