#!/bin/bash

# Update system and install required packages
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip unzip python3-venv libpq-dev

# Create a system user for the application
sudo groupadd csye6225
sudo useradd -r -g csye6225 -s /usr/sbin/nologin csye6225 -d /home/csye6225

# Create the user's home directory
sudo mkdir -p /home/csye6225/
sudo chown csye6225:csye6225 /home/csye6225/

# Copy webapp.zip to the appropriate location
sudo cp /tmp/webapp.zip /home/csye6225/webapp.zip

# Navigate to the user directory
cd /home/csye6225/

# Unzip the webapp.zip file
sudo unzip webapp.zip -d /home/csye6225/webapp

# Change ownership of the webapp directory to the correct user
sudo chown -R csye6225:csye6225 /home/csye6225/webapp/

# Remove the existing virtual environment
sudo -u csye6225 bash -c 'rm -rf /home/csye6225/webapp/venv'

# Create a new virtual environment
sudo -u csye6225 bash -c 'python3 -m venv /home/csye6225/webapp/venv'

# Activate the virtual environment and install requirements
sudo -u csye6225 bash -c 'source /home/csye6225/webapp/venv/bin/activate && pip install --upgrade pip && pip install -r /home/csye6225/webapp/requirements.txt'


# Copy the systemd service file for the web application
sudo cp /home/csye6225/webapp/sys-service/webapp.service /etc/systemd/system/webapp.service

# Reload systemd to register the new service
sudo systemctl daemon-reload

# Enable the webapp service to start at boot
sudo systemctl enable webapp.service

# Start the webapp service
sudo systemctl start webapp.service

# Change ownership of all files in /home/csye6225 to ensure correct user permissions
sudo chown -R csye6225:csye6225 /home/csye6225/

# Check the status of the webapp service
sudo systemctl status webapp.service
