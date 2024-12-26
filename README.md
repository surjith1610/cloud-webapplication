# WebApp

This web application is built using **Django** and **PostgreSQL**, designed to run on any Ubuntu server. It integrates **AWS Lambda** for user verification and **SendGrid** for email services. The project also features **CI/CD** implemented using **Terraform**.

## Please check the Terraform repository for the reusable Infrastructure code here: 
https://github.com/surjith1610/terraform-webapp-infrastructure
## Please check the serverless function repository for the user verification lambda function code here:
https://github.com/surjith1610/serverless-webapp-function

## Features

### APIs
- **Health Check API (`/healthz`)**  
  Verifies database connectivity and returns HTTP status codes.

- **User Management API**  
  - Create, update, and retrieve user details from the database.  
  - Email-based account verification using SendGrid and Lambda functions.  
  - Manage profile pictures with upload, update, and delete operations stored in an S3 bucket.

- **Image API**  
  - Supports `POST`, `GET`, and `PUT` methods for profile picture management.  
  - Integrated logging and performance metrics using **CloudWatch** and **statsd**.

### Infrastructure
- VPC and EC2 setup using **Terraform**.  
- RDS integration for PostgreSQL with secured private VPC access.  
- Custom AMI built with **Packer**, including a systemd file for auto-starting the application on instance launch.  
- Launch template with user data to collect metrics and auto-start the application.  
- **Autoscaling** for traffic-based scaling of instances.  
- Fine-grained **IAM roles** for enhanced resource security.  
- User verification using **SNS** and **Lambda** functions.  
- Resources encrypted with **AWS KMS** (90-day key rotation).  
- Securely stored credentials using **AWS Secrets Manager**.  
- Hosted zones and DNS management using **Route 53**.  
- SSL certificates added for secure HTTPS connections.

### CI/CD Workflow
- Automated builds and testing with GitHub Actions runners.  
- EC2 launch template refresh for seamless deployment during CI/CD.  
- Branch protection rules and pre-merge status checks enabled.

### Additional Features
- Email verification via **AWS SNS** and Lambda functions.  
- Metrics collection using **CloudWatch** for performance analysis.  
- Comprehensive logging for debugging and monitoring.

## Prerequisites
- Python 3.x  
- PostgreSQL  
- pip (Python package manager)  
- Virtual environment (recommended)  

## Setup Instructions for Ubuntu Server
**Prepare Directory**  
  ```bash
  mkdir cloud

   #Copy files to server
  scp ~/Downloads/webapp.zip <server_username>@<server_ip>:/root/cloud

   #Update system settings
  sudo apt update && sudo apt upgrade -y

  #Install required packages
  sudo apt install -y python3 python3-pip unzip postgresql python3-venv libpq-dev

  #Configure postrgresql for local db
  sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'your_database_password';"
  sudo -u postgres psql -c "CREATE DATABASE your_database_name;"

  # Extract Directory contents
  cd cloud
  unzip webapp.zip
  cd webapp

  # Create Environment vriables
  DB_NAME=your_database_name
  DB_USER=your_database_user
  DB_PASSWORD=your_database_password
  DB_HOST=localhost
  DB_PORT=5432

  # Setup virtual enviroment
  rm -rf venv
  python3 -m venv venv
  source venv/bin/activate

  # Install dependencies
  pip install --upgrade pip
  pip install -r requirements.txt

  # Run db migrations and start server
  python3 manage.py makemigrations
  python3 manage.py migrate

  # Additionally can also use remote db if required, replace its credentials in the env variables
  sudo apt-get install postgresql-client -y
  psql -h <rds_endpoint> -d <db_name> -U <db_user> -W
  \dt



