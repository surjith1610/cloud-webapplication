from django.http import HttpResponse, JsonResponse
from rest_framework import status
from rest_framework.parsers import JSONParser
from rest_framework.decorators import api_view
import bcrypt
from app.models import User
import base64
import re
from django.views.decorators.cache import cache_control
from django.db import connection
from statsd import StatsClient
import time
from django.utils.timezone import now
import boto3
import json
from ..authz import require_verified_user
import os
from datetime import datetime, timedelta
import uuid

from dotenv import load_dotenv
load_dotenv(override=True)

sns_client = boto3.client('sns', region_name= 'us-east-1')
sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')

statsd = StatsClient(host='localhost',
                     port=8125,
                     prefix=None,
                     maxudpsize=512,
                     ipv6=False)
import logging

logger = logging.getLogger('django')

@cache_control(no_cache=True)
@api_view(['POST', 'OPTIONS', 'GET', 'PUT', 'DELETE', 'PATCH', 'HEAD'])
def create_user(request):
    statsd.incr('user.create_user')
    start = time.time()
    # ensure the database connection
    try:
        connection.ensure_connection()
    except Exception:
        logger.error("Database connection error")
        return HttpResponse(status=503)
    
    # reject non POST methods
    if request.method in ['OPTIONS', 'GET', 'PUT', 'DELETE', 'PATCH', 'HEAD']:
        logger.error(f"Method not allowed: {request.method}")
        return HttpResponse(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    # check for query parameters
    if request.GET:
        logger.error(f"Query parameters not allowed: {request.GET}")
        return HttpResponse(status=status.HTTP_400_BAD_REQUEST)

    # check for empty body
    if not request.body:
        logger.error("Empty body")
        return HttpResponse(status=status.HTTP_400_BAD_REQUEST)
    
    # check for headers
    if request.headers.get('Authorization'):
        logger.error("Authorization header not allowed")
        return HttpResponse(status=status.HTTP_400_BAD_REQUEST)

    data = JSONParser().parse(request)

    required_fields = ["email", "password", "first_name", "last_name"]

    # checking for any invalid fields in the request body
    for key in data.keys():
        if key not in required_fields:
            logger.error(f"Invalid field: {key}")
            return JsonResponse({"error": "Invalid fields"}, status=status.HTTP_400_BAD_REQUEST)
    
    # checking for missing/empty fields in the request body
    for field in required_fields:
        if field not in data:
            logger.error(f"Missing field: {field}")
            return JsonResponse({"error": f"{field} is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not data[field] or data[field].strip() == "" or data[field] == None :
            logger.error(f"Empty field: {field}")
            return JsonResponse({ "error": f"{field} cannot be empty" }, status=status.HTTP_400_BAD_REQUEST)

    # validations
    email = data.get("email")
    if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        logger.error("Invalid email format")
        return JsonResponse({"error": "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)
    
    first_name = data.get("first_name")
    last_name = data.get("last_name")
    if not re.match(r'^[A-Za-z\s]+$', first_name):
        logger.error("First name must contain only alphabets")
        return JsonResponse({"error": "First name must contain only alphabets"}, status=status.HTTP_400_BAD_REQUEST)
    if not re.match(r'^[A-Za-z\s]+$', last_name):
        logger.error("Last name must contain only alphabets")
        return JsonResponse({"error": "Last name must contain only alphabets"}, status=status.HTTP_400_BAD_REQUEST)

    plain_password = data.get("password")
    if len(plain_password) < 8:
        logger.error("Password must be at least 8 characters long")
        return JsonResponse({"error": "Password must be at least 8 characters long"}, status=status.HTTP_400_BAD_REQUEST)
    
    # hashing the password
    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    data["password"] = hashed_password.decode('utf-8')
    
    try:
        # check if the email already exists
        if User.objects.filter(email=data.get("email")).exists():
            logger.error("Email already exists")
            return JsonResponse({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.create(
            email=data["email"],
            password=data["password"],
            first_name=data["first_name"],
            last_name=data["last_name"],
        )
        db_query_start = time.time()
        user.save()
        db_query_time = int((time.time() - db_query_start) * 1000)
        statsd.timing('user.create_user_dbquery', db_query_time)
        logger.info(f"{user.id} created")
        dt = int((time.time() - start) * 1000)
        statsd.timing('user.create_user', dt)

        token = str(uuid.uuid4())
        expiration_time = datetime.now() + timedelta(minutes=2)

        user.verification_token = token
        user.expiration_time = expiration_time

        user.save()
        # message payload for SNS
        payload = {
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "token": token
        }


        # publish to SNS
        try:
            sns_response = sns_client.publish(
                TopicArn=sns_topic_arn,
                Message=json.dumps(payload),
                Subject="New User Verification Email"
            )
            logger.info("Published message to SNS for user: %s", user.email)
        except Exception as e:
            logger.error("Failed to publish message to SNS: %s", str(e))
            return JsonResponse({'error': 'Error sending verification email'})
        
        return JsonResponse({
            "id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "account_created": user.account_created,
            "account_updated": user.account_updated
        }, status=status.HTTP_201_CREATED)
    

    except Exception as e:
        logger.error(str(e))
        return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

def verify_user(request):
    """
    Verify the user's email using the token from the link.
    """
    try:
        email = request.GET.get('user')
        token = request.GET.get('token')
        user_log = User.objects.get(email=email,verification_token=token)
        if now() > user_log.expiration_time:
            return JsonResponse({"error": "Verification link has expired."}, status=400)
        
        if user_log.is_verified:
            return JsonResponse({"message": "Email already verified."}, status=400)
        
        else:
            user_log.is_verified = True
            user_log.save()
            logger.info(f"{user_log.id} verified")
            return JsonResponse({"message": "Email verified successfully."}, status=200)

    except User.DoesNotExist:
        return JsonResponse({"error": "User not found."}, status=404)

@require_verified_user
@cache_control(no_cache=True)
@api_view(['GET', 'PUT', 'OPTIONS', 'HEAD', 'POST', 'DELETE', 'PATCH'])
def get_update_user(request):
    # ensure the database connection
    try:
        connection.ensure_connection()
    except Exception:
        return HttpResponse(status=503)

    # reject non GET and PUT requests
    if request.method in ['OPTIONS','HEAD' , 'POST', 'DELETE', 'PATCH']:
        logger.error(f"Method not allowed: {request.method}")
        return HttpResponse(status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    # Extract the Basic Auth header
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        logger.error("Authorization header not found")
        return HttpResponse(status=status.HTTP_401_UNAUTHORIZED)
    
    if not auth_header.startswith('Basic '):
        logger.error("Invalid Authorization header")
        return HttpResponse(status=status.HTTP_401_UNAUTHORIZED)
        
    # Decoding the Base64 encoded credentials
    credentials = base64.b64decode(auth_header.split(' ')[1]).decode('utf-8')
    email, password = credentials.split(':')

    if not email or not password:
        logger.error("Invalid credentials")
        return HttpResponse(status=status.HTTP_401_UNAUTHORIZED)

    # authentication
    try:
        db_query_start = time.time()
        user = User.objects.get(email=email)
        db_query_time = int((time.time() - db_query_start) * 1000)
        statsd.timing('user.get_user_dbquery', db_query_time)
        if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            logger.error("Invalid credentials")
            return JsonResponse({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    except User.DoesNotExist:
        logger.error("User not found")
        return JsonResponse({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    # handling GET request
    if request.method == 'GET':
        start = time.time()
        statsd.incr('user.get_user')
        # check for query parameters and body
        if request.GET:
            logger.error(f"Query parameters not allowed: {request.GET}")
            return HttpResponse(status=status.HTTP_400_BAD_REQUEST)

        if request.body:
            logger.error("Body not allowed")
            return HttpResponse(status=status.HTTP_400_BAD_REQUEST)

        logger.info(f"{user.id} retrieved")
        dt = int((time.time() - start) * 1000)
        statsd.timing('user.get_user', dt)
        return JsonResponse({
            "id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "account_created": user.account_created,
            "account_updated": user.account_updated
        }, status=status.HTTP_200_OK)
            

    # Handle PUT request
    elif request.method == 'PUT':
        start = time.time()
        statsd.incr('user.update_user')
        # check for empty body and query parameters
        if not request.body:
            logger.error("Empty body")
            return HttpResponse(status=status.HTTP_400_BAD_REQUEST)
        
        if request.GET:
            logger.error(f"Query parameters not allowed: {request.GET}")
            return HttpResponse(status=status.HTTP_400_BAD_REQUEST)
        
        data = JSONParser().parse(request)

        # check for invalid fields or extra fields
        allowed_fields = ["first_name", "last_name", "password"]

        invalid_fields = [key for key in data.keys() if key not in allowed_fields]

        # check if there are any invalid fields
        if invalid_fields:
            logger.error(f"Invalid fields: {invalid_fields}")
            return JsonResponse({"error": "Invalid fields"}, status=status.HTTP_400_BAD_REQUEST)
        
        for field in allowed_fields:
            if field in data and (data[field] == None or data[field].strip() == ""):
                logger.error(f"Empty field: {field}")
                return JsonResponse({"error": f"{field} cannot be empty"}, status=status.HTTP_400_BAD_REQUEST)

        if 'first_name' in data:
            first_name = data['first_name']
            if not re.match(r'^[A-Za-z\s]+$', first_name):
                logger.error("First name must contain only alphabets")
                return JsonResponse({"error": "First name must contain only alphabets"}, status=status.HTTP_400_BAD_REQUEST)
            
        if 'last_name' in data:
            last_name = data['last_name']
            if not re.match(r'^[A-Za-z\s]+$', last_name):
                logger.error("Last name must contain only alphabets")
                return JsonResponse({"error": "Last name must contain only alphabets"}, status=status.HTTP_400_BAD_REQUEST)

        user.first_name = data.get("first_name", user.first_name)
        user.last_name = data.get("last_name", user.last_name)

        # check if the password needs to be updated
        new_password = data.get("password")
        if new_password:
            if len(new_password) < 8:
                logger.error("Password must be at least 8 characters long")
                return JsonResponse({"error": "Password must be at least 8 characters long"}, status=status.HTTP_400_BAD_REQUEST)
        
            # Hash the new password and update it
            user.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

        try:
            db_query_start = time.time()
            user.save()
            db_query_time = int((time.time() - db_query_start) * 1000)
            statsd.timing('user.update_user_dbquery', db_query_time)
            logger.info(f"{user.id} updated")
            dt = int((time.time() - start) * 1000)
            statsd.timing('user.update_user', dt)
            return HttpResponse(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(str(e))
            return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
