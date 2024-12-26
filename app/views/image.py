from django.http import HttpResponse, JsonResponse
from rest_framework import status
from rest_framework.decorators import api_view
from app.models import Image, User
from django.views.decorators.cache import cache_control
from django.db import connection
import base64
import bcrypt
import boto3
from botocore.exceptions import NoCredentialsError
from django.conf import settings
from mimetypes import guess_extension
import logging
from statsd import StatsClient
import time
from datetime import datetime
from ..authz import require_verified_user

statsd = StatsClient(host='localhost',
                     port=8125,
                     prefix=None,
                     maxudpsize=512,
                     ipv6=False)

logger = logging.getLogger('django')

# Initialize your S3 client (add your AWS credentials to your environment variables or use AWS config)
s3_client = boto3.client('s3')

# Define acceptable MIME types for images
ACCEPTABLE_IMAGE_TYPES = ["image/png", "image/jpeg", "image/jpg"]

@require_verified_user
@cache_control(no_cache=True)
@api_view(['POST', 'OPTIONS', 'GET', 'PUT', 'DELETE', 'PATCH', 'HEAD'])
def image_view(request):
    # Ensure database connection
    try:
        connection.ensure_connection()
    except Exception:
        logger.error("Database connection error")
        return HttpResponse(status=503)
    
    if request.method in ['OPTIONS', 'PUT', 'PATCH', 'HEAD']:
        logger.error("Method not allowed")
        return HttpResponse(status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    if request.GET:
            logger.error("GET request not allowed")
            return HttpResponse(status=status.HTTP_400_BAD_REQUEST)

    # Check for Basic Auth header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Basic '):
        logger.error("Unauthorized")
        return HttpResponse(status=status.HTTP_401_UNAUTHORIZED)
    
    # Decode the Basic Auth credentials
    credentials = base64.b64decode(auth_header.split(' ')[1]).decode('utf-8')
    email, password = credentials.split(':')
    
    # Authenticate user
    try:
        user = User.objects.get(email=email)
        if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            logger.error("Invalid credentials")
            return JsonResponse({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    except User.DoesNotExist:
        logger.error("User not found")
        return JsonResponse({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    # Handle POST request - Upload a new image
    if request.method == 'POST':
        start = time.time()
        statsd.incr('user.image_upload')
        if 'file' not in request.FILES:
            logger.error("No file provided")
            return JsonResponse({"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if an image already exists for this user
        if Image.objects.filter(user_id=user).exists():
            logger.error("User already has an uploaded image")
            return JsonResponse({"error": "User already has an uploaded image"}, status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = request.FILES['file']
        file_name = uploaded_file.name

        # Check if the file is an acceptable image type
        file_type = uploaded_file.content_type
        if file_type not in ACCEPTABLE_IMAGE_TYPES:
            logger.error("Invalid file type. Only PNG, JPG, and JPEG are allowed.")
            return JsonResponse({"error": "Invalid file type. Only PNG, JPG, and JPEG are allowed."}, status=status.HTTP_400_BAD_REQUEST)
        

        # Prepare the upload path and bucket name
        bucket_name = settings.S3_BUCKET_NAME
        user_id = str(user.id)
        image_file_path = f"{user_id}/{file_name}"

        try:
            # Upload the file to S3
            s3_upload_start = time.time()
            s3_client.upload_fileobj(uploaded_file, bucket_name, image_file_path)
            s3_upload_dt = int((time.time() - s3_upload_start) * 1000)
            statsd.timing('s3.upload_image', s3_upload_dt)
            # Construct the file URL
            url = f"s3://{bucket_name}/{image_file_path}"

            # Save image details to the database
            image = Image.objects.create(
                file_name=file_name,
                url=url,
                user_id=user
            )
            logger.info(f"Image uploaded: {image.id}")
            dbquery_start = time.time()
            image.save()
            dbquery_dt = int((time.time() - dbquery_start) * 1000)
            statsd.timing('user.create_image_db_query_time', dbquery_dt)
            dt = int((time.time() - start) * 1000)
            statsd.timing('user.image_upload_time', dt)

            return JsonResponse({
                "id": str(image.id),
                "file_name": image.file_name,
                "url": image.url,
                "upload_date": image.upload_date.strftime("%Y-%m-%d"),
                "user_id": str(user.id)
            }, status=status.HTTP_201_CREATED)

        except NoCredentialsError:
            logger.error("S3 credentials not available")
            return JsonResponse({"error": "Credentials not available"}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.error(str(e))
            return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # Handle GET request - Retrieve an image
    elif request.method == 'GET':
        start = time.time()
        statsd.incr('user.image_retrieve')
        if request.body:
            logger.error("GET request does not accept a body")
            return HttpResponse(status=status.HTTP_400_BAD_REQUEST)
        try:
            db_query_start = time.time()
            image = Image.objects.get(user_id=user)
            db_query_dt = int((time.time() - db_query_start) * 1000)
            statsd.timing('user.get_image_db_query_time', db_query_dt)
            dt = int((time.time() - start) * 1000)
            statsd.timing('user.image_retrieve_time', dt)
            return JsonResponse({
                "file_name": image.file_name,
                "id": image.id,
                "url": image.url,
                "uploaded_date": image.upload_date,
                "user_id": str(image.user_id.id)
            }, status=status.HTTP_200_OK)
        except Image.DoesNotExist:
            logger.error("Image not found")
            return JsonResponse({"error": "Image not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(str(e))
            return JsonResponse({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)
        

    # Handle DELETE request - Delete an image
    elif request.method == 'DELETE':
        start = time.time()
        statsd.incr('user.image_delete')
        if request.body:
            logger.error("DELETE request does not accept a body")
            return HttpResponse(status=status.HTTP_400_BAD_REQUEST)
        try:
            # Retrieve the latest image uploaded by the authenticated user
            image = Image.objects.get(user_id=user)
            if not image:
                logger.error("No images found for this user")
                return JsonResponse({"error": "No images found for this user"}, status=status.HTTP_404_NOT_FOUND)
            # Delete the image from S3
            bucket_name = settings.S3_BUCKET_NAME
            s3_key = image.url.split(f"{bucket_name}/")[-1]
            s3_query_start = time.time()
            s3_client.delete_object(Bucket=bucket_name, Key=s3_key)
            s3_query_dt = int((time.time() - s3_query_start) * 1000)
            statsd.timing('s3.delete_image', s3_query_dt)

            # Delete the image record from the database
            db_query_start = time.time()
            image.delete()
            db_query_dt = int((time.time() - db_query_start) * 1000)
            statsd.timing('user.delete_image_db_query_time', db_query_dt)
            logger.info(f"Image deleted: {image.id}")
            dt = int((time.time() - start) * 1000)
            statsd.timing('user.image_delete_time', dt)
            return HttpResponse(status=status.HTTP_204_NO_CONTENT)
        except Image.DoesNotExist:
            logger.error("No images found for this user")
            return JsonResponse({"error": "No images found for this user"}, status=status.HTTP_404_NOT_FOUND)
        except NoCredentialsError:
            logger.error("S3 credentials not available")
            return JsonResponse({"error": "S3 credentials not available"}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.error(str(e))
            return JsonResponse({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)

    # Method not allowed
    else:
        logger.error("Method not allowed")
    return HttpResponse(status=status.HTTP_405_METHOD_NOT_ALLOWED)
