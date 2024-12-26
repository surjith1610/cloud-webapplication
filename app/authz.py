from functools import wraps
from django.http import JsonResponse
from rest_framework import status
from .models import User
import logging
import base64
import bcrypt

logger = logging.getLogger('django')

def authenticate_user(request):
    """
    Authenticate the user using Basic Auth and return the user object if successful.
    """
    auth_header = request.headers.get('Authorization')

    if not auth_header:
        logger.error("Authorization header not found")
        return None, "Authorization header not found"
    
    if not auth_header.startswith('Basic '):
        logger.error("Invalid Authorization header")
        return None, "Invalid Authorization header"
    
    # Decoding the Base64 encoded credentials
    try:
        credentials = base64.b64decode(auth_header.split(' ')[1]).decode('utf-8')
        email, password = credentials.split(':')
    except Exception as e:
        logger.error(f"Error decoding credentials: {e}")
        return None, "Invalid credentials format"

    if not email or not password:
        logger.error("Invalid credentials")
        return None, "Invalid credentials"
    
    # Authenticate the user
    try:
        user = User.objects.get(email=email)
        
        if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            logger.error("Invalid credentials")
            return None, "Invalid credentials"
        return user, None  # Authentication successful
    except User.DoesNotExist:
        logger.error("User not found")
        return None, "User not found"

def require_verified_user(view_func):
    """
    Decorator to ensure that the user is authenticated and their account is verified.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # Authenticate the user
        user, auth_error = authenticate_user(request)
        
        # If authentication failed, return the error message
        if auth_error:
            return JsonResponse({"error": auth_error}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Check if the user is verified
        if not user.is_verified:
            return JsonResponse({"error": "User account not verified"}, status=status.HTTP_403_FORBIDDEN)
        
        # If everything is fine, proceed with the original view function
        return view_func(request, *args, **kwargs)
    return _wrapped_view