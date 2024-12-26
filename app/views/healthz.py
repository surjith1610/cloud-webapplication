from django.http import HttpResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import cache_control
import logging
from statsd import StatsClient
import time
from datetime import datetime

statsd = StatsClient(host='localhost',
                     port=8125,
                     prefix=None,
                     maxudpsize=512,
                     ipv6=False)

logger = logging.getLogger('django')


def custom_page_not_found(request, exception=None):
    return HttpResponse(status=404)

@csrf_exempt
@cache_control(no_cache=True)
def health_check_api(request):
    statsd.incr('healthz.requests')
    start = time.time()
   
    # Rejects requests that are not GET requests with HTTP 405 Method Not Allowed
    if request.method != 'GET':
        logger.error("Method not allowed")
        return HttpResponse(status=405)

    # Rejects requests with a payload (content) in the body with HTTP 400 Bad Request
    if request.body or request.GET:
        logger.error("GET request not allowed")
        return HttpResponse(status=400)
    try:
        # Ensure the database connection
        connection.ensure_connection()
        logger.info("Database connection successful, healthz api works")

        # Returns HTTP 200 OK if the database connection is successful
        response = HttpResponse(status=200)

    except Exception:
        logger.error("Database connection error")
        statsd.incr('healthz.db_error')
        # Returns HTTP 503 Service Unavailable if there's a database error
        response = HttpResponse(status=503)
    dt = int((time.time() - start) * 1000)
    statsd.timing('healthz.response_time', dt)

    return response


