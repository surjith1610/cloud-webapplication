# from django.contrib import admin
from django.urls import path, include


urlpatterns = [
    # path('admin/', admin.site.urls),

    # including the app's urls
    path('', include('app.urls')),
]

handler404 = 'app.views.healthz.custom_page_not_found'
# handler405 = custom_method_not_allowed