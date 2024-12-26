from django.urls import path
from .views import healthz, user, image

urlpatterns = [
    path('healthz', healthz.health_check_api, name='health_check_api'),
    path('healthz/', healthz.health_check_api, name='health_check_api'),
    path('v1/user/self', user.get_update_user, name='get_update_user'),
    path('v1/user/self/', user.get_update_user, name='get_update_user'),
    path('v1/user', user.create_user, name='create_user'),
    path('v1/user/', user.create_user, name='create_user'),
    path('v1/user/self/pic', image.image_view, name='image_view'),
    # path('v2/user/self', user.get_update_user, name='get_update_user'),
    # path('v2/user/self/', user.get_update_user, name='get_update_user'),
    # path('v2/user', user.create_user, name='create_user'),
    # path('v2/user/', user.create_user, name='create_user'),
    # path('v2/user/self/pic', image.image_view, name='image_view'),
    # path('verify/', user.verify_user, name='verify_user'),
    
    # path('healthz/cicd', healthz.health_check_api, name='health_check_api'),
    # path('healthz/cicd/', healthz.health_check_api, name='health_check_api'),

]
