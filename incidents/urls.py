from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from . import api_views

# Configure the router for the viewset-based API endpoints
router = DefaultRouter()
router.register(r'incidents', api_views.IncidentViewSet, basename='incident')

urlpatterns = [
    # Web URLs
    path('', views.dashboard, name='dashboard'),
    path('register/', views.register, name='register'),
    path('create/', views.create_incident, name='create_incident'),
    path('search/', views.search_incident, name='search_incident'),
    path('get-location-info/', views.get_location_info, name='get_location_info'),
    
    # API URLs - ViewSet-based endpoints via the router
    path('api/', include(router.urls)),
    
    # API URLs - Function-based endpoints
    path('api/register/', api_views.register_user, name='api_register'),
    path('api/login/', api_views.login_user, name='api_login'),
    path('api/search/', api_views.search_incident, name='api_search_incident'),
    
    # Alternative direct access to incident operations (in case the router-based approach has issues)
    path('api/incidents/<str:id>/edit/', api_views.edit_incident, name='api_edit_incident'),
    path('api/incidents/<str:id>/delete/', api_views.delete_incident, name='api_delete_incident'),
]