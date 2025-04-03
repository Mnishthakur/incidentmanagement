from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes, throttle_classes, action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.throttling import UserRateThrottle
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
from django.core.exceptions import PermissionDenied
from .serializers import UserSerializer, IncidentSerializer
from .models import Incident
from rest_framework.authtoken.models import Token
import logging

# Set up logging
logger = logging.getLogger(__name__)

class CustomUserRateThrottle(UserRateThrottle):
    """Custom rate limiting for API endpoints."""
    rate = '100/hour'  
    
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([CustomUserRateThrottle])
def register_user(request):
    """Handle user registration through API."""
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        try:
            user = serializer.save()
            logger.info(f"New user registered via API: {user.username}")
            return Response({
                'message': 'User registered successfully',
                'user_id': user.id,
                'username': user.username
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Error during API user registration: {str(e)}")
            return Response({
                'error': 'Registration failed. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([CustomUserRateThrottle])
def login_user(request):
    """Handle user login through API."""
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response({
            'error': 'Please provide both username and password'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = authenticate(username=username, password=password)
        if user:
            token, created = Token.objects.get_or_create(user=user)
            logger.info(f"User logged in via API: {username}")
            return Response({
                'token': token.key,
                'user_id': user.id,
                'username': user.username
            })
        else:
            logger.warning(f"Failed login attempt via API for username: {username}")
            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)
    except Exception as e:
        logger.error(f"Error during API login: {str(e)}")
        return Response({
            'error': 'Login failed. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class IncidentViewSet(viewsets.ModelViewSet):
    """ViewSet for handling incident-related API operations."""
    serializer_class = IncidentSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [CustomUserRateThrottle]
    lookup_field = 'incident_id'  # Use incident_id instead of the default pk

    def get_queryset(self):
        """Get incidents for the authenticated user."""
        return Incident.objects.filter(reporter=self.request.user)

    def perform_create(self, serializer):
        """Create a new incident."""
        try:
            incident = serializer.save(reporter=self.request.user)
            logger.info(f"New incident created via API by {self.request.user.username}: {incident.incident_id}")
        except Exception as e:
            logger.error(f"Error creating incident via API: {str(e)}")
            raise

    def perform_update(self, serializer):
        """Update an existing incident."""
        incident = self.get_object()
        if incident.status == 'CLOSED':
            logger.warning(f"Attempt to update closed incident {incident.incident_id} by {self.request.user.username}")
            raise PermissionDenied("Closed incidents cannot be edited.")
        
        try:
            updated_incident = serializer.save()
            logger.info(f"Incident {incident.incident_id} updated via API by {self.request.user.username}")
        except Exception as e:
            logger.error(f"Error updating incident {incident.incident_id} via API: {str(e)}")
            raise

    def destroy(self, request, *args, **kwargs):
        """Handle DELETE requests."""
        try:
            incident = self.get_object()
            incident_id = incident.incident_id
            if incident.reporter != request.user:
                logger.warning(f"Unauthorized API delete attempt by {request.user.username} for incident {incident_id}")
                return Response({
                    'error': 'You do not have permission to delete this incident'
                }, status=status.HTTP_403_FORBIDDEN)
            
            self.perform_destroy(incident)
            logger.info(f"Incident {incident_id} deleted via API by {request.user.username}")
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(f"Error deleting incident via API: {str(e)}")
            return Response({
                'error': 'Delete failed. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
@throttle_classes([CustomUserRateThrottle])
def edit_incident(request, id):
    """Edit an existing incident through API."""
    try:
        incident = get_object_or_404(Incident, incident_id=id)
        
        # Check if user has permission to edit
        if incident.reporter != request.user:
            logger.warning(f"Unauthorized API edit attempt by {request.user.username} for incident {id}")
            return Response({
                'error': 'You do not have permission to edit this incident'
            }, status=status.HTTP_403_FORBIDDEN)
            
        # Check if incident is closed
        if incident.status == 'CLOSED':
            logger.warning(f"Attempt to update closed incident {id} by {request.user.username}")
            return Response({
                'error': 'Closed incidents cannot be edited'
            }, status=status.HTTP_403_FORBIDDEN)
            
        # For partial updates (PATCH)
        partial = request.method == 'PATCH'
        
        serializer = IncidentSerializer(incident, data=request.data, partial=partial)
        if serializer.is_valid():
            try:
                updated_incident = serializer.save()
                logger.info(f"Incident {id} updated via API by {request.user.username}")
                return Response(serializer.data)
            except Exception as e:
                logger.error(f"Error updating incident {id} via API: {str(e)}")
                return Response({
                    'error': 'Update failed. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        logger.error(f"Error during API incident edit: {str(e)}")
        return Response({
            'error': 'Edit failed. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@throttle_classes([CustomUserRateThrottle])
def delete_incident(request, id):
    """Delete an incident through API."""
    try:
        incident = get_object_or_404(Incident, incident_id=id)
        
        # Check if user has permission to delete
        if incident.reporter != request.user:
            logger.warning(f"Unauthorized API delete attempt by {request.user.username} for incident {id}")
            return Response({
                'error': 'You do not have permission to delete this incident'
            }, status=status.HTTP_403_FORBIDDEN)
            
        incident.delete()
        logger.info(f"Incident {id} deleted via API by {request.user.username}")
        return Response(status=status.HTTP_204_NO_CONTENT)
            
    except Exception as e:
        logger.error(f"Error during API incident deletion: {str(e)}")
        return Response({
            'error': 'Delete failed. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([CustomUserRateThrottle])
def search_incident(request):
    """Search for incidents by ID through API."""
    incident_id = request.query_params.get('incident_id')
    
    if not incident_id:
        return Response({
            'error': 'Please provide an incident ID'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        incident = Incident.objects.get(incident_id=incident_id)
        if incident.reporter != request.user:
            logger.warning(f"Unauthorized API search attempt by {request.user.username} for incident {incident_id}")
            raise PermissionDenied("You don't have permission to view this incident.")
        
        serializer = IncidentSerializer(incident)
        return Response(serializer.data)
    except Incident.DoesNotExist:
        logger.warning(f"API search for non-existent incident: {incident_id}")
        return Response({
            'error': 'Incident not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except PermissionDenied as e:
        return Response({
            'error': str(e)
        }, status=status.HTTP_403_FORBIDDEN)
    except Exception as e:
        logger.error(f"Error during API incident search: {str(e)}")
        return Response({
            'error': 'Search failed. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)