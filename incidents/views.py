from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.views import LoginView, PasswordResetView
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from .forms import UserRegistrationForm, IncidentForm, IncidentUpdateForm
from .models import Incident, UserProfile
import requests
import logging

# Set up logging
logger = logging.getLogger(__name__)

def register(request):
    """Handle user registration with additional profile information."""
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
                logger.info(f"New user registered: {user.username}")
                messages.success(request, 'Account created successfully! Please login.')
                return redirect('login')
            except Exception as e:
                logger.error(f"Error during user registration: {str(e)}")
                messages.error(request, 'An error occurred during registration. Please try again.')
    else:
        form = UserRegistrationForm()
    return render(request, 'registration/register.html', {'form': form})

@login_required
def dashboard(request):
    """Display user's dashboard with their incidents."""
    try:
        user_incidents = Incident.objects.filter(reporter=request.user).order_by('-reported_date')
        return render(request, 'incidents/dashboard.html', {'incidents': user_incidents})
    except Exception as e:
        logger.error(f"Error loading dashboard for user {request.user.username}: {str(e)}")
        messages.error(request, 'Error loading dashboard. Please try again.')
        return redirect('login')

@login_required
def create_incident(request):
    """Handle creation of new incidents."""
    if request.method == 'POST':
        form = IncidentForm(request.POST)
        if form.is_valid():
            try:
                incident = form.save(commit=False)
                incident.reporter = request.user
                incident.save()
                logger.info(f"New incident created by {request.user.username}: {incident.incident_id}")
                messages.success(request, 'Incident created successfully!')
                return redirect('dashboard')
            except Exception as e:
                logger.error(f"Error creating incident: {str(e)}")
                messages.error(request, 'Error creating incident. Please try again.')
    else:
        form = IncidentForm()
    return render(request, 'incidents/create_incident.html', {'form': form})

@login_required
def edit_incident(request, incident_id):
    """Handle editing of existing incidents."""
    incident = get_object_or_404(Incident, incident_id=incident_id)
    
    # Check if user owns this incident
    if incident.reporter != request.user:
        logger.warning(f"Unauthorized edit attempt by {request.user.username} on incident {incident_id}")
        raise PermissionDenied("You don't have permission to edit this incident.")
    
    if incident.status == 'CLOSED':
        messages.error(request, 'Closed incidents cannot be edited.')
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = IncidentUpdateForm(request.POST, instance=incident)
        if form.is_valid():
            try:
                form.save()
                logger.info(f"Incident {incident_id} updated by {request.user.username}")
                messages.success(request, 'Incident updated successfully!')
                return redirect('dashboard')
            except Exception as e:
                logger.error(f"Error updating incident {incident_id}: {str(e)}")
                messages.error(request, 'Error updating incident. Please try again.')
    else:
        form = IncidentUpdateForm(instance=incident)
    return render(request, 'incidents/edit_incident.html', {'form': form, 'incident': incident})

@login_required
def search_incident(request):
    """Search for incidents by ID."""
    incident_id = request.GET.get('incident_id', '')
    if incident_id:
        try:
            incident = Incident.objects.get(incident_id=incident_id)
            if incident.reporter != request.user:
                logger.warning(f"Unauthorized search attempt by {request.user.username} for incident {incident_id}")
                raise PermissionDenied("You don't have permission to view this incident.")
            return render(request, 'incidents/search.html', {'incident': incident})
        except Incident.DoesNotExist:
            messages.error(request, 'Incident not found.')
        except Exception as e:
            logger.error(f"Error searching incident {incident_id}: {str(e)}")
            messages.error(request, 'Error searching incident. Please try again.')
    return render(request, 'incidents/search.html')

@login_required
def get_location_info(request):
    """Get location information for auto-filling user details."""
    try:
        ip = request.META.get('REMOTE_ADDR')
        response = requests.get(f'http://ip-api.com/json/{ip}')
        if response.status_code == 200:
            data = response.json()
            return JsonResponse({
                'city': data.get('city', ''),
                'country': data.get('country', ''),
                'zip': data.get('zip', '')
            })
    except Exception as e:
        logger.error(f"Error fetching location info: {str(e)}")
    return JsonResponse({'error': 'Could not fetch location information'}, status=400)

class CustomLoginView(LoginView):
    """Custom login view with additional logging."""
    def form_valid(self, form):
        response = super().form_valid(form)
        logger.info(f"User logged in: {form.get_user().username}")
        return response

class CustomPasswordResetView(PasswordResetView):
    """Custom password reset view with additional logging."""
    template_name = 'registration/password_reset.html'
    email_template_name = 'registration/password_reset_email.html'
    success_url = '/login/'

    def form_valid(self, form):
        response = super().form_valid(form)
        logger.info(f"Password reset requested for email: {form.cleaned_data['email']}")
        return response
