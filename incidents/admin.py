from django.contrib import admin
from .models import UserProfile, Incident

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'phone_number', 'city', 'country')
    search_fields = ('user__username', 'phone_number', 'city', 'country')

@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ('incident_id', 'reporter', 'organization_type', 'reported_date', 'priority', 'status')
    list_filter = ('organization_type', 'priority', 'status')
    search_fields = ('incident_id', 'reporter__username', 'details')
    readonly_fields = ('incident_id', 'reported_date')
