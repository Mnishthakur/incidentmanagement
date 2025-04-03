from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile, Incident

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['phone_number', 'address', 'pincode', 'city', 'country']

class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer()
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'profile']

    def create(self, validated_data):
        profile_data = validated_data.pop('profile')
        password = validated_data.pop('password')
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        UserProfile.objects.create(user=user, **profile_data)
        return user

class IncidentSerializer(serializers.ModelSerializer):
    reporter_name = serializers.CharField(source='reporter.username', read_only=True)

    class Meta:
        model = Incident
        fields = ['incident_id', 'reporter_name', 'organization_type', 'details', 
                 'reported_date', 'priority', 'status']
        read_only_fields = ['incident_id', 'reported_date'] 