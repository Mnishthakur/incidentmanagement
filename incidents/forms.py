from django import forms
from django.contrib.auth.forms import UserCreationForm, PasswordResetForm
from django.contrib.auth.models import User
from .models import UserProfile, Incident

class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    phone_number = forms.CharField(max_length=15)
    address = forms.CharField(widget=forms.Textarea)
    pincode = forms.CharField(max_length=10)
    city = forms.CharField(max_length=100)
    country = forms.CharField(max_length=100)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
            UserProfile.objects.create(
                user=user,
                phone_number=self.cleaned_data['phone_number'],
                address=self.cleaned_data['address'],
                pincode=self.cleaned_data['pincode'],
                city=self.cleaned_data['city'],
                country=self.cleaned_data['country']
            )
        return user

class IncidentForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = ['organization_type', 'details', 'priority']
        widgets = {
            'details': forms.Textarea(attrs={'rows': 4}),
        }

class IncidentUpdateForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = ['details', 'priority', 'status']
        widgets = {
            'details': forms.Textarea(attrs={'rows': 4}),
        }

    def clean(self):
        cleaned_data = super().clean()
        instance = getattr(self, 'instance', None)
        if instance and instance.status == 'CLOSED':
            raise forms.ValidationError("Closed incidents cannot be edited.") 