from django.db import models
from django.contrib.auth.models import User
import random
from datetime import datetime

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=15)
    address = models.TextField()
    pincode = models.CharField(max_length=10)
    city = models.CharField(max_length=100)
    country = models.CharField(max_length=100)

    def __str__(self):
        return self.user.username

    class Meta:
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'

class Incident(models.Model):
    PRIORITY_CHOICES = [
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]
    
    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('IN_PROGRESS', 'In Progress'),
        ('CLOSED', 'Closed'),
    ]
    
    ORGANIZATION_TYPE = [
        ('ENTERPRISE', 'Enterprise'),
        ('GOVERNMENT', 'Government'),
    ]


    incident_id = models.CharField(max_length=15, unique=True)
    reporter = models.ForeignKey(User, on_delete=models.CASCADE)
    organization_type = models.CharField(max_length=20, choices=ORGANIZATION_TYPE)
    details = models.TextField()
    reported_date = models.DateTimeField(auto_now_add=True)
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN')

    def save(self, *args, **kwargs):
        if not self.incident_id:
            while True:
                random_num = str(random.randint(10000, 99999))
                year = str(datetime.now().year)
                new_id = f"RMG{random_num}{year}"
                if not Incident.objects.filter(incident_id=new_id).exists():
                    self.incident_id = new_id
                    break
        super().save(*args, **kwargs)

    def __str__(self):
        return self.incident_id

    class Meta:
        ordering = ['-reported_date'] 
        verbose_name = 'Incident'
        verbose_name_plural = 'Incidents'
