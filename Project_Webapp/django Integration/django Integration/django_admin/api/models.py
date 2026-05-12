from django.db import models
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    username = None
    email = models.EmailField(unique=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

class FalsePositiveReport(models.Model):
    url = models.URLField(max_length=2000)
    reported_at = models.DateTimeField(auto_now_add=True)
    reviewed = models.BooleanField(default=False)
    correct_label = models.CharField(
        max_length=20, 
        choices=[('Legitimate', 'Legitimate'), ('Phishing', 'Phishing')],
        null=True, blank=True
    )

    def __str__(self):
        return self.url
