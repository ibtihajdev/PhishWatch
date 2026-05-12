from django.urls import path
from .views import (
    URLPredictionApiView, 
    HealthCheckView, 
    ReportFalsePositiveView,
    whois_lookup,
    screenshot_preview
)

urlpatterns = [
    # ML API Endpoints
    path('predict/', URLPredictionApiView.as_view()),
    path('health/',  HealthCheckView.as_view()),
    path('report/',  ReportFalsePositiveView.as_view()),
    path('whois/', whois_lookup),
    path('screenshot/', screenshot_preview),
]
