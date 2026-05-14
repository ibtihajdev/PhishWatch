from django.urls import path
from .views import (
    URLPredictionApiView, 
    HealthCheckView, 
    ReportFalsePositiveView,
    whois_lookup,
    screenshot_preview,
    safe_browsing_check,
    save_history,
    get_history,
    ssl_check
)

urlpatterns = [
    # ML API Endpoints
    path('predict/', URLPredictionApiView.as_view()),
    path('health/',  HealthCheckView.as_view()),
    path('report/',  ReportFalsePositiveView.as_view()),
    path('whois/', whois_lookup),
    path('screenshot/', screenshot_preview),
    path('safebrowsing/', safe_browsing_check),
    path('history/save/', save_history),
    path('history/get/', get_history),
    path('ssl/', ssl_check),
]
