from django.contrib import admin
from django.urls import include, path
from django.http import HttpResponse
import os

FRONTEND_DIR = os.path.normpath(os.path.join(
    os.path.dirname(__file__),
    '..', '..', '..', '..', 'phisbusterv2'
))
FRONTEND_INDEX = os.path.join(FRONTEND_DIR, 'index.html')

def serve_frontend(request):
    with open(FRONTEND_INDEX, 'r', encoding='utf-8') as f:
        return HttpResponse(f.read(), content_type='text/html')

from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('api.urls')),
    path('app/', serve_frontend),
] + static('/app/', document_root=FRONTEND_DIR)
