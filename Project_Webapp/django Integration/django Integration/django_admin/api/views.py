"""
PhishWatch — URL Prediction API
Django REST Framework view that extracts 13 URL features and runs
them through the pre-trained XGBoost model to produce a phishing verdict.

NOTE: Web_Traffic, Domain_Age, and Domain_End were removed from the model
because the Alexa API is deprecated and WHOIS data is unreliable at runtime.
"""

from rest_framework.views import APIView
from django.http import JsonResponse
from django.core.cache import cache
import json
import pickle
import os
import pandas as pd
import socket
import ipaddress
from urllib.parse import urlparse
from .phishing_url_detection import DETECTION
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from rest_framework.throttling import AnonRateThrottle
from rest_framework.exceptions import Throttled
from rest_framework.permissions import IsAuthenticated
from rest_framework import authentication, exceptions
from django.contrib.auth import get_user_model
import time
import logging
import hashlib
import difflib
import re
from .models import FalsePositiveReport, ScanHistory

import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
import concurrent.futures
from rest_framework.decorators import api_view, authentication_classes, permission_classes, throttle_classes
from django.conf import settings
import requests
import base64
import urllib.parse
from datetime import datetime

User = get_user_model()
import ipaddress
from urllib.parse import urlparse
from .phishing_url_detection import DETECTION
from django.core.validators import URLValidator

PROTECTED_BRANDS = {
    "youtube": ["youtube.com", "youtu.be"],
    "google": ["google.com"],
    "facebook": ["facebook.com", "fb.com"],
    "apple": ["apple.com"],
    "microsoft": ["microsoft.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "paypal": ["paypal.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"]
}

def detect_brand_spoofing(url):
    try:
        domain = urlparse(url).hostname.lower()
    except Exception:
        return False
        
    for brand, official_list in PROTECTED_BRANDS.items():
        if any(domain == off or domain.endswith("." + off) for off in official_list):
            return False # Officially safe
            
    words = re.split(r'[\.-]', domain)
    for word in words:
        norm_word = word.replace('0', 'o').replace('1', 'l').replace('3', 'e')
        for brand in PROTECTED_BRANDS.keys():
            if brand in norm_word:
                return True
            if len(word) >= 5 and difflib.SequenceMatcher(None, norm_word, brand).ratio() >= 0.7:
                return True
    return False
from django.core.exceptions import ValidationError
from rest_framework.throttling import AnonRateThrottle
from rest_framework.exceptions import Throttled
import time
import logging
import hashlib
from .models import FalsePositiveReport

telemetry_logger = logging.getLogger('ml_telemetry')

def log_prediction(url, label, confidence, features, latency_ms):
    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
    log_entry = {
        "event": "prediction",
        "url_hash": url_hash,
        "prediction_label": label,
        "confidence_score": confidence,
        "latency_ms": round(latency_ms, 2),
        "features": features
    }
    telemetry_logger.info(json.dumps(log_entry))

class CustomAnonRateThrottle(AnonRateThrottle):
    def wait(self):
        return super().wait()

def is_safe_url(url: str) -> tuple[bool, str]:
    """
    Resolves the domain and checks if the underlying IP routes to a private, 
    loopback, or reserved subnet. Returns (is_safe, error_message).
    """
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False, "Invalid URL hostname."
            
        ip_addr = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip_addr)
        
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False, "Security violation: The provided URL resolves to a restricted or private IP address."
            
        return True, ""
    except socket.gaierror:
        # User requested to get a prediction result instead of an error popup
        # when a domain is unresolvable or offline.
        return True, ""
    except ValueError:
        return False, "Invalid IP address format."
    except Exception as e:
        return False, f"Error validating URL: {str(e)}"

# ─── Load model once at startup ───────────────────────────────────────────────
import os
from django.conf import settings

MODEL_PATH = os.path.join(settings.BASE_DIR, 'api', 'XGBoostClassifier.pickle.dat')

if os.path.exists(MODEL_PATH):
    with open(MODEL_PATH, 'rb') as f:
        xgb_model = pickle.load(f)
    print("[PhishWatch] XGBoost model loaded successfully.")
else:
    xgb_model = None
    print(f"[PhishWatch] WARNING: model not found at {MODEL_PATH}")

# ─── Initialize Firebase Admin ────────────────────────────────────────────────
if not firebase_admin._apps:
    _firebase_cred_json = os.environ.get('FIREBASE_CREDENTIALS_JSON')
    _firebase_cred_path = os.path.normpath(os.path.join(settings.BASE_DIR, '..', '..', '..', '..', 'phishing-detector-e7eef-firebase-adminsdk-fbsvc-a87923caa5.json'))

    if _firebase_cred_json:
        # Cloud deployment: load from environment variable
        try:
            _cred_dict = json.loads(_firebase_cred_json)
            cred = credentials.Certificate(_cred_dict)
            firebase_admin.initialize_app(cred)
            print("[PhishWatch] Firebase Admin initialized from environment variable.")
        except Exception as e:
            print(f"[PhishWatch] ERROR: Failed to init Firebase from env var: {e}")
    elif os.path.exists(_firebase_cred_path):
        # Local development: load from JSON file
        cred = credentials.Certificate(_firebase_cred_path)
        firebase_admin.initialize_app(cred)
        print("[PhishWatch] Firebase Admin initialized from local credentials file.")
    else:
        print("[PhishWatch] WARNING: No Firebase credentials found. Authentication will fail.")

class FirebaseAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        if not auth_header:
            return None
        
        bearer_token = auth_header.split(" ")
        if len(bearer_token) != 2 or bearer_token[0] != "Bearer":
            return None
            
        token = bearer_token[1]

        # If Firebase Admin isn't initialized (no credentials on server),
        # accept any Bearer token as an anonymous user so scans still work.
        if not firebase_admin._apps:
            anon_user, _ = User.objects.get_or_create(email="anon@phishwatch.local")
            return (anon_user, None)
        
        try:
            decoded_token = firebase_auth.verify_id_token(token)
            uid = decoded_token.get("uid")
            email = decoded_token.get("email") or f"{uid}@firebase.local"
        except Exception as e:
            raise exceptions.AuthenticationFailed(f"Invalid Firebase Token: {e}")
            
        # Create or get user based on email to satisfy IsAuthenticated
        user, _ = User.objects.get_or_create(email=email)
        return (user, None)

# These 13 features match exactly what the model was trained on.
# Web_Traffic, Domain_Age, Domain_End were dropped (unreliable at runtime).
FEATURE_NAMES = [
    'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
    'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record',
    'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards'
]


class URLPredictionApiView(APIView):
    """
    POST /predict/
    Body: { "url": "https://..." }
    Returns: { success, ml_verdict, confidence, detection, features }
    """
    authentication_classes = [FirebaseAuthentication]
    permission_classes = []  # Auth is handled gracefully in FirebaseAuthentication
    throttle_classes = [CustomAnonRateThrottle]

    def throttled(self, request, wait):
        return JsonResponse({
            "success": False,
            "error": f"Rate limit exceeded. Please wait {int(wait)} seconds before scanning another URL."
        }, status=429)

    def post(self, request):
        start_time = time.time()
        # ── Parse input ───────────────────────────────────────────────────────
        try:
            body = request.data if hasattr(request, 'data') else json.loads(request.body)
        except Exception:
            return JsonResponse({"success": False, "error": "Invalid request body."}, status=400)

        # 1. Check that the request body contains a "url" key.
        if "url" not in body:
            return JsonResponse({"success": False, "error": "URL field is required."}, status=400)

        url = body["url"]

        # 2. Check that the url value is a non-empty string.
        if not url or not isinstance(url, str) or not url.strip():
            return JsonResponse({"success": False, "error": "A valid URL string must be provided."}, status=400)

        url = url.strip()

        # 3. Check that the url starts with http:// or https://
        if not url.startswith(('http://', 'https://')):
            return JsonResponse({"success": False, "error": "URL must begin with http:// or https://"}, status=400)

        # 4. Use Django's built-in URLValidator to validate the URL format
        from django.core.validators import URLValidator
        from django.core.exceptions import ValidationError
        validator = URLValidator()
        try:
            validator(url)
        except ValidationError:
            return JsonResponse({"success": False, "error": "Malformed URL provided."}, status=400)

        # 5. SSRF CHECK
        is_safe, error_msg = is_safe_url(url)
        if not is_safe:
            return JsonResponse({
                "success": False, 
                "error": error_msg
            }, status=400)

        # ── Check Cache ───────────────────────────────────────────────────────
        cache_key = f"phishwatch_url_{url}"
        cached_result = cache.get(cache_key)
        if cached_result:
            print(f"[PhishWatch] Cache hit for: {url}")
            return JsonResponse(cached_result)

        # ── Feature extraction ────────────────────────────────────────────────
        try:
            detection_obj = DETECTION()
            raw_features  = detection_obj.featureExtractions(url)
        except Exception as e:
            return JsonResponse({"success": False, "error": f"Feature extraction failed: {str(e)}"}, status=500)

        # raw_features[0]  = domain string
        # raw_features[1:] = 16 numeric features
        domain       = raw_features[0]
        all_features = raw_features[1:]   # full 16-value list from extractor

        # Drop the 3 columns the model was NOT trained on
        ALL_16 = [
            'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
            'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record',
            'Web_Traffic', 'Domain_Age', 'Domain_End',
            'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards'
        ]
        DROP = {'Web_Traffic', 'Domain_Age', 'Domain_End'}
        num_features = [
            v for name, v in zip(ALL_16, all_features) if name not in DROP
        ]

        # ── ML prediction ─────────────────────────────────────────────────────
        ml_verdict = "Unknown"
        confidence = None

        if xgb_model is not None:
            df_features = pd.DataFrame([num_features], columns=FEATURE_NAMES)
            try:
                pred       = int(xgb_model.predict(df_features)[0])
                proba      = xgb_model.predict_proba(df_features)[0]
                # proba[0] = P(Legitimate), proba[1] = P(Phishing)
                ml_verdict = "Phishing" if pred == 1 else "Legitimate"
                confidence = round(float(max(proba)) * 100, 1)
            except Exception as e:
                ml_verdict = "Error"
                confidence = None

        # ── Post-processing: Brand Spoofing Heuristic ─────────────────────────
        if ml_verdict == "Legitimate" and detect_brand_spoofing(url):
            ml_verdict = "Phishing"
            confidence = 99.9  # High confidence for brand spoofing

        # ── Build features dict ───────────────────────────────────────────────
        features_dict = {
            name: int(val)
            for name, val in zip(FEATURE_NAMES, num_features)
        }

        response_data = {
            "success":    True,
            "ml_verdict": ml_verdict,
            "confidence": confidence,
            "domain":     domain,
            "detection":  raw_features,         # kept for backwards compat
            "features":   features_dict,        # clean named dict for UI
        }

        latency = (time.time() - start_time) * 1000 # Convert to milliseconds
        
        # Log asynchronously/fire-and-forget before returning the response
        if ml_verdict != "Unknown":
            log_prediction(url, ml_verdict, confidence, features_dict, latency)

        # Save to Redis cache
        cache.set(cache_key, response_data, timeout=86400)

        return JsonResponse(response_data, safe=False)

class ReportFalsePositiveView(APIView):
    throttle_classes = [CustomAnonRateThrottle]

    def throttled(self, request, wait):
        return JsonResponse({
            "success": False,
            "error": f"Rate limit exceeded. Please wait {int(wait)} seconds before reporting."
        }, status=429)

    def post(self, request):
        url = request.data.get('url', '').strip()
        if not url or len(url) > 2000:
            return JsonResponse({"success": False, "error": "Invalid URL"}, status=400)
            
        FalsePositiveReport.objects.create(url=url)
        return JsonResponse({"success": True, "message": "Report submitted for human review."})


class HealthCheckView(APIView):
    """GET /health/ — returns model status for testing."""

    def get(self, request):
        return JsonResponse({
            "status":       "ok",
            "model_loaded": xgb_model is not None,
            "model_path":   MODEL_PATH,
        })

import threading
import whois

def get_whois_with_timeout(domain, timeout=5):
    result = [None]
    error = [None]

    def target():
        try:
            result[0] = whois.whois(domain)
        except Exception as e:
            error[0] = str(e)

    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        return None, "WHOIS request timed out."
    if error[0]:
        return None, error[0]
    return result[0], None

@api_view(['POST'])
@authentication_classes([FirebaseAuthentication])
@permission_classes([])
@throttle_classes([CustomAnonRateThrottle])
def whois_lookup(request):
    try:
        body = request.data if hasattr(request, 'data') else json.loads(request.body)
        url = body.get('url', '').strip()
    except Exception:
        return JsonResponse({"success": False, "error": "Invalid request body."}, status=400)
    
    if not url:
        return JsonResponse({"success": False, "error": "URL is required."}, status=400)
        
    try:
        domain = urlparse(url if '://' in url else 'http://' + url).hostname
        if not domain:
            raise ValueError("Invalid domain")
    except Exception:
        return JsonResponse({"success": False, "error": "Could not extract domain."}, status=400)

    try:
        w, err = get_whois_with_timeout(domain, 5)
        if w is None:
            return JsonResponse({"success": False, "error": err or "WHOIS data could not be retrieved."})
    except Exception:
        return JsonResponse({"success": False, "error": "WHOIS data could not be retrieved."})

    try:
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
            
        domain_age_days = None
        is_newly_registered = False
        
        if creation_date:
            try:
                today = datetime.now()
                if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                    today = datetime.now(creation_date.tzinfo)
                domain_age_days = (today - creation_date).days
                is_newly_registered = domain_age_days < 180
            except Exception:
                pass
                
        return JsonResponse({
            "success": True,
            "domain": domain,
            "created_date": creation_date.strftime('%Y-%m-%d') if hasattr(creation_date, 'strftime') else str(creation_date),
            "expiry_date": expiration_date.strftime('%Y-%m-%d') if hasattr(expiration_date, 'strftime') else str(expiration_date),
            "registrar": w.registrar,
            "country": w.country,
            "domain_age_days": domain_age_days,
            "is_newly_registered": is_newly_registered
        })
    except Exception:
        return JsonResponse({"success": False, "error": "WHOIS data could not be retrieved."})

@api_view(['POST'])
@authentication_classes([FirebaseAuthentication])
@permission_classes([])
@throttle_classes([CustomAnonRateThrottle])
def screenshot_preview(request):
    try:
        body = request.data if hasattr(request, 'data') else json.loads(request.body)
        url = body.get('url', '').strip()
    except Exception:
        return JsonResponse({"success": False, "error": "Invalid request body."}, status=400)
        
    if not url:
        return JsonResponse({"success": False, "error": "URL is required."}, status=400)

    try:
        api_key = getattr(settings, 'SCREENSHOTLAYER_API_KEY', '')
        if not api_key:
            return JsonResponse({"success": False, "error": "Screenshot API key not configured."})
            
        encoded_url = urllib.parse.quote(url)
        api_url = f"https://api.screenshotlayer.com/api/capture?access_key={api_key}&url={encoded_url}&viewport=1280x800&format=PNG&fullpage=0&width=1000"
        
        resp = requests.get(api_url, timeout=10)
        
        if resp.status_code == 200 and resp.headers.get('Content-Type', '').startswith('image/'):
            img_b64 = base64.b64encode(resp.content).decode('utf-8')
            return JsonResponse({
                "success": True,
                "image_base64": f"data:image/png;base64,{img_b64}"
            })
        else:
            return JsonResponse({"success": False, "error": "Screenshot could not be captured."})
            
    except Exception:
        return JsonResponse({"success": False, "error": "Screenshot could not be captured."})

@api_view(['POST'])
@authentication_classes([FirebaseAuthentication])
@permission_classes([])
@throttle_classes([CustomAnonRateThrottle])
def safe_browsing_check(request):
    try:
        body = request.data if hasattr(request, 'data') else json.loads(request.body)
        url = body.get('url', '').strip()
        
        if not url:
            return JsonResponse({"success": False, "error": "URL is required."}, status=400)
            
        api_key = getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', '')
        if not api_key:
            return JsonResponse({"success": False, "error": "Google Safe Browsing API key not configured."})
            
        gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {
                "clientId": "phishwatch",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }
        
        resp = requests.post(gsb_url, json=payload, timeout=5)
        
        if resp.status_code == 200:
            data = resp.json()
            if "matches" in data and len(data["matches"]) > 0:
                threat_type = data["matches"][0].get("threatType", "UNKNOWN")
                return JsonResponse({
                    "success": True,
                    "is_dangerous": True,
                    "threat_type": threat_type,
                    "verdict": "Dangerous — flagged by Google Safe Browsing"
                })
            else:
                return JsonResponse({
                    "success": True,
                    "is_dangerous": False,
                    "threat_type": None,
                    "verdict": "Clean — not flagged by Google Safe Browsing"
                })
        else:
            return JsonResponse({"success": False, "error": "Google Safe Browsing check could not be completed."})
            
    except Exception as e:
        return JsonResponse({"success": False, "error": "Google Safe Browsing check could not be completed."})

@api_view(['POST'])
@authentication_classes([FirebaseAuthentication])
@permission_classes([IsAuthenticated])
def save_history(request):
    try:
        body = request.data if hasattr(request, 'data') else json.loads(request.body)
        url = body.get('url')
        verdict = body.get('verdict')
        confidence = body.get('confidence')

        if not url or not verdict:
            return JsonResponse({"success": False, "error": "URL and verdict are required."}, status=400)

        ScanHistory.objects.create(
            user=request.user,
            url=url,
            verdict=verdict,
            confidence=confidence
        )
        return JsonResponse({"success": True})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)

@api_view(['GET'])
@authentication_classes([FirebaseAuthentication])
@permission_classes([IsAuthenticated])
def get_history(request):
    try:
        history = ScanHistory.objects.filter(user=request.user).order_by('-timestamp')[:50]
        data = []
        for item in history:
            data.append({
                "url": item.url,
                "verdict": item.verdict,
                "confidence": item.confidence,
                "timestamp": item.timestamp.isoformat()
            })
        return JsonResponse({"success": True, "history": data})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)


from .ssl_checker import get_ssl_info

@api_view(['POST'])
@authentication_classes([FirebaseAuthentication])
@permission_classes([])
@throttle_classes([CustomAnonRateThrottle])
def ssl_check(request):
    try:
        body = request.data if hasattr(request, 'data') else json.loads(request.body)
        url = body.get('url', '').strip()
        
        if not url:
            return JsonResponse({"success": False, "error": "URL is required."}, status=400)
            
        ssl_data = get_ssl_info(url)
        if ssl_data.get("has_ssl"):
            return JsonResponse({
                "success": True,
                "has_ssl": True,
                "issuer": ssl_data.get("issuer"),
                "subject": ssl_data.get("subject"),
                "expiry_date": ssl_data.get("expiry_date"),
                "is_expired": ssl_data.get("is_expired")
            })
        else:
            return JsonResponse({
                "success": True,
                "has_ssl": False,
                "error": ssl_data.get("error")
            })
            
    except Exception as e:
        return JsonResponse({"success": False, "error": "SSL check could not be completed."})
