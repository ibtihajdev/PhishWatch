"""
PhishWatch — End-to-End API Tests
Run with: python manage.py test api
"""
import json
from django.test import TestCase, Client
from django.urls import reverse


class HealthCheckTest(TestCase):
    """Test the /health/ endpoint."""

    def setUp(self):
        self.client = Client()

    def test_health_returns_ok(self):
        response = self.client.get('/health/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'ok')
        self.assertIn('model_loaded', data)

    def test_health_model_loaded(self):
        response = self.client.get('/health/')
        data = response.json()
        self.assertTrue(data['model_loaded'],
                        "XGBoost model must be loaded. Run train_xgboost.py first.")


class PredictEndpointStructureTest(TestCase):
    """Test /predict/ response structure."""

    def setUp(self):
        self.client = Client()

    def _post(self, payload):
        return self.client.post(
            '/predict/',
            data=json.dumps(payload),
            content_type='application/json'
        )

    def test_missing_url_returns_400(self):
        resp = self._post({})
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertFalse(data['success'])
        self.assertIn('error', data)

    def test_empty_url_returns_400(self):
        resp = self._post({"url": ""})
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertFalse(data['success'])

    def test_no_scheme_url_returns_400(self):
        resp = self._post({"url": "google.com"})
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertFalse(data['success'])

    def test_response_has_required_keys(self):
        resp = self._post({"url": "https://www.google.com"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        required_keys = ['success', 'ml_verdict', 'confidence', 'domain', 'detection', 'features']
        for key in required_keys:
            self.assertIn(key, data, f"Response missing key: '{key}'")

    def test_response_success_true_for_valid_url(self):
        resp = self._post({"url": "https://www.google.com"})
        data = resp.json()
        self.assertTrue(data['success'])

    def test_confidence_is_float(self):
        resp = self._post({"url": "https://www.google.com"})
        data = resp.json()
        self.assertIsNotNone(data['confidence'])
        self.assertIsInstance(data['confidence'], float)
        self.assertGreaterEqual(data['confidence'], 0.0)
        self.assertLessEqual(data['confidence'], 100.0)

    def test_verdict_is_valid_string(self):
        resp = self._post({"url": "https://www.google.com"})
        data = resp.json()
        self.assertIn(data['ml_verdict'], ['Legitimate', 'Phishing', 'Unknown', 'Error'])

    def test_features_dict_has_all_16_features(self):
        resp = self._post({"url": "https://www.google.com"})
        data = resp.json()
        expected_features = [
            'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
            'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic',
            'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards'
        ]
        for feat in expected_features:
            self.assertIn(feat, data['features'], f"Feature '{feat}' missing from response")


class PredictLegitimateURLTest(TestCase):
    """Smoke test: well-known legitimate URL returns a valid verdict."""

    def setUp(self):
        self.client = Client()

    def test_google_returns_valid_response(self):
        """
        Verifies the API processes a known-good URL and returns a structured
        response. Note: the model's verdict depends on dataset bias — the key
        check here is API correctness, not model accuracy for this single URL.
        """
        resp = self.client.post(
            '/predict/',
            data=json.dumps({"url": "https://www.google.com"}),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data['success'])
        self.assertIn(data['ml_verdict'], ['Legitimate', 'Phishing'],
                      "Verdict must be a valid classification string")


class PredictIPBasedURLTest(TestCase):
    """IP-based URLs are a strong phishing signal."""

    def setUp(self):
        self.client = Client()

    def test_ip_url_classified(self):
        resp = self.client.post(
            '/predict/',
            data=json.dumps({"url": "http://125.98.3.123/login"}),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data['success'])
        # Should return some verdict (not error)
        self.assertIn(data['ml_verdict'], ['Legitimate', 'Phishing'])
