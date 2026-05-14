import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime

def get_ssl_info(url):
    try:
        parsed_url = urlparse(url if '://' in url else 'https://' + url)
        domain = parsed_url.hostname

        if not domain:
            return {"has_ssl": False, "error": "Invalid domain"}

        context = ssl.create_default_context()
        
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Extract Issuer
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer.get('organizationName') or issuer.get('commonName') or 'Unknown'

                # Extract Subject
                subject = dict(x[0] for x in cert.get('subject', []))
                subject_name = subject.get('commonName') or 'Unknown'

                # Extract Expiry Date
                not_after = cert.get('notAfter')
                expiry_date = None
                is_expired = False
                if not_after:
                    # e.g., 'May  9 23:59:59 2024 GMT'
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    is_expired = expiry_date < datetime.utcnow()

                return {
                    "has_ssl": True,
                    "issuer": issuer_name,
                    "subject": subject_name,
                    "expiry_date": expiry_date.strftime('%Y-%m-%d %H:%M:%S') if expiry_date else "Unknown",
                    "is_expired": is_expired
                }
    except ssl.SSLError as e:
        return {"has_ssl": False, "error": f"SSL Error: {str(e)}"}
    except socket.timeout:
        return {"has_ssl": False, "error": "Connection timed out"}
    except Exception as e:
        return {"has_ssl": False, "error": str(e)}
