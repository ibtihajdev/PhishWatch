from urllib.parse import urlparse, urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests
from requests.exceptions import RequestException
import threading

def safe_get(url: str, timeout: int = 3):
    """
    Safely executes an HTTP GET request with strict timeouts.
    If the target server hangs or drops packets, this throws an error 
    and frees the worker thread instead of blocking indefinitely.
    """
    try:
        response = requests.get(
            url, 
            timeout=timeout, 
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        return response
    except RequestException as e:
        print(f"[Timeout/Error] Failed to fetch {url}: {str(e)}")
        return None

class DETECTION:
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                          r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                          r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                          r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                          r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                          r"tr\.im|link\.zip\.net"

    def getDomain(self,url):  # 1.Domain of the URL (Domain)
        domain = urlparse(url).netloc
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
            return domain

    def havingIP(self,url):
        try:
            domain = urlparse(url).netloc
            ipaddress.ip_address(domain)
            ip = 1
        except:
            ip = 0
        return ip

    def haveAtSign(self,url):
        if "@" in url:
            at = 1
        else:
            at = 0
        return at

    def getLength(self,url):
        if len(url) < 54:
            length = 1
        else:
            length = 0
        return length

    def getDepth(self,url):
        s = urlparse(url).path.split('/')
        depth = 0
        for j in range(len(s)):
            if len(s[j]) != 0:
                depth = depth + 1
        return max(1, depth)

    def redirection(self,url):
        pos = url.rfind('//')
        if pos > 6:
            if pos > 7:
                return 1
            else:
                return 0
        else:
            return 0

    def httpDomain(self,url):
        # print(url)
        domain = urlparse(url).netloc
        # print(domain)
        if 'https' in url:
            return 0
        else:
            return 1


    def tinyURL(self,url):
        match = re.search(self.shortening_services, url)
        if match:
            return 1
        else:
            return 0

    def prefixSuffix(self,url):
        if '-' in urlparse(url).netloc:
            return 1  # phishing
        else:
            return 0  # legitimate

    # def get_ipython():
    #     pass
    # get_ipython().system('pip install python-whois')

    def web_traffic(self,url):
        # NOTE: The Alexa API was shut down. Returning 0 (neutral/legitimate)
        # to avoid biasing every URL as phishing due to a dead API.
        try:
            url = urllib.parse.quote(url)
            rank = \
                BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url, timeout=2).read(),
                              "xml").find("REACH")['RANK']
            rank = int(rank)
            if rank < 100000:
                return 1
            else:
                return 0
        except Exception:
            # Alexa API is defunct — default to 0 (do not penalise as phishing)
            return 0

    def domainAge(self,domain_name):
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
            try:
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except:
                return 1
        if ((expiration_date is None) or (creation_date is None)):
            return 1
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 1
        else:
            # `python-whois` may return tz-aware datetimes for one field and naive for another.
            # Normalize to the same "awareness" to avoid TypeError in subtraction.
            if getattr(expiration_date, "tzinfo", None) and not getattr(creation_date, "tzinfo", None):
                creation_date = creation_date.replace(tzinfo=expiration_date.tzinfo)
            elif getattr(creation_date, "tzinfo", None) and not getattr(expiration_date, "tzinfo", None):
                expiration_date = expiration_date.replace(tzinfo=creation_date.tzinfo)
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain / 30) < 6):
                age = 1
            else:
                age = 0
            return age

    def domainEnd(self,domain_name):
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date, str):
            try:
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except:
                return 1
        if (expiration_date is None):
            return 1
        elif (type(expiration_date) is list):
            return 1
        else:
            # Match `today` timezone-awareness to `expiration_date` to avoid
            # "can't subtract offset-naive and offset-aware datetimes".
            tzinfo = getattr(expiration_date, "tzinfo", None)
            today = datetime.now(tz=tzinfo) if tzinfo else datetime.now()
            end = abs((expiration_date - today).days)
            if ((end / 30) < 6):
                end = 0
            else:
                end = 1
            return end

    def iframe(self,response):
        if not response:
            return 0
        else:
            if re.findall(r"<iframe>|<frameBorder>", response.text, re.I):
                return 1
            else:
                return 0

    def mouseOver(self,response):
        if not response:
            return 0
        else:
            if re.findall("<script>.+onmouseover.+</script>", response.text):
                return 1
            else:
                return 0

    def rightClick(self,response):
        if not response:
            return 0
        else:
            if re.findall(r"event.button ?== ?2", response.text):
                return 0
            else:
                return 1

    def forwarding(self,response):
        if not response:
            return 0
        else:
            if len(response.history) <= 2:
                return 0
            else:
                return 1

    # Function to extract features
    # There are 17 features extracted from the dataset
    def featureExtractions(self, url):
        import concurrent.futures
        import socket
        detection = DETECTION()

        # Address-bar features (fast, no network) ─────────────────────────────
        # Feature order MUST match model training column order:
        # Have_IP, Have_At, URL_Length, URL_Depth, Redirection,
        # https_Domain, TinyURL, Prefix/Suffix, ...
        features = [
            detection.getDomain(url),
            detection.havingIP(url),
            detection.haveAtSign(url),
            detection.getLength(url),
            detection.getDepth(url),
            detection.redirection(url),
            detection.httpDomain(url),
            detection.tinyURL(url),
            detection.prefixSuffix(url),
        ]

        # Network-dependent features — run in parallel to cut latency ─────────
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

        def do_whois():
            try:
                res, err = get_whois_with_timeout(urlparse(url).netloc, 5)
                if res is None:
                    return None, 1
                return res, 0
            except Exception:
                return None, 1  # dns=1 means no record

        def do_http():
            return safe_get(url, timeout=3)

        def do_traffic():
            return detection.web_traffic(url)

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            f_whois   = pool.submit(do_whois)
            f_http    = pool.submit(do_http)
            f_traffic = pool.submit(do_traffic)

            domain_name, dns = f_whois.result()
            response         = f_http.result()
            traffic          = f_traffic.result()

        features.append(dns)
        features.append(traffic)
        features.append(1 if dns == 1 else detection.domainAge(domain_name))
        features.append(1 if dns == 1 else detection.domainEnd(domain_name))

        # HTML & Javascript features ───────────────────────────────────────────
        features.append(detection.iframe(response))
        features.append(detection.mouseOver(response))
        features.append(detection.rightClick(response))
        features.append(detection.forwarding(response))

        # features.append(label)

        return features
        # bob = featureExtractions('http://www.facebook.com/home/service')
        # print(bob)
