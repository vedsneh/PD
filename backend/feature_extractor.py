import re
import math
from urllib.parse import urlparse
import tldextract

_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_TLDS = {'zip', 'review', 'country', 'kim', 'cricket', 'science',
                    'work', 'party', 'gq', 'link', 'top', 'xyz', 'tk'}
SHORTENING_SERVICES = {'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly',
                        'is.gd', 'buff.ly', 'adf.ly', 'rebrand.ly'}
BRANDS = {'paypal', 'google', 'amazon', 'apple', 'microsoft', 'facebook',
          'bankofamerica', 'chase', 'netflix', 'instagram', 'linkedin', 'wellsfargo'}
PHISH_HINT_WORDS = {'login', 'signin', 'verify', 'secure', 'account', 'update',
                     'confirm', 'banking', 'password', 'ebay', 'webscr'}

def generate_reasons(features: dict, url: str) -> list[str]:
    reasons = []

    if features["ip"]:
        reasons.append("The website uses an IP address instead of a normal domain")

    if features["punycode"]:
        reasons.append("The domain uses punycode, which can be used to disguise characters")

    if features["random_domain"]:
        reasons.append("The domain has an unusual/random-looking structure")

    if features["prefix_suffix"]:
        reasons.append("The domain contains a suspicious hyphenated structure")

    if features["shortening_service"]:
        reasons.append("A URL shortening service is being used")

    if features["phish_hints"] > 0:
        reasons.append("Login, verification, security, or account-related keywords detected")

    if features["brand_in_subdomain"]:
        reasons.append("A known brand name appears in the subdomain")

    if features["brand_in_path"]:
        reasons.append("A known brand name appears in the URL path")

    if features["suspicious_tld"]:
        reasons.append("The website uses a potentially suspicious top-level domain")

    if features["abnormal_subdomain"]:
        reasons.append("The subdomain has an unusual structure")

    if features["http_in_path"]:
        reasons.append("An HTTP URL appears inside the path")

    if features["tld_in_path"]:
        reasons.append("The domain extension appears inside the URL path")

    if features["nb_at"] > 0:
        reasons.append("The URL contains an @ symbol, which can obscure the real destination")

    if not reasons:
        reasons.append("No major suspicious URL characteristics were detected")

    return reasons
    
def _shannon_entropy(s):
    if not s:
        return 0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def _avg_vowel_ratio(words):
    """Real English words average ~38-42% vowels. Random/obfuscated tokens
    (common in phishing paths) tend to deviate from this -- either very low
    (consonant clusters) or unusually high/low. This helps distinguish a
    legitimate long enterprise URL (real words: 'Understanding', 'Problem')
    from an obfuscated phishing path (random tokens), which raw length or
    word-count alone cannot do."""
    VOWELS = set('aeiouAEIOU')
    ratios = []
    for w in words:
        letters = [c for c in w if c.isalpha()]
        if len(letters) >= 3:
            ratios.append(sum(1 for c in letters if c in VOWELS) / len(letters))
    return sum(ratios) / len(ratios) if ratios else 0.4


def _word_stats(words):
    if not words:
        return 0, 0, 0
    lengths = [len(w) for w in words]
    return min(lengths), max(lengths), sum(lengths) / len(lengths)


def extract_lexical_features(url: str) -> dict:
    # Normalize: strip a single trailing slash so 'example.com' and
    # 'example.com/' (which browsers send interchangeably) always produce
    # identical features -- otherwise a tree model can flip verdicts on
    # what is really the same URL.
    if url.endswith('/') and not url.endswith('://'):
        url = url[:-1]

    parsed = urlparse(url if '://' in url else 'http://' + url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    ext = _tld_extractor(url)
    domain = ext.domain
    subdomain = ext.subdomain
    tld = ext.suffix

    words_raw = [w for w in re.split(r'[/\-_.?=&]', url) if w]
    words_host = [w for w in re.split(r'[\-.]', hostname) if w]
    words_path = [w for w in re.split(r'[/\-_.?=&]', path) if w]

    sw_raw, lw_raw, aw_raw = _word_stats(words_raw)
    sw_host, lw_host, aw_host = _word_stats(words_host)
    sw_path, lw_path, aw_path = _word_stats(words_path)

    return {
        'length_url': len(url),
        'length_hostname': len(hostname),
        'ip': 1 if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname) else 0,
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_or': url.count('|'),
        'nb_eq': url.count('='),
        'nb_underscore': url.count('_'),
        'nb_tilde': url.count('~'),
        'nb_percent': url.count('%'),
        'nb_slash': url.count('/'),
        'nb_star': url.count('*'),
        'nb_colon': url.count(':'),
        'nb_comma': url.count(','),
        'nb_semicolon': url.count(';'),
        'nb_dollar': url.count('$'),
        'nb_space': url.count(' ') + url.count('%20'),
        'nb_com': url.count('.com'),
        'nb_dslash': max(url.count('//') - 1, 0),
        'http_in_path': path.lower().count('http'),
        'https_token': 1 if 'https' in (hostname + path) else 0,
        'ratio_digits_url': sum(c.isdigit() for c in url) / max(len(url), 1),
        'ratio_digits_host': sum(c.isdigit() for c in hostname) / max(len(hostname), 1),
        'punycode': 1 if 'xn--' in hostname else 0,
        'port': 1 if parsed.port else 0,
        'tld_in_path': 1 if tld and tld in path else 0,
        'tld_in_subdomain': 1 if tld and tld in subdomain else 0,
        'abnormal_subdomain': 1 if re.match(r'^www-', subdomain or '') else 0,
        'nb_subdomains': len(subdomain.split('.')) if subdomain else 0,
        'prefix_suffix': 1 if '-' in domain else 0,
        'random_domain': 1 if _shannon_entropy(domain) > 3.5 else 0,
        'shortening_service': 1 if f"{domain}.{tld}" in SHORTENING_SERVICES else 0,
        'path_extension': 1 if re.search(r'\.\w{2,4}$', path) else 0,
        'nb_redirection': max(url.count('//') - 1, 0),
        'nb_external_redirection': 0,
        'length_words_raw': len(words_raw),
        'char_repeat': max((len(m.group()) for m in re.finditer(r'(.)\1*', url)), default=1),
        'shortest_words_raw': sw_raw, 'shortest_word_host': sw_host, 'shortest_word_path': sw_path,
        'longest_words_raw': lw_raw, 'longest_word_host': lw_host, 'longest_word_path': lw_path,
        'avg_words_raw': aw_raw, 'avg_word_host': aw_host, 'avg_word_path': aw_path,
        'phish_hints': sum(url.lower().count(w) for w in PHISH_HINT_WORDS),
        'domain_in_brand': 1 if domain.lower() in BRANDS else 0,
        'brand_in_subdomain': 1 if any(b in (subdomain or '').lower() for b in BRANDS) else 0,
        'brand_in_path': 1 if any(b in path.lower() for b in BRANDS) else 0,
        'suspicious_tld': 1 if tld in SUSPICIOUS_TLDS else 0,
        'statistical_report': 0,
        'word_vowel_ratio': _avg_vowel_ratio(words_raw),
    }
