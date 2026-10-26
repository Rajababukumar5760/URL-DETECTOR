import pytest
from app.url_analyzer import analyze_url, URLAnalysisError

@pytest.mark.parametrize('url,scheme', [('https://example.com','https'),('http://example.com','http'),('example.com/path','https')])
def test_valid_urls_and_missing_scheme(url,scheme):
    result=analyze_url(url); assert result['scheme']==scheme; assert result['hostname']=='example.com'

def test_ip_address_host(): assert analyze_url('http://192.0.2.1/login')['is_ip_address'] is True

def test_at_symbol_is_detected():
    result=analyze_url('https://example.com@evil.example/login'); assert result['contains_at_symbol']; assert result['hostname']=='evil.example'

def test_credentials_removed_from_normalized_url():
    result=analyze_url('https://user:pass@example.com'); assert 'user:pass' not in result['normalized_url']; assert result['has_url_credentials']

def test_unusual_port(): assert analyze_url('https://example.com:8443')['port']==8443

def test_invalid_port():
    with pytest.raises(URLAnalysisError): analyze_url('https://example.com:99999')

def test_unicode_hostname_idna():
    result=analyze_url('https://пример.рф'); assert result['hostname'].startswith('xn--')

def test_malformed_host():
    with pytest.raises(URLAnalysisError): analyze_url('https://bad host/path')

def test_empty_input():
    with pytest.raises(URLAnalysisError): analyze_url('   ')

def test_too_long_input():
    with pytest.raises(URLAnalysisError): analyze_url('https://example.com/'+'a'*5000)

def test_encoded_pattern(): assert analyze_url('https://example.com/%2f%40admin')['has_suspicious_encoding']

def test_shortener(): assert analyze_url('https://bit.ly/abc')['is_known_shortener']

def test_query_parameter_count(): assert analyze_url('https://example.com/?a=1&b=2')['query_parameter_count']==2

def test_unsupported_scheme():
    with pytest.raises(URLAnalysisError): analyze_url('ftp://example.com/file')

def test_fragment_removed_from_normalized_url(): assert '#' not in analyze_url('https://example.com/path#frag')['normalized_url']