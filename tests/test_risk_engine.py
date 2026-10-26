from app.risk_engine import evaluate_rules
from app.url_analyzer import analyze_url

def test_ordinary_url_low_observed_risk():
    result=evaluate_rules(analyze_url('https://example.com/')); assert result['risk_category']=='LOW OBSERVED RISK'; assert result['findings']==[]

def test_http_url_triggers_low_rule():
    result=evaluate_rules(analyze_url('http://example.com')); assert any(x['rule_id']=='URL011' for x in result['findings'])

def test_multiple_indicators_raise_score():
    result=evaluate_rules(analyze_url('http://192.0.2.1/verify-account-login?x=1')); assert result['rule_score']>=25; assert result['risk_category'] in {'CAUTION','HIGH RISK'}

def test_high_risk_ip_and_at_indicators():
    result=evaluate_rules(analyze_url('http://192.0.2.1/login@verify-account.example.top')); assert result['risk_category']=='HIGH RISK'

def test_scores_capped_at_100():
    result=evaluate_rules(analyze_url('http://192.0.2.1/'+'a'*150+'?a=1&b=2')); assert 0<=result['rule_score']<=100

def test_findings_are_explainable():
    result=evaluate_rules(analyze_url('http://192.0.2.1')); assert all({'rule_id','title','explanation','severity','evidence','points'} <= set(x) for x in result['findings'])

def test_thresholds_are_reported(): assert evaluate_rules(analyze_url('https://example.com'))['thresholds']=={'caution':25,'high':55}