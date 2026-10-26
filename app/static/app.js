const input = document.getElementById('urlInput');
const button = document.getElementById('analyzeBtn');
const statusBox = document.getElementById('status');
const results = document.getElementById('results');
const charCount = document.getElementById('charCount');
input.addEventListener('input', () => charCount.textContent = `${input.value.length} / 4096`);
document.querySelectorAll('.sample').forEach(btn => btn.addEventListener('click', () => { input.value = btn.dataset.url; charCount.textContent = `${input.value.length} / 4096`; input.focus(); }));
button.addEventListener('click', runAnalysis);
input.addEventListener('keydown', e => { if (e.key === 'Enter') runAnalysis(); });
function showStatus(message, error = false) { statusBox.textContent = message; statusBox.hidden = false; statusBox.classList.toggle('error', error); }
function addText(tag, className, text) { const el = document.createElement(tag); if (className) el.className = className; el.textContent = text; return el; }
function pretty(key) { return ({ url_length: 'URL length', hostname_length: 'Hostname length', hostname_dot_count: 'Hostname dots', subdomain_count_approx: 'Approx. subdomains', is_ip_address: 'IP address host', uses_https: 'HTTPS used', contains_at_symbol: '@ symbol present', hostname_hyphen_count: 'Hostname hyphens', hostname_digit_count: 'Hostname digits', query_parameter_count: 'Query parameters', has_suspicious_encoding: 'Selected encoding pattern', has_misleading_hostname_pattern: 'Security-themed wording', is_known_shortener: 'Known shortener', uses_uncommon_tld: 'TLD on review list', tld: 'Top-level domain', port: 'Explicit port' }[key] || key.replaceAll('_', ' ')); }
function formatValue(value) { if (value === true) return 'Yes'; if (value === false) return 'No'; if (value === null || value === undefined || value === '') return '—'; return String(value); }
async function runAnalysis() {
  const url = input.value.trim();
  if (!url) { showStatus('Enter a URL to begin the analysis.', true); input.focus(); return; }
  button.disabled = true; button.textContent = 'Analyzing…'; results.hidden = true; showStatus('Inspecting URL structure locally. The submitted URL will not be opened.');
  try {
    const response = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'The request could not be analyzed.');
    render(data); statusBox.hidden = true; results.hidden = false;
  } catch (err) { showStatus(err.message || 'Could not connect to PhishGuard. Check that the server is running.', true); }
  finally { button.disabled = false; button.innerHTML = 'Analyze URL <span aria-hidden="true">→</span>'; }
}
function render(data) {
  const category = data.risk_category;
  const card = document.getElementById('riskCard');
  card.className = 'panel risk-card ' + (category === 'HIGH RISK' ? 'high' : category === 'CAUTION' ? 'caution' : category === 'LOW OBSERVED RISK' ? 'low' : 'insufficient');
  document.getElementById('riskIcon').textContent = category === 'LOW OBSERVED RISK' ? '✓' : category === 'HIGH RISK' ? '!' : category === 'CAUTION' ? '!' : '?';
  document.getElementById('riskCategory').textContent = category;
  document.getElementById('riskExplanation').textContent = data.explanation;
  document.getElementById('ruleScore').textContent = `${data.rule_score} / 100`;
  document.getElementById('scoreBar').style.width = `${Math.min(100, data.rule_score)}%`;
  document.getElementById('hostname').textContent = data.hostname || 'Unavailable';
  document.getElementById('normalizedUrl').textContent = data.normalized_url || 'Unavailable';
  document.getElementById('mlStatus').textContent = data.ml?.available ? (data.ml.label || 'Model ready') : 'Not trained / unavailable';
  const findings = document.getElementById('findings'); findings.replaceChildren();
  document.getElementById('findingCount').textContent = `${data.findings.length} finding${data.findings.length === 1 ? '' : 's'}`;
  if (!data.findings.length) findings.append(addText('div', 'empty-findings', 'No configured warning rules were triggered. This is not a guarantee of safety.'));
  data.findings.forEach(f => { const item = addText('div', `finding ${f.severity}`, ''); item.append(addText('span', 'finding-bar', '')); const body = addText('div', '', ''); body.append(addText('h4', '', `${f.rule_id} · ${f.title}`), addText('p', '', f.explanation), addText('div', 'evidence', `Evidence: ${f.evidence} · +${f.points} points`)); item.append(body, addText('span', 'severity', f.severity)); findings.append(item); });
  const features = document.getElementById('features'); features.replaceChildren();
  const priority = ['url_length', 'hostname_length', 'hostname_dot_count', 'subdomain_count_approx', 'is_ip_address', 'uses_https', 'contains_at_symbol', 'hostname_hyphen_count', 'hostname_digit_count', 'query_parameter_count', 'has_suspicious_encoding', 'has_misleading_hostname_pattern', 'is_known_shortener', 'uses_uncommon_tld', 'tld', 'port'];
  priority.filter(k => Object.hasOwn(data.features, k)).forEach(k => { const tile = addText('div', 'feature', ''); tile.append(addText('span', '', pretty(k)), addText('strong', '', formatValue(data.features[k]))); features.append(tile); });
  document.getElementById('domainNote').textContent = 'Registrable-domain parsing is approximate: this MVP does not bundle a Public Suffix List. Feature flags are indicators, not proof of maliciousness.';
  const list = document.getElementById('precautions'); list.replaceChildren(); (data.precautions || []).forEach(p => list.append(addText('li', '', p)));
}