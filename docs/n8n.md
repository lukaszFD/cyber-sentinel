# Automated Domain & IP Reputation Guard (n8n Workflow)

Officially verified and published in the **n8n Workflow Library**.
Check it out here: [Score DNS Threats with VirusTotal, Abuse.ch, HashiCorp Vault, and Gemini](https://n8n.io/workflows/14127-score-dns-threats-with-virustotal-abusech-hashicorp-vault-and-gemini/)

## Overview

This workflow is a core component of the **Cyber Sentinel** platform.
It automates threat intelligence enrichment, analysis, and alerting for IP addresses and domain names observed in DNS traffic.

The pipeline integrates:

* Multi-source CTI (VirusTotal, ThreatFox, URLHaus)
* Secure secret management (HashiCorp Vault)
* AI-based decision engine (Google Gemini)
* Dual persistence (MongoDB + MySQL)

---

## 1. Workflow Trigger & Initialization

### Components

* Schedule Trigger
* HashiCorp Vault (MySQL, MongoDB credentials)

### Description

The workflow executes every **15 minutes**, ensuring continuous monitoring of infrastructure.

```json title="schedule-trigger.json" linenums="1"
{
  "rule": {
    "interval": [
      {
        "field": "minutes",
        "minutesInterval": 15
      }
    ]
  }
}
```

---

## 2. Secure Secrets Management

### Components

* HashiCorp Vault Nodes:

    * MySQL credentials
    * MongoDB credentials
    * API tokens (VirusTotal, Abuse.ch, Gemini)
    * Email credentials

### Description

All sensitive data is dynamically retrieved from Vault, implementing a **Zero Trust Secrets Model**.

```json title="vault-secret.json" linenums="1"
{
  "secretPath": "cyber-sentinel/api-keys/virustotal",
  "secretPath": "cyber-sentinel/api-keys/gemini/home-network-guardian",
  "secretPath": "cyber-sentinel/credentials/mysql/app_manager",
  "secretPath": "cyber-sentinel/api-keys/abuse/api-key",
  "secretPath": "cyber-sentinel/credentials/gmail"
}
```

---

## 3. Data Source (MySQL)

### Component

* Select rows from a table

### Description

The workflow retrieves observables (IP/FQDN) from:

```sql title="view.sql" linenums="1"
SELECT 
    dns_query_id,
    source_ip,
    fqdn,
    observable_ip,
    first_seen
FROM cyber_intelligence.v_pending_analysis
LIMIT 1;
```

This view acts as a queue of entities awaiting analysis.

---

## 4. Threat Intelligence Enrichment

### Components

* VirusTotal API
* Abuse.ch ThreatFox
* Abuse.ch URLHaus

### Description

Each observable is enriched using multiple CTI providers to ensure high-confidence detection.

---

### 4.1 VirusTotal Scan

```js title="virustotal-request.js" linenums="1"
const url = `https://www.virustotal.com/api/v3/ip_addresses/${observable_ip}`;
```

---

### 4.2 ThreatFox Request

```json title="threatfox-request.json" linenums="1"
{
  "method": "POST",
  "url": "https://threatfox-api.abuse.ch/api/v1/",
  "authentication": "genericCredentialType",
  "genericAuthType": "httpHeaderAuth",
  "sendBody": true,
  "bodyParameters": {
    "parameters": [
      {
        "name": "query",
        "value": "search_ioc"
      },
      {
        "name": "search_term",
        "value": "={{ $('Select rows from a table').item.json.fqdn }}"
      },
      {
        "name": "exact_match",
        "value": "true"
      }
    ]
  },
  "options": {}
}
```

---

### 4.3 URLHaus Request

```json title="urlhaus-request.json" linenums="1"
{
  "method": "POST",
  "url": "https://urlhaus-api.abuse.ch/v1/host/",
  "authentication": "genericCredentialType",
  "genericAuthType": "httpHeaderAuth",
  "sendBody": true,
  "contentType": "form-urlencoded",
  "bodyParameters": {
    "parameters": [
      {
        "name": "host",
        "value": "={{ $('Select rows from a table').item.json.fqdn }}"
      }
    ]
  },
  "options": {}
}
```

---

## 5. Conditional Flow Control

### Components

* IF node — VirusTotal (`malicious > 0 OR suspicious > 0`)
* IF node — ThreatFox (`query_status = ok`)
* IF node — URLHaus (`query_status = ok`)

### Description

Each CTI provider uses a dedicated IF node with a different condition, because each API returns data in a different format.

**VirusTotal** — evaluates raw `last_analysis_stats` fields directly:

```json title="if-virustotal.json" linenums="1"
{
  "combinator": "or",
  "conditions": [
    { "leftValue": "={{ $json.data.attributes.last_analysis_stats.malicious }}", "operator": "gt", "rightValue": 0 },
    { "leftValue": "={{ $json.data.attributes.last_analysis_stats.suspicious }}", "operator": "gt", "rightValue": 0 }
  ]
}
```

**ThreatFox & URLHaus** — evaluate the `query_status` field returned by the Abuse.ch API:

```json title="if-abusech.json" linenums="1"
{
  "conditions": [
    { "leftValue": "={{ $json.query_status }}", "operator": "equals", "rightValue": "ok" }
  ]
}
```

If the condition is **false**, the workflow branches to an `Insert a clear scan` MySQL node, which registers a baseline score of `1` (Safe) for that provider. This prevents redundant API calls on already-clean observables and maintains full relational integrity.

---

## 6. Raw Data Storage (MongoDB)

### Components

* MongoDB nodes (`Insert doc VirusTotal`, `Insert doc ThreatFox`, `Insert doc URLHaus`)
* Transformation Code nodes (`Edit Json for Mongo - *`)
* MySQL nodes (`Insert a clear scan - VirusTotal`, `Insert a clear scan - ThreatFox`, `Insert a clear scan - URLHaus`)

### Description

The storage layer has two parallel paths depending on the IF node result.

**Path A — Data found:** Raw API response is transformed and archived in MongoDB, then the enriched result proceeds to the normalization layer.

**Path B — No data (clean result):** A baseline scan record with `threat_score = 1` is written directly to MySQL. This short-circuits the full AI pipeline and prevents redundant API calls for already-clean observables.

All MongoDB documents are inserted into:

```
collection: threat_data_raw
```

Used for:

* forensic analysis
* audit trail
* reprocessing

---

### 6.1 Example Transformation

```js title="mongo-transform.js" linenums="1"
// Prepare structured document for MongoDB
return {
  resource: $('Select rows from a table').first().json.observable_ip,
  type: 'IP',
  source_provider: 'VirusTotal',
  scan_date: new Date().toISOString(),
  raw_data: $('VirusTotal IP Scan').item.json
};
```

---

### 6.2 Clean Scan — MySQL Fallback

When a provider returns no data, a safe baseline is written immediately:

```sql title="insert-clean-scan.sql" linenums="1"
-- Register a safe baseline verdict (score = 1) for referential integrity
INSERT INTO cyber_intelligence.ai_analysis_results (
    threat_score, verdict_summary_en, analysis_pl
) VALUES (1, null, null);

SET @last_clean_result_id = LAST_INSERT_ID();

-- Log the scan event in threat_indicators
INSERT INTO cyber_intelligence.threat_indicators (
    dns_query_id, type_id, analysis_result_id, last_scan
) VALUES (
    {{ $('Select rows from a table').item.json.dns_query_id }},
    (SELECT id FROM cyber_intelligence.dic_indicator_types WHERE name = 'IP'),
    @last_clean_result_id,
    NOW()
);
```

---

## 7. Data Normalization Layer

### Components

* Code nodes (per provider): `Data reduction and aggregation - VirusTotal / ThreatFox / Urlhaus`
* Merge node
* Aggregation node (`Code for Merge`)

### Description

Each provider response is reduced into a compact, structured object before being passed to the AI. Raw API payloads are large — normalization extracts only the fields relevant for threat scoring.

**VirusTotal** extracts:

| Field | Description |
|---|---|
| `vt_report` | Human-readable summary string |
| `vt_stats` | Raw counts: `malicious`, `suspicious`, `undetected` |
| `vt_owner` | AS owner name (e.g. `Google LLC`) |
| `vt_is_big_player` | `true` if owner matches known trusted providers |
| `vt_malicious_count` | Number of malicious engine detections |
| `vt_scan_date` | Freshness of the data |
| `no_data` | `true` if VirusTotal has no record for this resource |

**ThreatFox** extracts:

| Field | Description |
|---|---|
| `threatfox_report` | Identified malware families and threat types |
| `threatfox_active` | `true` if an actively confirmed threat exists |
| `threatfox_max_confidence` | Reliability score of the report |
| `no_data` | `true` if ThreatFox has no record |

**URLHaus** extracts:

| Field | Description |
|---|---|
| `urlhaus_report` | Details on active malware distribution |
| `is_active_threat` | `true` if payload URL is currently online |
| `urlhaus_reference` | Direct evidence link |
| `no_data` | `true` if URLHaus has no record |

---

### 7.1 Aggregation Logic

All three normalized objects are merged into a single context object for the AI prompt:

```js title="merge.js" linenums="1"
// Merge all CTI sources into one object
let combinedData = {};

for (const item of $input.all()) {
  Object.assign(combinedData, item.json);
}

return combinedData;
```

---

## 8. AI Threat Analysis

### Components

* AI Agent
* Google Gemini Model

### Description

The AI layer acts as a **Senior Cyber Threat Intelligence Analyst**.

Responsibilities:

* Correlate multiple CTI sources
* Apply scoring model (1–10)
* Detect malware patterns
* Reduce false positives (e.g. big cloud providers)
* Generate bilingual output (EN + PL)

---

### Prompt Structure

```txt title="ai-prompt.txt" linenums="1"
ROLE:
You are a Senior Cyber Threat Intelligence Analyst in the Cyber Sentinel system. Your task is to evaluate an artifact based on aggregated data from VirusTotal, ThreatFox, and Urlhaus, and return a structured analysis.

CONTEXT & SCORING POLICY:
Assign exactly one threat score from the following scale:
SCORE | DESCRIPTION | IS_MALICIOUS | CRITERIA
1 | Safe / Clean | FALSE | 0 detections; known trusted services (Google, MS, GitHub).
2 | Low Risk | FALSE | 1 detection (minor engine); no other evidence.
3 | Informational | FALSE | Cloud/CDN IPs without active malware.
4 | Unverified | FALSE | New domain, no history, no detections.
5 | Suspicious | FALSE | Heuristics, bad reputation hosting, low confidence.
6 | Likely Malicious | TRUE | 3-5 detections or grey-list presence.
7 | Malicious | TRUE | Confirmed by at least 1 reputable engine or CTI report.
8 | High Risk | TRUE | Critical detections, confirmed malware family (e.g., RAT).
9 | Confirmed Malware | TRUE | Active malware hosting confirmed by Urlhaus.
10 | Critical Threat | TRUE | Active C2 server confirmed by ThreatFox/Triage.

DATA SOURCE PRE-ANALYSIS:
Before finalizing the score, you must analyze every variable returned by the source nodes:

IMPORTANT: You will receive multiple threat intelligence reports in a single data object. You must synthesize ALL provided reports into ONE single evaluation. Do not generate separate outputs for each source.

Data : {{ JSON.stringify($('Code for Merge').item.json) }} 

1. VirusTotal Section ("virustotal"):
   - If "no_data" is true, skip this source.
   - Use "vt_report" for the textual summary.
   - Analyze "vt_stats" (malicious/suspicious/undetected counts) and "vt_malicious_count" for raw detection levels.
   - Check "vt_owner" and "vt_is_big_player" to identify if the infrastructure belongs to a trusted provider like Google or Microsoft.
   - Reference "vt_scan_date" to determine the freshness of the data.

2. ThreatFox Section ("threatfox"):
   - If "no_data" is true, skip this source.
   - Use "threatfox_report" for identified malware families and threat types.
   - "threatfox_active" (boolean): If true, this indicates an actively confirmed threat.
   - "threatfox_max_confidence": Use this to gauge the reliability of the report.

3. Urlhaus Section ("urlhaus"):
   - If "no_data" is true, skip this source.
   - Use "urlhaus_report" for details on active malware distribution.
   - "is_active_threat" (boolean): If true, the payload URL is currently online and dangerous.
   - "urlhaus_reference": Use this for providing direct evidence links.

DATA AVAILABILITY RULES:
1. Each source (virustotal, threatfox, urlhaus) contains a "no_data" flag.
2. If "no_data" is true, it means the artifact is not present in that database. Treat this as a clean result for that specific source.
3. If all sources report "no_data": true, set threat_score to 1 (if it's a known big player) or 4 (if entirely unknown).

ANALYSIS RULES:
1. Cross-Check: If ThreatFox or Urlhaus confirm active threats (threatfox_active: true or is_active_threat: true), the threat_score MUST be >= 8, regardless of low VirusTotal detections.
2. Big Player Exception: If vt_is_big_player is true, exercise caution with low detection counts (<3) to avoid False Positives.
3. Flagging: is_malicious MUST be true only if threat_score >= 6.
4. Attribution: Identify the infrastructure owner using vt_owner and specify malware families (e.g., ValleyRAT) if present in threatfox or urlhaus reports.

STRICT JSON FORMATTING RULE:
1. All string values (verdict_en, analysis_pl) MUST be single-line strings. NEVER use physical line breaks (\n) inside string values.
2. SQL ESCAPING: To prevent SQL syntax errors, you MUST replace every single quote (') found within the text with two single quotes (''). For example: 'malware' becomes ''malware''.
3. Avoid using any special characters like backslashes (\) or backticks (`) that could break JSON or SQL parsing.

REQUIRED OUTPUT (STRICT JSON ONLY):
{
  "threat_score": [number 1-10],
  "is_malicious": [boolean],
  "threat_label": "[Phishing / Botnet / C2 / Clean / Suspicious / Malware]",
  "verdict_en": "[Technical summary for threat_indicators table - max 200 chars]",
  "analysis_pl": "[Komentarz w jezyku Polskim dla Łukasza: 1. Właściciel IP/Hostingu. 2. Typ zagrożenia i wykryte rodziny malware. 3. Rekomendacja (Blokować/Monitorować/Zignorować)]",
  "active_providers": ["virustotal", "threatfox", "urlhaus"]
}
```

---

## 9. AI Output Parsing

### Component

* Code node

### Description

Cleans LLM output and converts it into valid JSON.

---

### Example

````js title="parse-ai.js" linenums="1"
// Retrieve the raw output from the AI node
let rawText = $json.output;

// Clean the markdown formatting and newlines from the AI output
let cleanJson = rawText.replace(/```json\n|```/g, "").trim();
cleanJson = cleanJson.replace(/[\r\n]+/g, " ");

try {
  // Parse the cleaned JSON string into a structured object
  const data = JSON.parse(cleanJson);
  const providerDetails = [];

  // Helper function to retrieve Mongo IDs from previous transformation nodes
  const getMongoId = (nodeName, providerKey) => {
    try {
      // Access all data items from the specified node to ensure comprehensive search
      const nodeData = $(nodeName).all(); 
      
      // Iterate through all entries to find the one containing the provider key and mongo_id
      for (const entry of nodeData) {
        if (entry.json && entry.json[providerKey] && entry.json[providerKey].mongo_id) {
          return entry.json[providerKey].mongo_id;
        }
      }
    } catch (e) {
      // Return null if the node or the specific key is inaccessible
      return null;
    }
    return null;
  };

  // Map active providers to their respective MongoDB IDs for the final report
  if (data.active_providers.includes("virustotal")) {
    const vt_id = getMongoId('Data reduction and aggregation - VirusTotal', 'virustotal');
    if (vt_id) providerDetails.push({ name: "VirusTotal", mongo_id: vt_id });
  }

  if (data.active_providers.includes("threatfox")) {
    const tf_id = getMongoId('Data reduction and aggregation - ThreatFox', 'threatfox');
    if (tf_id) providerDetails.push({ name: "Abuse_ThreatFox", mongo_id: tf_id });
  }

  if (data.active_providers.includes("urlhaus")) {
    const uh_id = getMongoId('Data reduction and aggregation - Urlhaus', 'urlhaus');
    if (uh_id) providerDetails.push({ name: "Abuse_URLhaus", mongo_id: uh_id });
  }

  // Return the final structured object for database persistence and alerting
  return {
    score: data.threat_score,
    verdict_en: data.verdict_en,
    analysis_pl: data.analysis_pl,
    provider_details: providerDetails
  };

} catch (error) {
  // Handle parsing errors if the AI output is malformed or not valid JSON
  return { 
    error: "Parsing failed", 
    details: error.message, 
    raw_received: rawText 
  };
}
````

---

## 10. Relational Database Storage (MySQL)

### Components

* Insert AI verdict
* Insert threat indicators
* Insert provider details

### Description

Final structured intelligence is stored in relational tables:

* `ai_analysis_results`
* `threat_indicators`
* `threat_indicator_details`

Every AI decision is linked back to the original DNS query and raw provider data via MongoDB Object IDs, creating a complete audit trail.

---

### Example

```sql title="insert-verdict.sql" linenums="1"
-- STEP 1: Insert the unique AI verdict into the results table
INSERT INTO cyber_intelligence.ai_analysis_results (
    threat_score, 
    verdict_summary_en, 
    analysis_pl
) VALUES (
    {{ $json.score }},
    '{{ $json.verdict_en }}',
    '{{ $json.analysis_pl }}'
);

-- Store the generated verdict ID for the next steps
SET @last_result_id = LAST_INSERT_ID();

-- STEP 2: Insert the event record into the threat_indicators table
INSERT INTO cyber_intelligence.threat_indicators (
    dns_query_id,
    type_id,
    analysis_result_id,
    last_scan
) VALUES (
    {{ $('Select rows from a table').item.json.dns_query_id }}, 
    (SELECT id FROM cyber_intelligence.dic_indicator_types WHERE name = 'IP'),
    @last_result_id,
    NOW()
);

-- Store the event ID to link with specific scanner details
SET @last_event_id = LAST_INSERT_ID();

-- STEP 3: Dynamically insert scanner details (VirusTotal, ThreatFox, etc.)
{{ $json.provider_details.map(p => `
INSERT INTO cyber_intelligence.threat_indicator_details (indicator_id, source_id, mongo_ref_id)
SELECT @last_event_id, id, '${p.mongo_id}' 
FROM cyber_intelligence.dic_source_providers WHERE name = '${p.name}';
`).join('\n') }}

-- Return the event ID for subsequent steps (e.g., email notification)
SELECT @last_event_id AS indicator_id;
```

---

## 11. Alerting & Notification

### Components

* Filter node (score > 5)
* Email node

### Description

Alerts are triggered only for meaningful threats.

---

### Condition

```js title="filter.js" linenums="1"
// Trigger alert only for medium/high threats
return $json.score > 5;
```

---

### Email Template

=== "Preview"
<div style="border: 1px solid #333; border-radius: 8px; overflow: hidden;">
<div style="font-family: 'Segoe UI', Tahoma, sans-serif; background-color: #121212; color: #e0e0e0; padding: 20px;">
<div style="max-width: 600px; margin: auto; background: #1e1e1e; border: 1px solid #333; border-radius: 8px; border-top: 4px solid #f44336;">
<div style="background: #263238; padding: 15px; text-align: center;">
<h2 style="margin:0; color: #ff5252;">🚨 ALARM: Cyber Sentinel</h2>
</div>
<div style="padding: 25px;">
<div style="background: #2d2d2d; border-radius: 5px; padding: 10px; text-align: center; margin-bottom: 20px; border: 1px solid #444;">
<div style="font-size: 12px; color: #888;">Threat Severity Score</div>
<div style="font-size: 36px; font-weight: bold; color: #ff5252;">8/10</div>
</div>
<p><strong>IP Object:</strong> <span style="color: #64ffda;">192.168.1.105</span></p>
<div style="background: #252525; padding: 15px; border-left: 4px solid #90caf9;">
<strong style="color: #90caf9;">Analysis (PL):</strong><br>
Wykryto podejrzany ruch wychodzący do znanej infrastruktury C&C.
</div>
</div>
</div>
</div>
</div>


```html title="alert.html" linenums="1"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 20px; }
        .card { max-width: 600px; margin: auto; background: #1e1e1e; border: 1px solid #333; border-radius: 8px; overflow: hidden; border-top: 4px solid #f44336; }
        .header { background: #263238; padding: 15px; text-align: center; }
        .content { padding: 25px; }
        .score-box { background: #2d2d2d; border-radius: 5px; padding: 10px; text-align: center; margin-bottom: 20px; border: 1px solid #444; }
        .ip-addr { font-family: 'Courier New', monospace; color: #64ffda; font-size: 18px; font-weight: bold; }
        .analysis { background: #252525; padding: 15px; border-radius: 4px; border-left: 4px solid #90caf9; font-size: 14px; line-height: 1.6; margin-top: 15px; }
        .provider-tag { display: inline-block; background: #37474f; color: #cfd8dc; padding: 2px 8px; border-radius: 3px; font-size: 11px; margin-right: 5px; border: 1px solid #546e7a; }
        .btn { display: inline-block; padding: 10px 20px; background-color: #f44336; color: white; text-decoration: none; border-radius: 4px; font-weight: bold; margin-top: 20px; font-size: 14px; }
        .footer { text-align: center; font-size: 11px; color: #777; padding: 15px; }
    </style>
</head>
<body>
<div class="card">
    <div class="header">
        <h2 style="margin:0; color: #ff5252;">🚨 ALARM: Cyber Sentinel</h2>
    </div>
    <div class="content">
        <div class="score-box">
            <div style="font-size: 12px; text-transform: uppercase; color: #888; letter-spacing: 1px;">Threat Severity Score</div>
            <div style="font-size: 36px; font-weight: bold; color: #ff5252;">{{ $node["Parse AI Agent output"].json.score }}/10</div>
        </div>

        <p><strong>Obiekt (IP):</strong> <span class="ip-addr">{{ $('Select rows from a table').item.json.observable_ip }}</span></p>
        <p><strong>Powiązana domena:</strong> <span style="color: #90caf9;">{{ $('Select rows from a table').item.json.fqdn }}</span></p>

        <div style="margin-top: 10px;">
            <strong style="font-size: 13px; color: #888;">Aktywne źródła danych:</strong><br>
            {{ $node["Parse AI Agent output"].json.provider_details.map(p => `<span class="provider-tag">${p.name}</span>`).join('') }}
        </div>

        <div class="analysis">
            <strong style="color: #90caf9;">Analiza (PL):</strong><br>
            <div style="margin-top: 5px;">
                {{ $node["Parse AI Agent output"].json.analysis_pl }}
            </div>
        </div>

        <p style="color: #bbb; font-style: italic; font-size: 12px; margin-top: 15px; border-top: 1px solid #333; padding-top: 10px;">
            <strong>Technical Verdict:</strong> {{ $node["Parse AI Agent output"].json.verdict_en }}
        </p>

        <div style="text-align: center;">
            <a href="https://rdap.arin.net/registry/ip/{{ $('Select rows from a table').item.json.observable_ip }}" class="btn">Sprawdź detale IP (RDAP)</a>
        </div>
    </div>
    <div class="footer">
        System: <strong>Cyber Sentinel v1.0</strong><br>
        Data: {{ new Date().toLocaleString('pl-PL') }}
    </div>
</div>
</body>
</html>
```

---

## 12. Architecture Patterns

### Dual Storage Strategy

* MongoDB → raw intelligence (forensics)
* MySQL → structured data (operations)

### Zero Trust Secrets

* All secrets from Vault
* No hardcoded credentials

### Multi-Source Correlation

* VirusTotal + ThreatFox + URLHaus

### AI Decision Engine

* Central intelligence layer
* Context-aware scoring

---

## 13. End-to-End Flow

1. Schedule trigger starts workflow
2. Fetch observable from MySQL
3. Enrich using CTI providers
4. Store raw responses in MongoDB
5. Normalize and merge data
6. Perform AI analysis
7. Store results in MySQL
8. Send alert if threat score > 5

---

## 14. Practical Use Cases

* SOC automation pipelines
* Home network threat monitoring
* Threat intelligence enrichment (SIEM/SOAR)
* Malware infrastructure detection
* Automated incident triage

---