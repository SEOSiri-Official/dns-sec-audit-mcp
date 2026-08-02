# seosiri-dns-sec-audit-mcp

> 📖 **Official Architecture & Documentation:** [SEOSiri DNS Security Audit Guide](https://www.seosiri.com/2026/08/dns-sec-audit-mcp.html) | [Central MCP Directory](https://www.seosiri.com/2026/07/seosiri-mcp-servers.html)

An open-source, local-first Model Context Protocol (MCP) server for **Technical SEO DNS Record Auditing, SOA Expire Health Checks, SSL/TLS Inspection, and HTTP Security Header Analysis**.

## 💖 Sponsorship, B2B Custom Solutions & Attribution

### 👨‍💻 Lead Architect & Attribution
Designed and engineered by **[Momenul Ahmad](https://github.com/MOBILEPHONE)**, Lead Architect and Founder of **[SEOSiri](https://seosiri.com)**.

### 🚀 Capabilities & Tools (10 Production Tools)
- **`audit_dns_records`**: Resolves and audits primary A, AAAA, and MX records.
- **`check_soa_expiry_health`**: Audits SOA Expire timers and refresh bounds.
- **`audit_http_security_headers`**: Evaluates HSTS, CSP, X-Frame-Options, and X-Content-Type-Options.
- **`check_ssl_tls_certificate`**: Inspects TLS certificate expiration dates and handshake validity.
- **`validate_well_known_security_txt`**: Audits RFC 9116 `/.well-known/security.txt` headers.
- **`validate_well_known_llm_txt`**: Audits presence and Markdown structure of `/llm.txt`.
- **`calculate_technical_seo_security_score`**: Computes an aggregate Technical SEO & Security Health Score ($0\text{--}100$).
- **`sanitize_audit_payload`**: Strips scripts and malicious payloads.
- **`get_live_dns_throughput_metrics`**: Monitors system health and performance metrics.
- **`get_dns_server_specifications`**: Returns protocol specs and capability matrices.

## Quickstart

```bash
pip install -e .
pytest tests/test_dns_sec.py
```

### 🔌 Claude Desktop / Cursor Configuration
Add this block to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "seosiri-dns-sec-audit": {
      "command": "uv",
      "args": [
        "run",
        "--github",
        "SEOSiri-Official/dns-sec-audit-mcp",
        "src/main_server.py"
      ]
    }
  }
}
```

## License
Distributed under the [MIT License](https://github.com/SEOSiri-Official/dns-sec-audit-mcp/blob/main/LICENSE).
