# AutoShield AI

AutoShield AI is a local-first cyber defense platform for web attack detection and response.

It supports:
- Real-time detection (SQLi, XSS, LFI, CMDi)
- Persistent storage (SQLite WAL)
- Auto-blocking and rate enforcement
- Threat scoring and IP reputation
- CVE/CERT intelligence enrichment
- SIEM/webhook integrations
- Streamlit SOC dashboard + FastAPI integration layer
- Nginx/Apache log agent ingestion

## Architecture

- `dashboard.py`: Streamlit Fusion Console UI
- `api_layer.py`: FastAPI service (modern endpoints + legacy compatibility endpoints)
- `db.py`: persistent database layer (events, users, rules, blocks, webhooks, sessions)
- `rule_engine.py`: DB/YAML rule engine with hot reload
- `scapy_engine.py`: packet/simulation detection engine (falls back gracefully when Scapy unavailable)
- `auto_block.py`: block manager (iptables or in-memory fallback)
- `threat_score.py`: threat profile scoring
- `webhook_manager.py`: Slack/Elastic/CEF/PagerDuty/Teams/etc payload delivery
- `nginx_agent.py`: access-log tailing and event forwarder
- `auth.py`: RBAC auth and session handling

## Quick Start

```bash
python -m pip install -r requirements.txt
python -m pip install --break-system-packages bcrypt pyyaml fastapi uvicorn
python -c "import db; db.init_db(); print('DB ready')"
streamlit run dashboard.py
python test_website/server.py
```

## API Run

```bash
python api_layer.py
```

FastAPI docs: `http://127.0.0.1:8502/docs`

Default demo API key in DB seed:
- `as_demo_key_change_in_production`

## Endpoints

Modern API:
- `POST /events`
- `POST /events/batch`
- `GET /events`
- `GET /stats`
- `GET /threats`
- `POST /block`
- `DELETE /block/{ip}`
- `GET /blocked`
- `GET /rules`
- `POST /rules`
- `PUT /rules/{rule_id}`
- `POST /webhooks`
- `GET /webhooks`
- `POST /scan`
- `GET /health`

Legacy compatibility API (for existing dashboard tools):
- `POST /log-event`
- `POST /block-ip`
- `GET /threat-score`

## Log Agent

```bash
python nginx_agent.py --log /var/log/nginx/access.log --api http://127.0.0.1:8502 --key as_demo_key_change_in_production
```

Replay mode:

```bash
python nginx_agent.py --log /var/log/nginx/access.log.1 --replay --api http://127.0.0.1:8502 --key as_demo_key_change_in_production
```

## Validation Commands

```bash
python -c "import db; db.init_db(); print('DB init OK')"
python -c "import auth, db; db.init_db(); auth.bootstrap_users(); print(auth.login('admin','admin123')[0])"
python -c "from rule_engine import get_rule_engine; print(get_rule_engine().rule_count())"
python -c "from webhook_manager import _build_slack; print('attachments' in _build_slack({'severity':'HIGH','attack_type':'SQLi','src_ip':'1.2.3.4','action':'BLOCKED','confidence':90,'cve_hints':['CVE-1'],'payload_snip':'x','timestamp':'2024-01-01T00:00:00'}))"
python -c "from nginx_agent import parse_line; print(parse_line('1.2.3.4 - - [01/Jan/2024:12:00:00 +0000] \"GET /x HTTP/1.1\" 200 1 \"-\" \"ua\"','nginx')['ip'])"
```

## Notes

- If Scapy import fails in a container/VM, the engine continues in simulation mode.
- Dashboard API controls are wired through `AutoShieldAPIServer` wrapper in `api_layer.py`.
- Replace demo credentials and demo API key before any real deployment.
