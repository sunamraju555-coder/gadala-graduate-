# GSR Graduate Assistance & Management Portal

Runnable Flask + SQLite internal portal for WKN graduate enrolment assistance and field operations. It is **not** an official voter-registration platform and does not submit Form 18.

## Features
- Secure hashed-password login, role-based access, and geography-scoped data access
- Admin-created coordinator accounts (district, assembly, mandal, booth, viewer)
- Internal assistance record intake with explicit consent
- Status updates with audit events
- District/assembly/mandal/booth reporting and privacy-conscious CSV export
- Responsive dashboard

## Local installation (Python 3.10+)

```bash
cd gsr_full_portal
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

Set environment variables BEFORE first launch:

**Windows PowerShell**
```powershell
$env:SECRET_KEY = 'replace-with-a-long-random-secret'
$env:ADMIN_USERNAME = 'gsr_admin'
$env:ADMIN_PASSWORD = 'replace-with-a-unique-strong-password'
python app.py
```

**macOS/Linux**
```bash
export SECRET_KEY='replace-with-a-long-random-secret'
export ADMIN_USERNAME='gsr_admin'
export ADMIN_PASSWORD='replace-with-a-unique-strong-password'
python app.py
```

Open http://127.0.0.1:8000 and sign in with your chosen credentials. The SQLite database is created automatically.

## Important before any public deployment
This is an MVP, **not production-hardened**. Do not put real voter contact data online until you add HTTPS, a managed database, encrypted backups, MFA, login rate limiting/account lockouts, password reset and rotation, secrets management, privacy notice and retention policy, secure hosting, monitoring, disaster recovery, and an independent security review. Add validated official geography masters (34 assemblies, 156 mandals and booth data) rather than free-text fields. Protect access to personal records, implement consent withdrawal and deletion workflows, and comply with applicable Indian privacy and election requirements. Only the Election Commission's official process establishes electoral enrolment. No sample voter data is bundled.
