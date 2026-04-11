# 🎯 AI Bug Hunter - SaaS Platform

**Live at:** https://aibughunter-marketing.fly.dev

## Features

### User Dashboard
- **Authentication** - Register/login with email and password
- **Dashboard** - Overview of scans, vulnerabilities, and remaining scans
- **Scan History** - Track all your scans with status updates
- **Report Downloads** - Download detailed reports for completed scans
- **Billing** - Upgrade plans and manage subscriptions

### Pricing Plans
| Plan | Price | Scans/Month | Features |
|------|-------|-------------|----------|
| **Free** | $0 | 1 | Basic scan, Markdown report |
| **Pro** | $49/mo | 10 | Full scan, HTML reports, AI analysis |
| **Enterprise** | $199/mo | Unlimited | All features, exploitation testing |

### Scan Types
| Type | Price | Pages | Turnaround |
|------|-------|-------|------------|
| Quick | $9.99 | 25 | 48 hours |
| Standard | $19.99 | 50 | 24 hours |
| Aggressive | $49.99 | 150 | 12 hours |

## API Reference

### Authentication
```bash
# Register
POST /api/auth/register
{ "email": "user@example.com", "password": "password123" }

# Login
POST /api/auth/login
{ "email": "user@example.com", "password": "password123" }
```

### Scans
```bash
# Request scan
POST /api/scans
Authorization: Bearer <token>
{ "target": "https://example.com", "scan_type": "standard" }

# List scans
GET /api/scans
Authorization: Bearer <token>

# Download report
GET /api/scans/{id}/report
Authorization: Bearer <token>
```

### Plans
```bash
# Get plans
GET /api/plans

# Upgrade plan
POST /api/plans/upgrade
Authorization: Bearer <token>
{ "plan": "pro" }
```

## Revenue Model

- **Pay-per-scan** - One-time payments for individual scans
- **Monthly subscriptions** - Recurring revenue from Pro/Enterprise plans
- **Enterprise deals** - Custom pricing for agencies
- **API access** - Charge per API call (future)

## Deploy to Fly.io

```bash
fly deploy --dockerfile Dockerfile.marketing --app aibughunter-marketing
```

## Local Development

```bash
# Run SaaS platform
python -m uvicorn aibughunter.web.saas_platform:app --reload --port 8080

# Open in browser
open http://localhost:8080
```

## Next Steps

1. ✅ User authentication
2. ✅ Scan request flow
3. ✅ Dashboard with scan history
4. ✅ Billing and plan management
5. ⏳ Stripe integration (live payments)
6. ⏳ Automated scan fulfillment
7. ⏳ Email notifications
8. ⏳ Team features
