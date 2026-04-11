# Deploying AI Bug Hunter to Fly.io

## Quick Deploy

### 1. Install Fly CLI
```bash
# macOS
brew install flyctl

# Linux
curl -L https://fly.io/install.sh | sh
```

### 2. Login to Fly
```bash
fly auth login
```

### 3. Deploy Marketing Site
```bash
# From project root
fly launch --dockerfile Dockerfile.marketing --name aibughunter-marketing

# Or manually
fly deploy --dockerfile Dockerfile.marketing
```

### 4. Set Environment Variables
```bash
# Optional: Stripe keys for payments
fly secrets set STRIPE_PUBLISHABLE_KEY=pk_test_...
fly secrets set STRIPE_SECRET_KEY=sk_test_...
```

### 5. Open Your Site
```bash
fly open
```

## Monetization Strategy

### Pricing Tiers
- **Quick Scan** - $9.99 (basic vulnerability scan)
- **Standard Scan** - $19.99 (recommended, full scan)
- **Aggressive Scan** - $49.99 (comprehensive with exploitation)

### Additional Revenue Streams
1. **Subscription Plans** - Monthly recurring scans
2. **Enterprise** - Custom deployments
3. **API Access** - Charge per API call
4. **Bug Bounty Cut** - % of successful bounties (future)

## Revenue Projections

| Metric | Conservative | Optimistic |
|--------|--------------|------------|
| Monthly Scans | 50 | 200 |
| Average Order | $20 | $30 |
| Monthly Revenue | $1,000 | $6,000 |
| Annual Revenue | $12,000 | $72,000 |

## Next Steps

1. ✅ Marketing site deployed
2. ⏳ Stripe integration for payments
3. ⏳ Automated scan fulfillment
4. ⏳ Email notifications
5. ⏳ User dashboard for scan history
6. ⏳ Subscription management

## Monitoring

```bash
# View logs
fly logs

# Check status
fly status

# Scale up
fly scale count 2
```
