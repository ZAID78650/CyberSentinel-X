#!/bin/bash
# CyberSentinel X — Custom Domain Setup Helper
# Run this after configuring your custom domain on Render + DNS.
#
# Usage:
#   ./scripts/setup-custom-domain.sh your-domain.com
#
# Example:
#   ./scripts/setup-custom-domain.sh www.cybersentinel.io

set -e

DOMAIN="${1:?Usage: $0 <domain>}"
FRONTEND_URL="https://${DOMAIN}"
BACKEND_URL="https://cybersentinel-backend-t5pv.onrender.com"

echo "╔═══════════════════════════════════════════════════╗"
echo "  CyberSentinel X — Custom Domain Setup"
echo "╠═══════════════════════════════════════════════════╣"
echo "  Domain:    ${DOMAIN}"
echo "  Frontend:  ${FRONTEND_URL}"
echo "  Backend:   ${BACKEND_URL}"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# 1. Update render.yaml CORS and URLs
echo "📝 Updating render.yaml..."
sed -i.bak "s|value: https://cybersentinel-frontend.onrender.com|value: ${FRONTEND_URL}|g" render.yaml
rm -f render.yaml.bak

# 2. Update frontend index.html meta tags
echo "📝 Updating frontend/index.html..."
sed -i.bak \
  -e "s|https://cybersentinel-frontend.onrender.com|${DOMAIN}|g" \
  -e "s|https://cybersentinel-backend-t5pv.onrender.com|${DOMAIN}|g" \
  frontend/index.html
rm -f frontend/index.html.bak

# 3. Update frontend .env.production
echo "📝 Updating frontend/.env.production..."
cat > frontend/.env.production << EOF
VITE_API_BASE=/api
VITE_WS_BASE=ws
EOF

echo ""
echo "✅ Config updated. Next steps:"
echo ""
echo "  1. Update Render dashboard env vars:"
echo "     Backend → CORS_ORIGINS: ${FRONTEND_URL}"
echo "     Backend → FRONTEND_URL: ${FRONTEND_URL}"
echo "     Backend → BACKEND_URL:  ${FRONTEND_URL}"
echo ""
echo "  2. Update OAuth redirect URIs:"
echo "     Google: ${FRONTEND_URL}/api/auth/oauth/google/callback"
echo "     GitHub: ${FRONTEND_URL}/api/auth/oauth/github/callback"
echo ""
echo "  3. Commit and push:"
echo "     git add -A && git commit -m 'Configure custom domain: ${DOMAIN}' && git push"
echo ""
echo "  4. Verify DNS on Render dashboard"
echo ""
