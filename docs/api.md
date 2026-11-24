# API

Sunshine has a RESTful API which can be used to interact with the service.

Unless otherwise specified, authentication is required for all API calls. You can authenticate using
basic authentication with the admin username and password.

## CSRF Protection

State-changing API endpoints (POST, DELETE) are protected against Cross-Site Request Forgery (CSRF) attacks.

**For Web Browsers:**
- Requests whose `Origin` (or, without it, `Referer`) matches an allowed origin (`https://localhost`,
  `https://127.0.0.1`, `https://[::1]` on any port, plus `csrf_allowed_origins`) are allowed.
  This covers the Web UI opened through an SSH tunnel.
- All other requests require a CSRF token.

**For Non-Browser Applications:**
- Requests without an `Origin` or `Referer` header (as is typical for `curl` and scripts) **require a
  CSRF token**. A missing header does not prove that the request did not come from a browser.
- Get a token from `GET /api/csrf-token` (authenticated) and send it in the `X-CSRF-Token` header
  (or the `csrf_token` query parameter for compatibility). Tokens are valid for one hour and consist
  of 64 hexadecimal characters. Prefer the header so the token stays out of the request URL.

**Example:**
```bash
# Get CSRF token
curl -u user:pass https://localhost:47990/api/csrf-token

# Use token in request
curl -u user:pass -H "X-CSRF-Token: your_token_here" \
  -X POST https://localhost:47990/api/restart
```

@htmlonly
<script src="api.js"></script>
@endhtmlonly

## GET /api/csrf-token
@copydoc confighttp::getCSRFToken()

## GET /api/apps
@copydoc confighttp::getApps()

## POST /api/apps
@copydoc confighttp::saveApp()

## POST /api/apps/close
@copydoc confighttp::closeApp()

## DELETE /api/apps/{index}
@copydoc confighttp::deleteApp()

## GET /api/browse
@copydoc confighttp::browseDirectory()

## GET /api/clients/list
@copydoc confighttp::getClients()

## POST /api/clients/unpair
@copydoc confighttp::unpair()

## POST /api/clients/unpair-all
@copydoc confighttp::unpairAll()

## POST /api/clients/update
@copydoc confighttp::updateClient()

## GET /api/config
@copydoc confighttp::getConfig()

## GET /api/configLocale
@copydoc confighttp::getLocale()

## POST /api/config
@copydoc confighttp::saveConfig()

## GET /api/covers/{index}
@copydoc confighttp::getCover()

## POST /api/covers/upload
@copydoc confighttp::uploadCover()

## GET /api/logs
@copydoc confighttp::getLogs()

## POST /api/password
@copydoc confighttp::savePassword()

## POST /api/pin
@copydoc confighttp::savePin()

## POST /api/reset-display-device-persistence
@copydoc confighttp::resetDisplayDevicePersistence()

## POST /api/reset-portal-token
@copydoc confighttp::resetPortalToken()

## POST /api/restart
@copydoc confighttp::restart()

## GET /api/virtual-input/status
@copydoc confighttp::getVirtualInputStatus()
