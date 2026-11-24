import { notifyKey } from './Notification.vue'

/**
 * The set of error messages that indicate a CSRF validation failure.
 */
const CSRF_ERRORS = new Set([
  'Missing CSRF token',
  'Invalid CSRF token',
  'CSRF token expired',
  'Origin not allowed',
])

/**
 * The subset of CSRF validation failures that can be recovered by refreshing
 * the cached CSRF token and retrying the request once.
 */
const RETRYABLE_CSRF_ERRORS = new Set([
  'Missing CSRF token',
  'Invalid CSRF token',
  'CSRF token expired',
])

/**
 * HTTP methods that mutate server state and require a CSRF token header.
 */
const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

/**
 * Cached CSRF token fetched from the backend API.
 * @type {string | null}
 */
let cachedCsrfToken = null

/**
 * In-flight CSRF token fetch promise used to coalesce concurrent callers.
 * @type {Promise<string | null> | null}
 */
let pendingCsrfTokenPromise = null

/**
 * Check whether the target URL points to the CSRF token endpoint itself.
 *
 * @param {string} url - Request URL.
 * @returns {boolean} True when targeting the CSRF token endpoint.
 */
function isCsrfTokenUrl(url) {
  const normalized = String(url ?? '').split('?')[0]
  return normalized === './api/csrf-token' || normalized === '/api/csrf-token'
}

/**
 * Fetch and cache a CSRF token from GET ./api/csrf-token.
 *
 * @param {boolean} [forceRefresh=false] - Bypass cached token and issue a fresh GET.
 * @returns {Promise<string | null>} CSRF token string, or null when unavailable.
 */
async function fetchCsrfToken(forceRefresh = false) {
  if (forceRefresh) {
    cachedCsrfToken = null
    pendingCsrfTokenPromise = null
  } else if (cachedCsrfToken) {
    return cachedCsrfToken
  }

  if (!pendingCsrfTokenPromise) {
    const requestPromise = (async () => {
      try {
        const tokenResponse = await fetch('./api/csrf-token', { method: 'GET' })
        const failed =
          !tokenResponse ||
          tokenResponse.ok === false ||
          (typeof tokenResponse.status === 'number' && tokenResponse.status >= 400)
        if (failed) {
          return null
        }

        const payload = await tokenResponse.json()
        const token = typeof payload?.csrf_token === 'string' ? payload.csrf_token : ''
        if (!token) {
          return null
        }
        cachedCsrfToken = token
        return token
      } catch (e) {
        console.debug('apiFetch: failed to fetch CSRF token', e)
        return null
      } finally {
        if (pendingCsrfTokenPromise === requestPromise) {
          pendingCsrfTokenPromise = null
        }
      }
    })()
    pendingCsrfTokenPromise = requestPromise
  }

  return pendingCsrfTokenPromise
}

/**
 * Attach X-CSRF-Token to fetch options without mutating the caller's object.
 *
 * @param {RequestInit | undefined} options - Original fetch options.
 * @param {string} token - CSRF token string.
 * @param {boolean} overwrite - Replace any caller-supplied X-CSRF-Token header.
 * @returns {RequestInit} Updated fetch options.
 */
function withCsrfTokenHeader(options, token, overwrite) {
  const rawHeaders = options?.headers
  if (rawHeaders instanceof Headers || Array.isArray(rawHeaders)) {
    const headers = new Headers(rawHeaders)
    if (overwrite || !headers.has('X-CSRF-Token')) {
      headers.set('X-CSRF-Token', token)
    }
    return { ...options, headers }
  }

  const headers = { ...(rawHeaders || {}) }
  const existingKey = Object.keys(headers).find((key) => key.toLowerCase() === 'x-csrf-token')
  if (overwrite && existingKey && existingKey !== 'X-CSRF-Token') {
    delete headers[existingKey]
  }
  if (overwrite || !existingKey) {
    headers['X-CSRF-Token'] = token
  }
  return { ...(options || {}), headers }
}

/**
 * Safely clone and parse a JSON response body when checking for CSRF errors.
 *
 * @param {Response} response - HTTP response object.
 * @returns {Promise<object | null>} Parsed JSON object or null.
 */
async function readJsonError(response) {
  try {
    return await response.clone().json()
  } catch (e) {
    console.debug('apiFetch: response body is not JSON', e)
    return null
  }
}

/**
 * Reset the in-memory CSRF token cache. Intended for unit tests.
 */
export function resetCsrfTokenCacheForTesting() {
  cachedCsrfToken = null
  pendingCsrfTokenPromise = null
}

/**
 * Wrapper around native fetch that automatically attaches X-CSRF-Token for
 * state-changing HTTP methods, refreshes and retries once when the server
 * rejects an invalid/expired token, and displays a notification on persistent
 * CSRF failures.
 *
 * @param {string} url - The URL to fetch.
 * @param {RequestInit} [options] - Standard fetch options.
 * @returns {Promise<Response>} The fetch Response.
 */
export async function apiFetch(url, options) {
  const method = String(options?.method || 'GET').toUpperCase()
  const needsCsrf = STATE_CHANGING_METHODS.has(method) && !isCsrfTokenUrl(url)

  let requestOptions = options
  if (needsCsrf) {
    const token = await fetchCsrfToken(false)
    if (token) {
      requestOptions = withCsrfTokenHeader(options, token, false)
    }
  }

  let response = await fetch(url, requestOptions)

  if (response && response.status === 400) {
    let body = await readJsonError(response)
    if (needsCsrf && body && RETRYABLE_CSRF_ERRORS.has(body.error)) {
      const refreshedToken = await fetchCsrfToken(true)
      if (refreshedToken) {
        response = await fetch(url, withCsrfTokenHeader(options, refreshedToken, true))
        body = response && response.status === 400 ? await readJsonError(response) : null
      }
    }

    if (response && response.status === 400 && body && CSRF_ERRORS.has(body.error)) {
      notifyKey.error('_common.csrf_error_desc', '_common.csrf_error')
    }
  }

  return response
}
