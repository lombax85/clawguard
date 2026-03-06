import { ServiceConfig } from './types';

/**
 * For oauth2_client_credentials services, checks if the request targets
 * the token endpoint and rewrites client_id / client_secret in the body.
 *
 * Returns the (possibly rewritten) body buffer and whether auth headers
 * should be skipped (for oauth2, the script manages Bearer tokens itself).
 */
export function rewriteRequestAuth(
  serviceConfig: ServiceConfig,
  method: string,
  requestPath: string,
  body: Buffer,
  headers: Record<string, string>
): { body: Buffer; headers: Record<string, string>; skipAuthInjection: boolean } {
  if (serviceConfig.auth.type !== 'oauth2_client_credentials') {
    return { body, headers, skipAuthInjection: false };
  }

  const tokenPath = serviceConfig.auth.tokenPath || '/token';

  // Strip query string for path matching
  const pathOnly = requestPath.split('?')[0];

  // Non-token requests: pass through as-is (script already has its Bearer token)
  if (method.toUpperCase() !== 'POST' || !pathOnly.endsWith(tokenPath)) {
    return { body, headers, skipAuthInjection: true };
  }

  // Token endpoint: rewrite client_id and client_secret in the body
  const realClientId = serviceConfig.auth.clientId || '';
  const realClientSecret = serviceConfig.auth.clientSecret || '';

  if (!realClientId || !realClientSecret) {
    console.warn('⚠ oauth2_client_credentials: missing clientId or clientSecret in config');
    return { body, headers, skipAuthInjection: true };
  }

  const contentType = (headers['content-type'] || '').toLowerCase();

  if (contentType.includes('application/x-www-form-urlencoded')) {
    const params = new URLSearchParams(body.toString('utf-8'));
    params.set('client_id', realClientId);
    params.set('client_secret', realClientSecret);
    const newBody = Buffer.from(params.toString(), 'utf-8');

    // Update content-length
    const newHeaders = { ...headers };
    newHeaders['content-length'] = String(newBody.length);

    return { body: newBody, headers: newHeaders, skipAuthInjection: true };
  }

  if (contentType.includes('application/json')) {
    try {
      const json = JSON.parse(body.toString('utf-8'));
      json.client_id = realClientId;
      json.client_secret = realClientSecret;
      const newBody = Buffer.from(JSON.stringify(json), 'utf-8');

      const newHeaders = { ...headers };
      newHeaders['content-length'] = String(newBody.length);

      return { body: newBody, headers: newHeaders, skipAuthInjection: true };
    } catch {
      // Can't parse JSON, pass through
      return { body, headers, skipAuthInjection: true };
    }
  }

  // Unknown content type, pass through
  return { body, headers, skipAuthInjection: true };
}
