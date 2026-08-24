import path from 'path';
import { randomUUID } from 'crypto';
import {
  resolveServiceConfigSecrets,
  validateFtpConfiguration,
  validateHttpConfiguration,
  validateSshConfiguration,
} from './config';
import {
  isAllowedUpstream,
  validateFtpService,
  validateFtpTargetRuntime,
  validateSshService,
  validateSshTargetRuntime,
  validateUpstreamUrl,
} from './security';
import { Config, ServiceConfig } from './types';
import { loadPlugin, unloadPlugin } from './auth-plugins/loader';
import {
  getSshCredentialPlugin,
  loadSshCredentialPlugin,
  unloadSshCredentialPlugin,
} from './ssh-credential-plugins/loader';
import {
  getFtpCredentialPlugin,
  loadFtpCredentialPlugin,
  unloadFtpCredentialPlugin,
} from './ftp-credential-plugins/loader';

const SECRET_MARKER_KEY = '$clawguard';
const SECRET_MARKER_VALUE = 'keep-secret';

type JsonObject = Record<string, unknown>;

export interface AdminServiceRuntime {
  apply(name: string, service: ServiceConfig): Promise<ServiceConfig>;
  remove(name: string): void;
}

function isPlainObject(value: unknown): value is JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function cloneJson<T>(value: T): T {
  return structuredClone(value);
}

function secretMarker(): JsonObject {
  return { [SECRET_MARKER_KEY]: SECRET_MARKER_VALUE };
}

function isSecretMarker(value: unknown): boolean {
  return isPlainObject(value)
    && Object.keys(value).length === 1
    && value[SECRET_MARKER_KEY] === SECRET_MARKER_VALUE;
}

function redactEveryLeaf(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactEveryLeaf);
  if (isPlainObject(value)) {
    const result: JsonObject = {};
    for (const [key, item] of Object.entries(value)) result[key] = redactEveryLeaf(item);
    return result;
  }
  return secretMarker();
}

/**
 * Return a complete, editable service document without returning credentials.
 * Secret markers are resolved only by the server against the current service
 * (edit) or source service (duplicate).
 */
export function redactServiceForAdmin(service: ServiceConfig): ServiceConfig {
  const result = cloneJson(service) as ServiceConfig;
  const auth = result.auth as unknown as JsonObject;
  for (const key of ['token', 'dummyToken', 'password', 'clientSecret']) {
    if (auth[key] !== undefined) auth[key] = secretMarker();
  }
  if (auth['fields'] !== undefined) auth['fields'] = redactEveryLeaf(auth['fields']);
  if (auth['pluginConfig'] !== undefined) {
    // Plugin schemas are extensible, so no pluginConfig value is assumed safe
    // to expose. Its complete shape remains editable and cloneable.
    auth['pluginConfig'] = redactEveryLeaf(auth['pluginConfig']);
  }
  return result;
}

function resolveSecretMarkers(value: unknown, source: unknown, location: string): unknown {
  if (isSecretMarker(value)) {
    if (source === undefined) {
      throw new Error(`Secret marker at ${location} has no source value`);
    }
    return cloneJson(source);
  }
  if (Array.isArray(value)) {
    const sourceArray = Array.isArray(source) ? source : [];
    return value.map((item, index) => resolveSecretMarkers(
      item,
      sourceArray[index],
      `${location}[${index}]`
    ));
  }
  if (isPlainObject(value)) {
    const sourceObject = isPlainObject(source) ? source : {};
    const result: JsonObject = {};
    for (const [key, item] of Object.entries(value)) {
      result[key] = resolveSecretMarkers(item, sourceObject[key], `${location}.${key}`);
    }
    return result;
  }
  return value;
}

export function hydrateAdminService(
  candidate: unknown,
  secretSource?: ServiceConfig
): ServiceConfig {
  if (!isPlainObject(candidate)) throw new Error('Service config must be a JSON object');
  return resolveSecretMarkers(candidate, secretSource, 'config') as ServiceConfig;
}

function mergeObjectPatch(base: unknown, patch: unknown): unknown {
  if (!isPlainObject(base) || !isPlainObject(patch) || isSecretMarker(patch)) {
    return cloneJson(patch);
  }
  const result: JsonObject = cloneJson(base);
  for (const [key, value] of Object.entries(patch)) {
    result[key] = mergeObjectPatch(result[key], value);
  }
  return result;
}

/** Backward-compatible partial update for API clients predating replace=true. */
export function hydrateAdminServicePatch(candidate: unknown, source: ServiceConfig): ServiceConfig {
  if (!isPlainObject(candidate)) throw new Error('Service config must be a JSON object');
  const merged = mergeObjectPatch(source, candidate);
  return resolveSecretMarkers(merged, source, 'config') as ServiceConfig;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function validateAuth(service: ServiceConfig): string[] {
  const errors: string[] = [];
  if (!isPlainObject(service.auth)) return ['service.auth must be an object'];
  const auth = service.auth as unknown as JsonObject;
  const type = auth['type'];
  const supported = new Set([
    'bearer', 'header', 'query', 'basic', 'url',
    'oauth2_client_credentials', 'oauth2_authorization_code',
    'body_json', 'plugin',
  ]);
  if (typeof type !== 'string' || !supported.has(type)) {
    return [`Unsupported auth.type: ${String(type)}`];
  }

  if (type === 'plugin') {
    if (!nonEmptyString(auth['pluginPath'])) errors.push('plugin auth requires auth.pluginPath');
    if (!isPlainObject(auth['pluginConfig'])) errors.push('plugin auth requires auth.pluginConfig');
    return errors;
  }
  if (type === 'bearer' || type === 'header' || type === 'query') {
    if (!nonEmptyString(auth['token'])) errors.push(`${type} auth requires auth.token`);
    if (type === 'header' && !nonEmptyString(auth['headerName'])) {
      errors.push('header auth requires auth.headerName');
    }
    if (type === 'query' && !nonEmptyString(auth['paramName'])) {
      errors.push('query auth requires auth.paramName');
    }
  } else if (type === 'basic' || type === 'url') {
    if (!nonEmptyString(auth['username'])) errors.push(`${type} auth requires auth.username`);
    if (!nonEmptyString(auth['password'])) errors.push(`${type} auth requires auth.password`);
  } else if (type === 'oauth2_client_credentials') {
    if (!nonEmptyString(auth['tokenPath'])) errors.push('OAuth2 client credentials requires auth.tokenPath');
    if (!nonEmptyString(auth['clientId'])) errors.push('OAuth2 client credentials requires auth.clientId');
    if (!nonEmptyString(auth['clientSecret'])) errors.push('OAuth2 client credentials requires auth.clientSecret');
  } else if (type === 'oauth2_authorization_code') {
    for (const field of ['authorizeUrl', 'tokenUrl', 'redirectUri', 'clientId']) {
      if (!nonEmptyString(auth[field])) errors.push(`OAuth2 authorization code requires auth.${field}`);
    }
    if (!Array.isArray(auth['scopes']) || auth['scopes'].some((scope) => !nonEmptyString(scope))) {
      errors.push('OAuth2 authorization code requires auth.scopes as a list of strings');
    }
  } else if (type === 'body_json') {
    if (!isPlainObject(auth['fields']) || Object.keys(auth['fields']).length === 0
      || Object.values(auth['fields']).some((field) => !nonEmptyString(field))) {
      errors.push('body_json auth requires non-empty string auth.fields values');
    }
  }
  return errors;
}

function validatePolicy(service: ServiceConfig): string[] {
  if (!isPlainObject(service.policy)) return ['service.policy must be an object'];
  const errors: string[] = [];
  if (service.policy.default !== 'auto_approve' && service.policy.default !== 'require_approval') {
    errors.push('policy.default must be auto_approve or require_approval');
  }
  if (service.policy.rules !== undefined) {
    if (!Array.isArray(service.policy.rules)) return [...errors, 'policy.rules must be a list'];
    for (const [index, rule] of service.policy.rules.entries()) {
      if (!isPlainObject(rule) || !isPlainObject(rule['match'])
        || (rule['action'] !== 'auto_approve' && rule['action'] !== 'require_approval')) {
        errors.push(`policy.rules[${index}] is invalid`);
      }
    }
  }
  return errors;
}

/** Validate one complete service without mutating process state. */
export function validateAdminService(name: string, service: ServiceConfig, config: Config): string[] {
  const errors: string[] = [];
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) {
    errors.push('Service name must be 1-64 letters, digits, hyphens, or underscores');
  }
  if (!isPlainObject(service)) return [...errors, 'Service config must be an object'];
  if (!nonEmptyString(service.upstream)) errors.push('service.upstream must be a non-empty URL');
  errors.push(...validateAuth(service), ...validatePolicy(service));

  const protocol = service.protocol ?? 'http';
  if (!['http', 'ssh', 'ftp', 'ftps'].includes(protocol)) {
    errors.push(`Unsupported service protocol: ${String(protocol)}`);
  }
  // The protocol-specific validators expect the base document to be
  // structurally sound. Never let malformed admin JSON reach their typed
  // property accessors and turn a client error into an HTTP 500.
  if (errors.length > 0) {
    return [...new Set(errors)];
  }

  const candidateConfig: Config = {
    ...config,
    services: { ...config.services, [name]: service },
  };
  errors.push(
    ...validateHttpConfiguration(candidateConfig),
    ...validateSshConfiguration(candidateConfig),
    ...validateFtpConfiguration(candidateConfig)
  );

  const target = protocol === 'ssh'
    ? validateSshService(service, config.security)
    : protocol === 'ftp' || protocol === 'ftps'
      ? validateFtpService(service, config.security)
      : validateUpstreamUrl(
        service.upstream,
        config.security,
        service.http?.allowPrivateTarget === true
      );
  if (!target.valid) errors.push(target.reason || 'Invalid upstream');

  if (protocol === 'http' && service.hostnames !== undefined) {
    if (!Array.isArray(service.hostnames) || service.hostnames.some((hostname) => !nonEmptyString(hostname))) {
      errors.push('service.hostnames must be a list of non-empty strings');
    } else if (nonEmptyString(service.upstream)) {
      try {
        const upstreamHost = new URL(service.upstream).hostname;
        for (const hostname of service.hostnames) {
          if (hostname !== upstreamHost && !isAllowedUpstream(hostname, config.security.allowedUpstreams)) {
            errors.push(`Hostname "${hostname}" is not in security.allowedUpstreams`);
          }
        }
      } catch { /* validateUpstreamUrl reports the malformed URL */ }
    }
  }
  return [...new Set(errors)];
}

export function createAdminServiceRuntime(config: Config): AdminServiceRuntime {
  const pluginDataDir = path.resolve('data/plugins');
  const sshPluginDataDir = path.resolve('data/ssh-credential-plugins');
  const ftpPluginDataDir = path.resolve('data/ftp-credential-plugins');

  const remove = (name: string) => {
    unloadPlugin(name);
    unloadSshCredentialPlugin(name);
    unloadFtpCredentialPlugin(name);
  };

  return {
    async apply(name: string, service: ServiceConfig): Promise<ServiceConfig> {
      const activeService = await resolveServiceConfigSecrets(service, config.secrets);

      if (activeService.protocol === 'ssh') {
        const validation = await validateSshTargetRuntime(activeService, config.security);
        if (!validation.valid) throw new Error(validation.reason || 'SSH target validation failed');
      } else if (activeService.protocol === 'ftp' || activeService.protocol === 'ftps') {
        const validation = await validateFtpTargetRuntime(activeService, config.security);
        if (!validation.valid) throw new Error(validation.reason || 'FTP target validation failed');
      }

      if (activeService.auth.type !== 'plugin' || !activeService.auth.pluginPath) {
        remove(name);
        return activeService;
      }
      if (activeService.protocol === 'ssh') {
        if (getSshCredentialPlugin(name)) {
          const probeName = `${name}__admin_probe_${randomUUID()}`;
          await loadSshCredentialPlugin(
            probeName,
            activeService.auth.pluginPath,
            activeService.auth.pluginConfig || {},
            sshPluginDataDir
          );
          unloadSshCredentialPlugin(probeName);
        }
        await loadSshCredentialPlugin(
          name,
          activeService.auth.pluginPath,
          activeService.auth.pluginConfig || {},
          sshPluginDataDir
        );
        unloadPlugin(name);
        unloadFtpCredentialPlugin(name);
      } else if (activeService.protocol === 'ftp' || activeService.protocol === 'ftps') {
        if (getFtpCredentialPlugin(name)) {
          const probeName = `${name}__admin_probe_${randomUUID()}`;
          await loadFtpCredentialPlugin(
            probeName,
            activeService.auth.pluginPath,
            activeService.auth.pluginConfig || {},
            ftpPluginDataDir
          );
          unloadFtpCredentialPlugin(probeName);
        }
        await loadFtpCredentialPlugin(
          name,
          activeService.auth.pluginPath,
          activeService.auth.pluginConfig || {},
          ftpPluginDataDir
        );
        unloadPlugin(name);
        unloadSshCredentialPlugin(name);
      } else {
        await loadPlugin(
          name,
          activeService.auth.pluginPath,
          activeService.auth.pluginConfig || {},
          pluginDataDir
        );
        unloadSshCredentialPlugin(name);
        unloadFtpCredentialPlugin(name);
      }
      return activeService;
    },
    remove,
  };
}
