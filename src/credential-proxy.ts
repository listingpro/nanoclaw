/**
 * Credential proxy for container isolation.
 * Containers connect here instead of directly to the Anthropic API.
 * The proxy injects real credentials so containers never see them.
 *
 * Two auth modes:
 *   API key:  Proxy injects x-api-key on every request.
 *   OAuth:    Container CLI exchanges its placeholder token for a temp
 *             API key via /api/oauth/claude_cli/create_api_key.
 *             Proxy injects real OAuth token on that exchange request;
 *             subsequent requests carry the temp key which is valid as-is.
 */
import { createServer, Server } from 'http';
import { request as httpsRequest } from 'https';
import { request as httpRequest, RequestOptions } from 'http';
import path from 'path';

import { readEnvFile } from './env.js';
import { logger } from './logger.js';

export type AuthMode = 'api-key' | 'oauth';

export interface ProxyConfig {
  authMode: AuthMode;
}

export function startCredentialProxy(
  port: number,
  host = '127.0.0.1',
): Promise<Server> {
  const secrets = readEnvFile([
    'ANTHROPIC_API_KEY',
    'CLAUDE_CODE_OAUTH_TOKEN',
    'ANTHROPIC_AUTH_TOKEN',
    'ANTHROPIC_BASE_URL',
    'CLAUDE_CODE_MODEL',
  ]);

  const authMode: AuthMode = secrets.ANTHROPIC_API_KEY ? 'api-key' : 'oauth';
  const oauthToken =
    secrets.CLAUDE_CODE_OAUTH_TOKEN || secrets.ANTHROPIC_AUTH_TOKEN;

  const upstreamUrl = new URL(
    secrets.ANTHROPIC_BASE_URL || 'https://api.anthropic.com',
  );
  const isHttps = upstreamUrl.protocol === 'https:';
  const makeRequest = isHttps ? httpsRequest : httpRequest;

  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        let body = Buffer.concat(chunks);

        // Override model in request body if CLAUDE_CODE_MODEL is configured.
        // The Claude SDK hardcodes its own default model; we rewrite it here
        // so OpenRouter receives the model we actually want.
        const overrideModel = secrets.CLAUDE_CODE_MODEL;
        const contentType = (req.headers['content-type'] || '').toLowerCase();
        if (overrideModel && contentType.includes('application/json') && body.length > 0) {
          try {
            const parsed = JSON.parse(body.toString('utf8'));
            if (parsed && typeof parsed === 'object' && 'model' in parsed) {
              parsed.model = overrideModel;
              body = Buffer.from(JSON.stringify(parsed), 'utf8');
            }
          } catch {
            // Not valid JSON, leave body as-is
          }
        }

        const headers: Record<string, string | number | string[] | undefined> =
          {
            ...(req.headers as Record<string, string>),
            host: upstreamUrl.host,
            'content-length': body.length,
          };

        // Strip hop-by-hop headers that must not be forwarded by proxies
        delete headers['connection'];
        delete headers['keep-alive'];
        delete headers['transfer-encoding'];

        const isOpenRouter = upstreamUrl.hostname.includes('openrouter.ai');

        if (authMode === 'api-key') {
          // API key mode: inject x-api-key or Authorization: Bearer for OpenRouter
          delete headers['x-api-key'];
          delete headers['authorization'];
          if (isOpenRouter) {
            headers['authorization'] = `Bearer ${secrets.ANTHROPIC_API_KEY}`;
          } else {
            headers['x-api-key'] = secrets.ANTHROPIC_API_KEY;
          }
        } else {
          // OAuth mode: replace placeholder Bearer token with the real one
          // only when the container actually sends an Authorization header
          // (exchange request + auth probes). Post-exchange requests use
          // x-api-key locally, but if upstream is OpenRouter, they need
          // to be translated back to Bearer tokens for the final request.
          if (headers['authorization']) {
            delete headers['authorization'];
            if (oauthToken) {
              headers['authorization'] = `Bearer ${oauthToken}`;
            }
          } else if (isOpenRouter && headers['x-api-key']) {
            // Translate local x-api-key (from temp key) back to Bearer for OpenRouter
            const tempKey = headers['x-api-key'] as string;
            delete headers['x-api-key'];
            headers['authorization'] = `Bearer ${tempKey}`;
          }
        }

        const basePath = upstreamUrl.pathname.replace(/\/$/, '');
        const reqPath = (req.url || '').replace(/^\/+/, '');
        const upstreamPath = basePath + (reqPath ? '/' + reqPath : '');
        const upstream = makeRequest(
          {
            hostname: upstreamUrl.hostname,
            port: upstreamUrl.port || (isHttps ? 443 : 80),
            path: upstreamPath,
            method: req.method,
            headers,
          } as RequestOptions,
          (upRes) => {
            logger.info(
              {
                method: req.method,
                url: upstreamPath,
                status: upRes.statusCode,
              },
              'Credential proxy upstream response',
            );
            res.writeHead(upRes.statusCode!, upRes.headers);
            upRes.pipe(res);
          },
        );

        logger.info(
          {
            method: req.method,
            url: upstreamPath,
            headers: {
              ...headers,
              authorization: headers['authorization'] ? '[REDACTED]' : undefined,
              'x-api-key': headers['x-api-key'] ? '[REDACTED]' : undefined,
            },
          },
          'Credential proxy upstream request',
        );

        upstream.on('error', (err) => {
          logger.error(
            { err, url: upstreamPath },
            'Credential proxy upstream error',
          );
          if (!res.headersSent) {
            res.writeHead(502);
            res.end('Bad Gateway');
          }
        });

        upstream.write(body);
        upstream.end();
      });
    });

    server.listen(port, host, () => {
      logger.info({ port, host, authMode }, 'Credential proxy started');
      resolve(server);
    });

    server.on('error', reject);
  });
}

/** Detect which auth mode the host is configured for. */
export function detectAuthMode(): AuthMode {
  const secrets = readEnvFile(['ANTHROPIC_API_KEY']);
  return secrets.ANTHROPIC_API_KEY ? 'api-key' : 'oauth';
}
