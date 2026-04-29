'use strict';

require('should');

const renderAuthTemplate = require('../../src/auth-template/render-auth-template');

const buildInput = (compiledApp, authData = {}) => ({
  bundle: { authData },
  _zapier: {
    app: compiledApp,
    event: { bundle: { authData } },
    promises: [],
    logger: () => Promise.resolve(),
    logBuffer: [],
    whatHappened: [],
  },
});

const run = (compiledApp, authData) =>
  renderAuthTemplate(compiledApp, buildInput(compiledApp, authData));

describe('renderAuthTemplate', () => {
  describe('early returns', () => {
    it('returns null authType with empty template when no authentication', async () => {
      const result = await run({});
      result.should.deepEqual({ authType: null, template: {} });
    });
  });

  describe('beforeRequest pipeline', () => {
    it('renders auth headers added by a beforeRequest function', async () => {
      const beforeRequest = (req, z, bundle) => {
        req.headers = req.headers || {};
        req.headers.Authorization = `Bearer ${bundle.authData.access_token}`;
        return req;
      };
      const result = await run(
        {
          authentication: {
            type: 'oauth2',
            test: { url: 'https://example.com' },
            fields: [{ key: 'access_token' }],
          },
          beforeRequest: [beforeRequest],
        },
        { access_token: 'real-token-123' },
      );
      result.authType.should.eql('oauth2');
      result.template.headers.Authorization.should.eql('Bearer real-token-123');
    });

    it('accepts beforeRequest as a single function (not an array)', async () => {
      const beforeRequest = (req, z, bundle) => {
        req.headers = req.headers || {};
        req.headers['X-Api-Key'] = bundle.authData.api_key;
        return req;
      };
      const result = await run(
        {
          authentication: {
            type: 'custom',
            test: { url: 'https://example.com' },
            fields: [{ key: 'api_key' }],
          },
          beforeRequest,
        },
        { api_key: 'real-key-abc' },
      );
      result.template.headers['X-Api-Key'].should.eql('real-key-abc');
    });

    it('renders requestTemplate via prepareRequest merge', async () => {
      const result = await run(
        {
          authentication: {
            type: 'oauth2',
            test: { url: 'https://example.com' },
            fields: [{ key: 'access_token' }],
          },
          requestTemplate: {
            headers: {
              Authorization: 'Bearer {{bundle.authData.access_token}}',
            },
          },
        },
        { access_token: 'real-token-xyz' },
      );
      result.template.headers.Authorization.should.eql('Bearer real-token-xyz');
    });

    it('renders both requestTemplate and beforeRequest contributions', async () => {
      const beforeRequest = (req, z, bundle) => {
        req.headers = req.headers || {};
        req.headers.Authorization = `Bearer ${bundle.authData.access_token}`;
        return req;
      };
      const result = await run(
        {
          authentication: {
            type: 'oauth2',
            test: { url: 'https://example.com' },
            fields: [{ key: 'access_token' }, { key: 'tenant' }],
          },
          requestTemplate: {
            headers: { 'X-Tenant': '{{bundle.authData.tenant}}' },
          },
          beforeRequest: [beforeRequest],
        },
        { access_token: 'real-token', tenant: 'acme' },
      );
      result.template.headers.Authorization.should.eql('Bearer real-token');
      result.template.headers['X-Tenant'].should.eql('acme');
    });

    it('returns error when the pipeline throws', async () => {
      const beforeRequest = () => {
        throw new Error('middleware blew up');
      };
      const result = await run(
        {
          authentication: { type: 'custom', fields: [{ key: 'api_key' }] },
          beforeRequest: [beforeRequest],
        },
        { api_key: 'x' },
      );
      result.authType.should.eql('custom');
      result.error.should.match(/middleware blew up/);
      result.template.should.deepEqual({});
    });
  });

  describe('auth-type-specific middleware', () => {
    it('basic auth applies the addBasicAuthHeader middleware', async () => {
      const result = await run(
        { authentication: { type: 'basic' } },
        { username: 'alice', password: 's3cret' },
      );
      // addBasicAuthHeader produces `Basic base64(user:pass)`
      const expected =
        'Basic ' + Buffer.from('alice:s3cret').toString('base64');
      result.template.headers.Authorization.should.eql(expected);
    });
  });

  describe('inline-auth fallback (auth.test as object)', () => {
    it('renders headers from a static test object via renderFromTest', async () => {
      // No beforeRequest, no requestTemplate. Pipeline produces an empty
      // template; renderFromTest substitutes placeholder strings in the test
      // object headers with real authData values.
      const result = await run(
        {
          authentication: {
            type: 'custom',
            fields: [{ key: 'api_key' }],
            test: {
              url: 'https://example.com/me',
              headers: { 'X-Api-Key': '{{bundle.authData.api_key}}' },
            },
          },
        },
        { api_key: 'real-fallback-key' },
      );
      result.template.headers['X-Api-Key'].should.eql('real-fallback-key');
    });

    it('renders params from a static test object via renderFromTest', async () => {
      const result = await run(
        {
          authentication: {
            type: 'custom',
            fields: [{ key: 'api_key' }],
            test: {
              url: 'https://example.com/me',
              params: { token: '{{bundle.authData.api_key}}' },
            },
          },
        },
        { api_key: 'real-key' },
      );
      result.template.params.token.should.eql('real-key');
    });

    it('returns empty template when test object has no placeholders to render', async () => {
      // Test object exists but doesn't reference any authData placeholders —
      // nothing for renderFromTest to emit.
      const result = await run(
        {
          authentication: {
            type: 'custom',
            fields: [{ key: 'api_key' }],
            test: { url: 'https://example.com/me' },
          },
        },
        { api_key: 'real-key' },
      );
      result.template.should.deepEqual({});
    });
  });

  describe('inline-auth fallback (auth.test as function)', () => {
    it('renders auth from inline z.request config when test is a function', async () => {
      // Inline-auth pattern: no beforeRequest, no requestTemplate. Auth lives
      // inside the test function's z.request config. The inline fallback runs
      // the test function with real authData and captures the prepared
      // request.
      const result = await run(
        {
          authentication: {
            type: 'custom',
            fields: [{ key: 'api_key' }],
            test: async (z, bundle) => {
              const resp = await z.request({
                url: 'https://example.com/me',
                headers: { 'X-Api-Key': bundle.authData.api_key },
              });
              return resp.data;
            },
          },
        },
        { api_key: 'real-inline-key' },
      );
      result.template.headers['X-Api-Key'].should.eql('real-inline-key');
    });

    it('still captures the request when the test function throws after z.request', async () => {
      // Test functions often parse the response and crash on the empty stub.
      // The captured request is preserved.
      const result = await run(
        {
          authentication: {
            type: 'custom',
            fields: [{ key: 'api_key' }],
            test: async (z, bundle) => {
              const resp = await z.request({
                url: 'https://example.com/me',
                headers: { 'X-Api-Key': bundle.authData.api_key },
              });
              return resp.data.user.email; // crashes — resp.data is {}
            },
          },
        },
        { api_key: 'real-key' },
      );
      result.template.headers['X-Api-Key'].should.eql('real-key');
    });

    it('captures via raw http/fetch when the test function bypasses z.request', async () => {
      // Some test functions construct a request via raw fetch (or via SDKs
      // that destructure http.request at import time). The withHttpCapture
      // safety net catches them.
      const result = await run(
        {
          authentication: {
            type: 'custom',
            fields: [{ key: 'api_key' }],
            test: async (z, bundle) => {
              await fetch('https://example.com/me', {
                headers: { 'X-Api-Key': bundle.authData.api_key },
              });
            },
          },
        },
        { api_key: 'raw-fetch-key' },
      );
      result.template.headers['X-Api-Key'].should.eql('raw-fetch-key');
    });

    it('returns empty template when the test function never makes a request', async () => {
      const result = await run(
        {
          authentication: {
            type: 'custom',
            fields: [{ key: 'api_key' }],
            test: async () => ({ ok: true }),
          },
        },
        { api_key: 'unused' },
      );
      result.template.should.deepEqual({});
    });
  });

  describe('beforeRequest with z.request (real network call)', () => {
    let origFetch;
    beforeEach(() => {
      origFetch = globalThis.fetch;
    });
    afterEach(() => {
      globalThis.fetch = origFetch;
    });

    it('routes beforeRequest internal z.request calls through real fetch', async () => {
      // Refresh-token-style pattern: BR fetches an auxiliary value and uses
      // it to set the auth header. The render path replaces stubZ.request
      // with a real fetch-backed implementation so this works.
      let capturedFetchUrl = null;
      globalThis.fetch = async (url) => {
        capturedFetchUrl = url;
        return new Response('encoded-' + url.split('/').pop(), {
          status: 200,
          headers: { 'content-type': 'text/plain' },
        });
      };

      const beforeRequest = async (req, z, bundle) => {
        const resp = await z.request({
          url: `https://encoder.example.com/encode/${bundle.authData.api_key}`,
        });
        req.headers = req.headers || {};
        req.headers['X-Encoded'] = resp.content;
        return req;
      };

      const result = await run(
        {
          authentication: {
            type: 'custom',
            fields: [{ key: 'api_key' }],
          },
          beforeRequest: [beforeRequest],
        },
        { api_key: 'plain-key' },
      );

      capturedFetchUrl.should.eql(
        'https://encoder.example.com/encode/plain-key',
      );
      result.template.headers['X-Encoded'].should.eql('encoded-plain-key');
    });
  });
});
