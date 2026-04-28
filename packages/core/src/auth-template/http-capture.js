'use strict';

const http = require('http');
const https = require('https');
const { Readable } = require('stream');
const { EventEmitter } = require('events');

// Patches http/https/fetch so outbound requests are intercepted instead of
// hitting the network. `onRequest({ url, headers, method })` is invoked for
// every intercepted call. The original globals are restored on completion
// (success or error). Used by both getAuthTemplate (placeholder authData)
// and renderAuthTemplate (real authData) when invoking authentication.test
// as a function.
const withHttpCapture = async (onRequest, fn) => {
  const origHttpRequest = http.request;
  const origHttpsRequest = https.request;
  const origHttpGet = http.get;
  const origHttpsGet = https.get;
  const origFetch = globalThis.fetch;

  const patchedRequest = (origFn, protocol) =>
    function patchedReq(...args) {
      // args can be (url, options, cb), (options, cb), or (url, cb)
      let options = {};
      const cb =
        typeof args[args.length - 1] === 'function'
          ? args[args.length - 1]
          : null;

      if (typeof args[0] === 'string' || args[0] instanceof URL) {
        const parsed = typeof args[0] === 'string' ? new URL(args[0]) : args[0];
        options =
          typeof args[1] === 'object' && args[1] !== null
            ? { url: parsed.href, ...args[1] }
            : { url: parsed.href };
      } else {
        options = args[0] || {};
      }

      onRequest({
        url:
          options.url ||
          `${protocol}://${options.host || options.hostname || 'localhost'}${options.path || '/'}`,
        headers: options.headers || {},
        method: options.method || 'GET',
      });

      // Return a no-op request that doesn't actually connect.
      // Use a real Readable stream so libraries that call .pipe() or
      // .setEncoding() (e.g. xmlrpc's SAX deserializer) work correctly.
      const fakeReq = new EventEmitter();
      fakeReq.write = () => {};
      fakeReq.end = () => {
        const body =
          '<?xml version="1.0"?><methodResponse><params>' +
          '<param><value><string>ok</string></value></param>' +
          '</params></methodResponse>';
        const fakeRes = new Readable({
          read() {
            this.push(body);
            this.push(null);
          },
        });
        fakeRes.statusCode = 200;
        fakeRes.headers = { 'content-type': 'text/xml' };
        if (cb) {
          cb(fakeRes);
        }
        fakeReq.emit('response', fakeRes);
      };
      fakeReq.setTimeout = () => fakeReq;
      fakeReq.destroy = () => {};
      return fakeReq;
    };

  http.request = patchedRequest(origHttpRequest, 'http');
  https.request = patchedRequest(origHttpsRequest, 'https');
  http.get = patchedRequest(origHttpGet, 'http');
  https.get = patchedRequest(origHttpsGet, 'https');

  globalThis.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input?.url || '';
    const headers = init?.headers || input?.headers || {};
    onRequest({
      url,
      headers:
        headers instanceof Headers
          ? Object.fromEntries(headers.entries())
          : headers,
      method: init?.method || input?.method || 'GET',
    });
    return new Response('{}', { status: 200, headers: {} });
  };

  try {
    return await fn();
  } finally {
    http.request = origHttpRequest;
    https.request = origHttpsRequest;
    http.get = origHttpGet;
    https.get = origHttpsGet;
    globalThis.fetch = origFetch;
  }
};

module.exports = { withHttpCapture };
