// not intended to be loaded via require() or import() - copied during build step
import zapier from 'zapier-platform-core';

let _appRaw;
try {
  _appRaw = await import('{REPLACE_ME_PACKAGE_NAME}');
} catch (err) {
  if (
    err.code === 'ERR_MODULE_NOT_FOUND' &&
    err.message?.includes('{REPLACE_ME_PACKAGE_NAME}')
  ) {
    err.message =
      'It seems you are using ESM because your package.json has `"type": "module"`. ' +
      'For ESM to work, make sure you specify a valid entry point using `exports` (instead of `main`) in package.json.\n\n' +
      err.message;
  }
  throw err;
}

// Allows a developer to use named exports or default export in entry point
if (_appRaw && _appRaw.default) {
  _appRaw = _appRaw.default;
}

export const appRaw = _appRaw;
export const handler = zapier.createAppHandler(_appRaw);
