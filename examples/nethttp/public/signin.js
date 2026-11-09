// The sign-in page's script. It is the same file in every example in this folder.
// The server writes the app's settings and a nonce it issued for this browser session onto the container element.
(() => {
  'use strict';

  const container = document.getElementById('rante-signin');
  const status = document.getElementById('rante-signin-status');
  const show = (message) => { status.textContent = message; };

  if (!window.RanteLogin) {
    show('The Rante Login SDK did not load. Check the browser console.');
    return;
  }

  const { clientId, redirectUri, scope, nonce } = container.dataset;

  // The SDK keeps the PKCE verifier, the state and the nonce in cookies on this page's origin, so the server only
  // sees them when the site is opened on the redirect URI's origin.
  const expectedOrigin = new URL(redirectUri).origin;
  if (location.origin !== expectedOrigin) {
    show(`Open this site at ${expectedOrigin} (the redirect URI's origin); sign-in cookies are kept per origin.`);
    return;
  }

  RanteLogin.init({
    clientId,
    redirectUri,
    scope,
    // The redirect flow ends on the server: the SDK writes rante_login_pkce, rante_login_state and rante_login_nonce
    // as cookies, and the server exchanges the code.
    serverSide: true
  });

  RanteLogin.renderButton(container, {
    // The server's nonce for this browser session. The SDK sends it in both flows.
    nonce,
    // FedCM (Chrome and Edge): the browser's account dialog returned an ID token to this page. Send it to the server,
    // which validates it before it trusts it. A redirect sign-in comes back to the redirect URI on the server instead.
    onSignIn: async (result) => {
      show('Signing in…');
      try {
        const response = await fetch('/auth/rante/fedcm', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ idToken: result.idToken })
        });
        if (response.ok) {
          location.assign('/');
          return;
        }
        const body = await response.json().catch(() => ({}));
        show(`Sign-in failed: ${body.error || response.status}.`);
      } catch {
        show('Sign-in failed: the server could not be reached.');
      }
    },
    onError: (error) => {
      show(error.code === 'fedcm_dismissed'
        ? 'The browser closed its sign-in dialog. Select the button again to sign in on the Rante Login page.'
        : `Sign-in failed: ${error.code}.`);
    }
  });
})();
