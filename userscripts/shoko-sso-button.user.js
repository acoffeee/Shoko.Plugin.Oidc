// ==UserScript==
// @name         Shoko: Login with SSO
// @namespace    shoko-oidc
// @version      1.0.0
// @description  Adds a "Login with SSO" button to the Shoko Web UI login page, using the OpenID Connect plugin.
// @match        *://*/webui/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function () {
    'use strict';

    // The plugin's login page, resolved against the server root (the part of
    // the URL before "/webui/"), so it keeps working behind a reverse proxy
    // sub-path. If you changed the plugin's Web UI Path, change @match too.
    const LOGIN_PATH = 'plugin/OIDC/login';
    const WEBUI_SEGMENT = '/webui/';
    const BUTTON_TEXT = 'Login with SSO';
    const BUTTON_ID = 'tm-shoko-sso-button';

    function serverRoot() {
        const index = location.pathname.indexOf(WEBUI_SEGMENT);
        return location.origin + (index === -1 ? '/' : location.pathname.slice(0, index + 1));
    }

    function loginUrl() {
        const url = new URL(LOGIN_PATH, serverRoot());
        // Hand a Web UI redirect on to the plugin, which only accepts paths
        // inside the Web UI.
        const redirectTo = new URLSearchParams(location.search).get('redirectTo');
        if (redirectTo)
            url.searchParams.set('redirectTo', redirectTo);
        return url.href;
    }

    function createButton(template) {
        // Copy the Web UI's own login button so the theme carries over. A
        // clone keeps the classes but none of React's handlers.
        const button = template ? template.cloneNode(false) : document.createElement('button');
        button.id = BUTTON_ID;
        button.type = 'button';
        button.disabled = false;
        button.removeAttribute('form');
        button.textContent = BUTTON_TEXT;
        button.style.marginTop = '0.75rem';
        button.style.width = '100%';
        button.addEventListener('click', () => {
            location.href = loginUrl();
        });
        return button;
    }

    function inject() {
        if (!/\/login\/?$/.test(location.pathname) || document.getElementById(BUTTON_ID))
            return;

        const password = document.querySelector('input[type="password"]');
        const form = password && password.closest('form');
        if (!form)
            return;

        const submit = form.querySelector('button[type="submit"]') || form.querySelector('button');
        // Outside the form, so pressing Enter in a field still signs in with
        // the password.
        form.insertAdjacentElement('afterend', createButton(submit));
    }

    // The Web UI is a single-page app, so the login form can appear at any
    // time (first load, logging out, an expired session).
    new MutationObserver(inject).observe(document.body, { childList: true, subtree: true });
    inject();
})();
