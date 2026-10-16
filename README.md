> [!WARNING]
> **Disclaimer** This entire project is vibe coded and not reviewed and NOT garunteed to be secure or safe. It was more or less made so i didnt have to type in passwords cause thats alot of work and asking claude to make me this was not.
# Shoko OpenID Connect

Sign in to Shoko through an OpenID Connect provider, such as Authelia, with
passkeys or whatever else the provider supports. Shoko stays the source of
truth for users: the provider only vouches for who is signing in, and each
subject (`sub` claim) is mapped by hand to an existing Shoko user. A subject
that is not mapped cannot sign in.

## How it works

1. A browser opens `/plugin/OIDC/login` and is sent to the provider, using
   the authorization code flow with PKCE.
2. The provider sends it back to `/plugin/OIDC/callback`. The plugin
   exchanges the code, checks the ID token (signature, issuer, audience,
   expiry and nonce), and looks the subject up in its mappings.
3. A mapped subject gets an API key for its Shoko user. The key is handed to
   the Web UI the way its own login form stores it, and the Web UI opens.
4. An unmapped subject is turned away with its subject shown, and is listed
   on the **User Mappings** page for an admin to map.

## Setting it up with Authelia

1. Install the plugin and restart Shoko.
2. In the Web UI, open the plugin's settings and set the **Issuer URL** (e.g.
   `https://auth.example.com`), **Client ID**, **Client Secret** and, if
   Shoko is behind a reverse proxy, the **Public URL** (e.g.
   `https://shoko.example.com`). Shoko does not read `X-Forwarded-*`
   headers, so without it the redirect URI is built from the address the
   request came in on.
3. Open the plugin's **User Mappings** page. It shows the redirect URI to
   register, and an example client for Authelia's configuration:

   ```yaml
   identity_providers:
     oidc:
       clients:
         - client_id: 'shoko'
           client_name: 'Shoko'
           client_secret: '$pbkdf2-sha512$...' # authelia crypto hash generate pbkdf2
           authorization_policy: 'two_factor'
           require_pkce: true
           pkce_challenge_method: 'S256'
           redirect_uris:
             - 'https://shoko.example.com/plugin/OIDC/callback'
           scopes: ['openid', 'profile', 'email']
           response_types: ['code']
           grant_types: ['authorization_code']
           token_endpoint_auth_method: 'client_secret_basic'
   ```

   Restrict who may use the client with Authelia's `authorization_policy`
   or access control rules; the plugin itself only checks the mappings.
4. Sign in once at `/plugin/OIDC/login` with each account. Each one is
   turned away and appears on the **User Mappings** page, where you pick the
   Shoko user it signs in as. The mappings are kept in the plugin's
   configuration, so they can also be edited on its settings page.
5. Bookmark `https://shoko.example.com/plugin/OIDC/login`, or link to it from
   your dashboard. `?redirectTo=/webui/...` opens a page of the Web UI
   afterwards.

The issuer, client ID, client secret and public URL can also be set with
the `SHOKO_OIDC_ISSUER`, `SHOKO_OIDC_CLIENT_ID`, `SHOKO_OIDC_CLIENT_SECRET`
and `SHOKO_OIDC_PUBLIC_URL` environment variables.

### Sessions

Every login mints a new API key for the Web UI, under the device name
`web-ui (oidc)`, that expires after the **Web UI Session Lifetime** (30 days
by default). Shoko refuses to create a non-expiring key from an expiring
session, so set the lifetime to 0 if you create API keys from the Web UI.
Removing a mapping stops new logins only; revoke the keys already handed
out from the Web UI's API key settings.

## Pairing a device

A device that cannot open a browser itself, such as a TV app, can be paired.
This follows the device authorization grant (RFC 8628):

1. The device calls `POST /api/plugin/OIDC/Pair` with
   `{ "DeviceName": "Living Room TV" }` and gets back a `Code`, a `Secret`, a
   `VerificationUri`, a `VerificationUriComplete` (with the code filled in,
   for a link or QR code), `ExpiresAt` and a poll `Interval` in seconds.
2. The device shows the code and the link. The user opens the link, signs in
   with the provider, and approves or denies the device.
3. The device calls `POST /api/plugin/OIDC/Pair/Poll` with
   `{ "Secret": "..." }` every `Interval` seconds. The `Status` is `Pending`
   until the user answers, then `Approved` (with `ApiKey` and `Username`),
   `Denied` or `Expired`.

The approved key is handed out once. A key nobody collects within five
minutes is revoked. The **Pair a device** plugin page is where a user enters
a code by hand. Pairing can be turned off in the plugin's settings.

## Building

```sh
dotnet build
```

Copy `source/bin/Debug/net10.0` into the server's `plugins` folder to try
it. Releases are built by `.github/workflows/release.yml` when a GitHub
release is published: bump `<Version>` in the `.csproj` and publish a
release tagged `v<Version>`. Before the first release, create a branch named
`metadata` holding a copy of `manifest.json` with your identity filled in.
