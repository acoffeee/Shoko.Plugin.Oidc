> ### **Disclaimer **
> This entire project is vibe coded and not reviewed and NOT garunteed to be secure or safe. It was more or less made so i didnt have to type in passwords cause thats alot of work and asking claude to make me this was not.
# Shoko OpenID Connect

A plugin for [Shoko](https://shokoanime.com/), built from the
[Shoko Plugin Template](https://github.com/ShokoAnime/Plugin-Template).

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

## Installing

Add this manifest URL as a plugin repository in Shoko:

```
https://raw.githubusercontent.com/acoffeee/Shoko.Plugin.Oidc/metadata/manifest.json
```

Shoko then lists the plugin and its releases, and can install and update
it from there. Each release's zip is also attached to its
[GitHub release](https://github.com/acoffeee/Shoko.Plugin.Oidc/releases),
for installing by hand into the server's `plugins` folder.

## Setting it up with Authelia

1. Install the plugin (see [Installing](#installing)) and restart Shoko.
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

See [Configuration](#configuration) for every setting, including how to
use `client_secret_post` or a public client instead.

## Configuration

All settings are on the plugin's settings page in the Web UI. Changes apply
to the next login; nothing needs a restart. Logins are switched off, and the
plugin offers no login or pairing to clients, until both **Issuer URL** and
**Client ID** are set.

| Setting | Default | Environment variable |
| --- | --- | --- |
| [Issuer URL](#issuer-url) | | `SHOKO_OIDC_ISSUER` |
| [Client ID](#client-id) | | `SHOKO_OIDC_CLIENT_ID` |
| [Client Secret](#client-secret) | | `SHOKO_OIDC_CLIENT_SECRET` |
| [Token Endpoint Auth Method](#token-endpoint-auth-method) | `ClientSecretBasic` | |
| [Scopes](#scopes) | `openid profile email` | |
| [Public URL](#public-url) | | `SHOKO_OIDC_PUBLIC_URL` |
| [Web UI Session Lifetime (Days)](#web-ui-session-lifetime-days) | `30` | |
| [Web UI Device Name](#web-ui-device-name) | `web-ui (oidc)` | |
| [Remember Login](#remember-login) | on | |
| [Web UI Path](#web-ui-path) | `/webui` | |
| [Enable Device Pairing](#enable-device-pairing) | on | |
| [Pairing Window (Minutes)](#pairing-window-minutes) | `10` | |
| [Paired Device Key Lifetime (Days)](#paired-device-key-lifetime-days) | `0` | |
| [User Mappings](#user-mappings) | none | |

A setting with an environment variable is read from it when the variable is
set, and can still be changed on the settings page afterwards.

### The identity provider

#### Issuer URL

The provider's issuer, e.g. `https://auth.example.com`. The plugin reads
`<issuer>/.well-known/openid-configuration` and the signing keys it points
to, and keeps both for an hour. Changing the issuer reads them again on the
next login.

The `issuer` in the discovery document has to be this URL exactly (a
trailing slash is ignored), or every login fails with a message naming
the issuer the provider uses. Copy that one into this setting.

ID tokens have to be signed with RS256, RS384, RS512, PS256, PS384, PS512,
ES256, ES384 or ES512. Authelia's default, RS256, works. HMAC-signed tokens
(HS256) and unsigned tokens are refused. Shoko's and the provider's clocks
may disagree by up to two minutes.

#### Client ID

The `client_id` of the client registered with the provider. It is also the
audience the ID token has to be issued to.

#### Client Secret

The client secret in plain text, which is what the plugin sends. Authelia
stores only a hash of it in its `client_secret`: generate the secret and its
hash with `authelia crypto hash generate pbkdf2 --random`, put the hash in
Authelia's configuration and the plain-text secret here.

Leave it empty for a public client (one without a secret). The plugin then
sends only its `client_id` in the token request; PKCE still protects the
login. In Authelia, a public client needs `public: true` and
`token_endpoint_auth_method: 'none'`, and no `client_secret`:

```yaml
- client_id: 'shoko'
  client_name: 'Shoko'
  public: true
  token_endpoint_auth_method: 'none'
  require_pkce: true
  pkce_challenge_method: 'S256'
  # redirect_uris, scopes and so on as in the example above
```

#### Token Endpoint Auth Method

How the plugin proves who it is when it exchanges the login code for
tokens. It has to match `token_endpoint_auth_method` on the provider's
client, or the provider answers `invalid_client`.

- **`ClientSecretBasic`** (`client_secret_basic`): the client ID and secret
  go in an `Authorization: Basic` header, each form-encoded first, as RFC
  6749 asks.
- **`ClientSecretPost`** (`client_secret_post`): the client ID and secret go
  in the request body as `client_id` and `client_secret`. Use it for a
  provider, or a client, set up for `client_secret_post`.

To switch to `client_secret_post` with Authelia, change the client to

```yaml
  token_endpoint_auth_method: 'client_secret_post'
```

restart Authelia, then set **Token Endpoint Auth Method** to
`ClientSecretPost` and save. The example client on the **User Mappings**
page follows this setting, and shows a public client when **Client
Secret** is empty.

The setting is ignored when **Client Secret** is empty. `client_secret_jwt`
and `private_key_jwt` are not supported.

#### Scopes

The scopes asked for, separated by spaces. `openid` is always added, even
if left out. Only the `sub` claim decides who signs in; `profile` and
`email` are asked for so the **User Mappings** page can show a username,
name and email next to a subject that is not mapped yet. Without them, an
unmapped subject shows as just its `sub`.

When the ID token leaves those claims out, as Authelia's does by default,
the plugin asks the provider's user info endpoint for them. A failure there
does not fail the login.

Each scope also has to be allowed in the provider's client (`scopes` in
Authelia), or the provider refuses the login.

#### Public URL

The address browsers reach Shoko on, e.g. `https://shoko.example.com`. The
redirect URI is this plus `/plugin/OIDC/callback`, and it has to be
registered with the provider exactly as the **User Mappings** page shows it.

Shoko does not read `X-Forwarded-*` headers, so when this is empty the
redirect URI is built from the address the request reached Shoko on. Behind
a reverse proxy that is usually the internal address, so set this. If Shoko
is served from a sub-path, include it, e.g. `https://example.com/shoko`.

### Web UI sessions

#### Web UI Session Lifetime (Days)

How long the API key handed to the Web UI after a login stays valid,
from 0 to 3650 days. Every login mints a new key.

Set to 0 for a key that never expires. A non-expiring key is shared by
every login of the same user under the same device name, the way a password
login's key is. Shoko refuses to create a non-expiring key from a session
whose own key expires, so set this to 0 if you create API keys from the Web
UI.

Removing a mapping stops new logins only. Revoke the keys already handed
out from the Web UI's API key settings, where they are listed under the
**Web UI Device Name**.

#### Web UI Device Name

The device name the Web UI's API keys are listed under, so they can be told
apart from password logins and revoked together. Cannot be empty.

#### Remember Login

Whether the Web UI stays logged in after the browser is closed, like the
**Remember Me** box on the password login. Off, the session ends when the
tab or browser is closed; the API key itself stays valid until it expires
or is revoked.

#### Web UI Path

The path the Web UI is served from, matching the server's own Web UI path.
After a login, the browser is sent here. A `?redirectTo=` on
`/plugin/OIDC/login` is only followed when it is a path inside this one, so
a link cannot send a fresh session anywhere else. Has to start with `/`.

If you change it, change `@match` in the [userscript](#a-login-button-for-the-web-ui)
to the same path.

### Device pairing

See [Pairing a device](#pairing-a-device) for how pairing works.

#### Enable Device Pairing

Whether devices can ask to be paired. Off, devices can no longer start
pairing, codes can no longer be entered or approved, and the plugin stops
offering pairing to clients.

#### Pairing Window (Minutes)

How long a device's code can be approved for, from 1 to 60 minutes. The
device's poll answers `Expired` after that.

#### Paired Device Key Lifetime (Days)

How long the API key handed to a paired device stays valid, from 0 to 3650
days. 0, the default, never expires; as with Web UI sessions, a
non-expiring key is shared by every pairing of the same user with the same
device name.

### User Mappings

Which provider subject signs in as which Shoko user. A subject that is not
listed cannot sign in. Each mapping has:

- **Subject**: the `sub` claim, matched exactly (case included) after
  trimming spaces. For Authelia, an opaque UUID per user. Each subject can
  be mapped once.
- **Shoko User ID**: the Shoko user it signs in as. Several subjects may
  map to the same user.
- **Note**: for your own reference, e.g. who the subject is.

The **User Mappings** page is the easier way to edit them: it lists the
subjects that tried to sign in and the Shoko users to pick from.

## A login button for the Web UI

The Web UI's login page has no button for the plugin. The userscript in
[`userscripts/shoko-sso-button.user.js`](userscripts/shoko-sso-button.user.js)
adds a **Login with SSO** button under the password form, which opens
`/plugin/OIDC/login` and keeps any `?redirectTo=` from the Web UI.

To install it, put a userscript manager such as Tampermonkey or
Violentmonkey in your browser, then open
[the raw script](https://raw.githubusercontent.com/acoffeee/Shoko.Plugin.Oidc/master/userscripts/shoko-sso-button.user.js);
the manager offers to install it.

It runs on every page whose path contains `/webui/`. To keep it to your own
server, change its `@match` line to your Shoko address, e.g.
`https://shoko.example.com/webui/*`.

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
it. See [RELEASING.md](RELEASING.md) for how releases are made.
