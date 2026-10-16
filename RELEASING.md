# Releasing

Releases are built by [`.github/workflows/release.yml`](.github/workflows/release.yml)
when a GitHub release is published. Nothing is built on a plain push.

## Making a release

1. Bump `<Version>` in [`source/Shoko.Plugin.Oidc.csproj`](source/Shoko.Plugin.Oidc.csproj),
   commit and push to `master`.
2. Publish a GitHub release tagged `v<Version>` (e.g. `v1.1.0`), either on
   GitHub or with:

   ```sh
   gh release create v1.1.0 --notes "What changed, for users."
   ```

   The release description becomes the release's `release_notes` in the
   manifest, so write it for people deciding whether to update.
3. Watch the **Release** run under the repository's Actions tab. When it
   passes, the release has `OpenIDConnect-v<Version>-any.zip` attached and
   the `metadata` branch has a new commit adding the release to
   `manifest.json`.

## What the workflow does

1. Fails if the tag (minus the `v`) does not match `<Version>`.
2. Fetches `manifest.json` from the `metadata` branch.
3. Runs `dotnet shoko-build` (from [`.config/dotnet-tools.json`](.config/dotnet-tools.json)),
   which builds the plugin, packs the zip, and appends the release (version,
   tag, notes, download URL and checksum) to that manifest.
4. Uploads the zip to the GitHub release.
5. Commits the updated manifest back to the `metadata` branch.

## The two manifests

- `manifest.json` on `master` is a stub: the plugin's identity with no
  releases. The workflow never changes it.
- `manifest.json` on `metadata` is the published one. Users point Shoko at
  `https://raw.githubusercontent.com/acoffeee/Shoko.Plugin.Oidc/metadata/manifest.json`.

A change to the plugin's identity (`name`, `overview`, `authors`,
`repository_url`, `icon_url`, `thumbnail_url`, ...) has to be made on the
`metadata` branch to reach users; make it on `master` too to keep the two
in step. Never edit the `releases` list by hand unless fixing a mistake.

The `id` must match `PluginGuid` in [`source/Constants.cs`](source/Constants.cs).
Do not change it once a release is out: Shoko would see a different plugin
and installs would stop updating.

## Testing a release locally

This runs the same build into a scratch folder without touching the real
manifest:

```sh
dotnet tool restore
cp manifest.json /tmp/manifest.json
cd source
dotnet shoko-build --configuration Release --channel Stable --tag v1.0.0 \
  --manifest /tmp/manifest.json \
  --output "/tmp/dist/{name}-{tag}-{runtime}.zip" \
  --url "https://github.com/acoffeee/Shoko.Plugin.Oidc/releases/download/{tag}/{name}-{tag}-{runtime}.zip"
```

## Fixing a failed release

If the workflow fails before uploading, fix the cause, then delete the
release and its tag and publish it again:

```sh
gh release delete v1.1.0 --cleanup-tag
```

If it uploaded the zip but failed to update `metadata`, delete the release
the same way before publishing it again, or the upload step fails on the
existing zip.
