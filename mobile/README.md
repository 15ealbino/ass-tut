# CYBER//ASM — Mobile

A native iOS **and** Android app for the Assembly Tutorial. It mirrors the web
frontend: write Python, compile it, and trace each line through the generated
**C** and **x86 Assembly** with color-coded, tap-to-highlight cross-references.
It also ships the **VULN//LAB** example catalogue of classic memory-corruption
patterns.

Built with **Expo** (React Native + TypeScript), so a single codebase runs on
both platforms.

```
mobile/
  App.tsx                 Navigation + auth gating (signed-out → Login/Register, signed-in → Editor)
  index.ts                Expo entry point
  app.json                Expo config (name, icons, bundle IDs, API URL, OTA update policy)
  eas.json                EAS Build/Submit/Update profiles
  src/
    api.ts                fetch wrapper for /auth/*, /compile, /health
    config.ts             Resolves the backend base URL (in-app override → app.json → prod default)
    theme.ts              CYBER//ASM dark palette + monospace font stack
    context/AuthContext.tsx   JWT stored in the device keychain via expo-secure-store
    screens/
      LoginScreen.tsx     Sign in (+ collapsible "Server" field to point at any backend)
      RegisterScreen.tsx  Create account
      EditorScreen.tsx    The main screen: editor, method toggle, C/ASM panes, legend, VULN//LAB
    components/CodePane.tsx    Read-only pane: color stripe + line numbers + tap-to-trace
    data/snippets.ts      Starter code + curated vulnerability examples
```

## What it talks to

The app is a **client only** — it uses the same backend as the web app
(`/auth/register`, `/auth/login`, `/compile`). It needs an **absolute** URL to
that backend (the web app uses a same-origin `/api` proxy, which a mobile app
has no equivalent for).

The URL is resolved in this order:

1. A value the user typed into the **Server** field on the login screen
   (persisted on-device).
2. `expo.extra.apiBaseUrl` in `app.json` — baked into each build.
3. The hard fallback `https://assembly-tutorial.com/api` in `src/config.ts`.

> Set `expo.extra.apiBaseUrl` in `app.json` to your own backend before you build
> for release. Your backend must allow the app's requests — CORS does **not**
> apply to native apps, but make sure the domain is reachable over HTTPS.

---

## Prerequisites

- **Node.js 18+** and npm.
- The **Expo Go** app on your phone (from the App Store / Play Store) for quick
  local testing, OR an iOS Simulator / Android Emulator.
- An **[Expo account](https://expo.dev/signup)** (free) — required for cloud
  builds and OTA updates.
- **EAS CLI**: `npm install -g eas-cli` (or use `npx eas-cli` everywhere).

```bash
cd mobile
npm install
```

---

## Run it locally (development)

```bash
cd mobile
npm start
```

This starts the Metro bundler and prints a QR code:

- **Phone**: open **Expo Go** and scan the QR code.
- **iOS Simulator**: press `i` in the terminal (macOS + Xcode required).
- **Android Emulator**: press `a` (Android Studio required).

Because your phone and the backend are on different networks, the **default
server is the production API** (`https://assembly-tutorial.com/api`). To test
against a backend on your laptop:

1. Run the backend so it's reachable on your LAN, e.g.
   `uvicorn app.main:app --host 0.0.0.0 --port 8000`.
2. On the login screen tap **▸ SERVER** and enter
   `http://<your-laptop-LAN-IP>:8000` (find it with `ipconfig`/`ip addr`).
   `localhost` will **not** work from a physical phone — it points at the phone.
3. Note: the production backend serves the API under `/api`; a bare local
   uvicorn serves routes at the root (no `/api` prefix).

---

## Host the web build on the VM (browser access for anyone)

The same codebase also runs in a **browser** via `react-native-web`, so you can
serve it as a static site from the existing Oracle VM production stack — anyone
opens a URL, no app install, no Expo Go. It's wired into the repo's
docker-compose + Caddy setup and served at:

```
https://assembly-tutorial.com/app/
```

### How it's wired

- **`mobile/Dockerfile.web`** — builds `npx expo export --platform web` and
  serves the static output with nginx. The export uses `expo.experiments.baseUrl
  = "/app"` (in `app.json`) so every asset is referenced under `/app/...`.
- **`mobileweb` service** — the nginx container above (internal only; no host
  port). In the **prod/http** stacks it runs a **prebuilt image pulled from
  GHCR** (built by CI, see below) rather than building on the VM; the base
  `docker-compose.yml` keeps a `build:` section only for local dev.
- **`Caddyfile` / `Caddyfile.http`** — route `/app/*` → `mobileweb`, everything
  else (including `/api`) → the main `frontend` container.
- **Same-origin API** — on the web build, `src/config.ts` points the API at a
  relative `/api`, which the main frontend nginx already proxies to the backend.
  Because it's the same origin, there are **no CORS changes** to the backend.
- **Auth token** — `src/storage.ts` uses `localStorage` on web (the native
  keychain isn't available in a browser). Not encrypted at rest; fine for this
  app's JWT.

### The image is built by CI, not on the VM

The production VM is a small (~1 GB RAM) box, and building the Expo/Metro bundle
on it once **OOM-killed the whole stack**. So the image is built off-VM by
GitHub Actions and the VM only pulls it:

- **`.github/workflows/mobileweb.yml`** — on any push to `master` that touches
  `mobile/**`, it builds `mobile/Dockerfile.web` and pushes
  `ghcr.io/15ealbino/ass-tut-mobileweb:latest` (plus a `:<sha>` tag) to GHCR,
  with layer caching. No secrets needed — it uses the built-in `GITHUB_TOKEN`.
- **prod/http compose overlays** set `image: ghcr.io/…/ass-tut-mobileweb:latest`
  + `pull_policy: always` and reset `build`, so `make prod` **pulls** the image
  instead of compiling on the VM.

**One-time setup:** after the first workflow run, make the GHCR package
**public** so the VM can pull it without credentials —
`github.com/users/15ealbino/packages/container/ass-tut-mobileweb/settings` →
*Change visibility* → *Public*. (The image is just a static web bundle + nginx,
no secrets.) If you'd rather keep it private, instead run
`echo <PAT> | docker login ghcr.io -u 15ealbino --password-stdin` on the VM once,
using a PAT with `read:packages`.

### Deploy it

```bash
# 1. Push your change; wait for the "Build mobileweb image" Action to go green.
# 2. On the VM (or via the `deployer` agent):
cd ~/ass-tut
git pull --rebase origin master
make prod            # pulls latest mobileweb image, rebuilds frontend, reloads Caddy
```

Verify:

```bash
curl -fsSI https://assembly-tutorial.com/app/ | head -3   # expect HTTP/2 200
```

> Order matters: deploy **after** CI has published the new image, otherwise the
> VM pulls the previous `latest`. `make prod` no longer builds the bundle on the
> VM, so it's fast and can't OOM the box.

### Update it

Change anything under `mobile/src/` (or its config), commit, and push to
`master`. CI rebuilds and republishes the image automatically; then deploy
(`git pull && make prod`) to pull it onto the VM. To roll back, redeploy with the
service pinned to a known-good `:<sha>` tag instead of `:latest`.

### Serve it somewhere else instead

- **Different path/subdomain**: change `expo.experiments.baseUrl` in `app.json`
  to match (e.g. `"/"` for a dedicated subdomain), rebuild, and adjust the Caddy
  route. For a subdomain like `app.assembly-tutorial.com` you'd add a Cloudflare
  DNS record → the VM IP and a matching Caddy site block; Caddy auto-issues the
  cert.
- **Static host (Netlify / Vercel / S3 / GitHub Pages)**: run
  `npx expo export --platform web` and upload `dist/`. Set `baseUrl` to match the
  host's path, and set `expo.extra.apiBaseUrl` (or the in-app Server field) to an
  absolute backend URL — a static host has no `/api` proxy, and the backend's
  CORS allow-list would then need that origin added.

---

## Deploy the mobile app

"Deploying" a mobile app means two different things, and this project supports
both:

- **Store builds** — native binaries (`.ipa` / `.aab`) submitted to the Apple
  App Store and Google Play. Needed for the first release and any change to
  native code, config, permissions, icons, or SDK version.
- **OTA updates** — JavaScript/asset-only updates pushed instantly to installed
  apps without a new store review. Used for day-to-day changes (see
  [Updating](#updating-the-mobile-app)).

### One-time setup

```bash
cd mobile
eas login                # sign in to your Expo account
eas init                 # creates the EAS project and writes its projectId into app.json
```

Set your real values in `app.json` before the first build:

- `expo.ios.bundleIdentifier` (e.g. `com.yourcompany.cyberasm`)
- `expo.android.package` (e.g. `com.yourcompany.cyberasm`)
- `expo.extra.apiBaseUrl` (your production backend)

### Build

```bash
# Shareable internal build (Android .apk you can sideload; iOS via internal distribution)
eas build --profile preview --platform android
eas build --profile preview --platform ios

# Production store builds
eas build --profile production --platform android   # → .aab for Google Play
eas build --profile production --platform ios        # → .ipa for the App Store
eas build --profile production --platform all        # both at once
```

EAS runs the build in the cloud and gives you a download link (and a QR code for
internal builds). The build profiles live in `eas.json`.

> **iOS** builds require enrollment in the **Apple Developer Program**
> ($99/yr). EAS will prompt to manage signing credentials for you.
> **Android** builds need a Google Play keystore — EAS generates and stores one
> automatically on first build.

### Submit to the stores

```bash
eas submit --profile production --platform android   # uploads the .aab to Google Play
eas submit --profile production --platform ios        # uploads the .ipa to App Store Connect
```

Then finish the listing (screenshots, description, review notes) in
**App Store Connect** / the **Google Play Console** and submit for review.

---

## Updating the mobile app

Pick the path that matches what you changed:

### 1. JS / styling / logic changes → **OTA update** (instant, no store review)

Anything under `src/` — UI, screens, API calls, business logic — ships over the
air. Users get it the next time they open the app (already-open apps get it on
the following launch).

```bash
cd mobile
eas update --branch production --message "Fix legend colors on ASM pane"
```

The `production` build profile in `eas.json` is subscribed to the `production`
channel, so a published update on that branch reaches production installs. Use a
matching branch for `preview` when testing (`eas update --branch preview ...`).

OTA updates are gated by `runtimeVersion` (set to `appVersion` policy in
`app.json`): an update only lands on installs whose native runtime is
compatible. Bump the app version + rebuild whenever you change native code.

### 2. Native / config / dependency changes → **new store build**

Rebuild and resubmit (Section [Deploy](#deploy-the-mobile-app)) when you:

- change `app.json` native config, icons, splash, permissions, bundle IDs;
- add/upgrade a native module or bump the Expo SDK;
- change `runtimeVersion`.

Typical release bump:

```bash
# 1. Raise the user-facing version
#    app.json → expo.version  (e.g. "1.0.0" → "1.1.0")
# 2. Rebuild (build/version numbers auto-increment via eas.json "autoIncrement")
eas build --profile production --platform all
# 3. Resubmit
eas submit --profile production --platform all
```

### Keeping dependencies healthy

```bash
npx expo install --check      # verify packages match the installed Expo SDK
npx expo-doctor               # broader project health check
npx expo install expo@latest  # then follow the SDK upgrade guide before bumping others
```

---

## Notes / limitations

- **Auth token**: stored in the device keychain/keystore (`expo-secure-store`),
  so the session survives app restarts — unlike the web app, which intentionally
  keeps the JWT in memory only. Tap **EXIT** in the editor header to sign out and
  clear it.
- **Fonts**: the web app uses *Fira Code*; the app falls back to each platform's
  built-in monospace face (Menlo on iOS, `monospace` on Android). To match the
  web exactly, bundle the font with `expo-font` + `useFonts` and point
  `theme.mono` at it.
- **Icons/splash**: no custom icon is committed, so Expo's default is used. Add
  `assets/icon.png` (1024×1024) and `assets/splash.png`, then reference them
  under `expo.icon` / `expo.splash.image` in `app.json` before a store release.
- The `pyghidra` compile method depends on the backend having the Ghidra
  toolchain; if it's unavailable the API returns 503 and the app surfaces the
  error.
