# Sibaihua University — Chiang Mai Campus

> A single-page showcase website for **Sibaihua University, Chiang Mai Campus**.
> Motto: *One World, One Dream.*

This repository contains the official homepage of Sibaihua University's Chiang Mai Campus. The entire site is delivered as a **single static file** — `index.html` — with a pre-built Tailwind CSS bundle (compiled locally and committed as `css/tailwind.css`), no backend, and no framework dependencies required at runtime.

---

## Overview

| | |
|---|---|
| **Site title** | Sibaihua University, Chiang Mai Campus |
| **Live site** | https://sibaihua.com |
| **Repository** | https://github.com/sibaihua/Sibaihua-University-Chiang-Mai-Campus |
| **Delivery** | One static `index.html` (no bundler / no server-side code) |
| **Deployment** | Cloudflare Pages (auto-deploys on push to `main`) |
| **Stack** | HTML5 · Tailwind CSS (local production build) · Vue 3 (CDN) · FontAwesome (CDN) |

---

## Quick start

The site is static — just open the file or serve the folder:

```bash
# Option A: open directly
open index.html            # or double-click in a file manager

# Option B: serve locally (any static server)
python3 -m http.server 8080
# then visit http://localhost:8080
```

No framework dependencies are required at runtime. To **rebuild the Tailwind CSS** after editing classes, Node.js + the Tailwind CLI are needed (see *Building the CSS*).

---

## Tech stack

Vue and FontAwesome are loaded from public CDNs; Tailwind CSS is compiled ahead of time into a static bundle:

- **Tailwind CSS** — compiled with the Tailwind CLI into `css/tailwind.css` (minified, committed). The `brand` color palette is defined in `tailwind.config.js` (`#1E3A5F` and variants). See *Building the CSS* below.
- **Vue 3** (`unpkg.com/vue@3`) — used only for lightweight client interactions (mobile menu toggle, scroll-state styling). The app mounts on `#app`.
- **FontAwesome 6.4** (`cdnjs.cloudflare.com`) — icons.
- **Background images & favicon** — served from `cdn.sibh.cn`.

---

## Building the CSS

The site no longer uses the Tailwind Play CDN (`cdn.tailwindcss.com`) in production. Styles are compiled to a static file so the page works without a runtime CDN dependency for CSS.

```bash
# install dev dependency (Tailwind CLI) — one time
npm install

# rebuild the production stylesheet (output: css/tailwind.css)
npm run build:css

# during development, watch for changes:
npm run watch:css
```

- Source entry: `src/tailwind.css` (the three `@tailwind` directives).
- Scan target: `tailwind.config.js` → `content: ["./index.html"]` (only the deployed page is scanned).
- The compiled `css/tailwind.css` is **committed** and served directly by Cloudflare Pages — there is no build step on the hosting side.
- ⚠️ After adding or changing any Tailwind class in `index.html`, **rebuild `css/tailwind.css` and commit it**, otherwise the new classes will not be styled.

---

## Page structure

The page is composed of full-height, scroll-snapping sections. Each is marked with a `<!-- Section N -->` comment in `index.html`:

| Section | Id | Content |
|---|---|---|
| 1 · Hero Banner | — | Full-screen banner with the motto *"One World, One Dream"* and positioning line. |
| 2 · About University | `#about` | Mission, vision, and the Sibaihua E-Campus digital gateway. |
| 3 · Faculty of Science | `#science` | Featured faculty with imagery and research areas. |
| 4 · Academic Faculties | `#faculties` | Overview of all faculties and schools. |
| 5 · Campuses & Locations | `#campuses` | Campus/office locations **plus** the institutional bodies (University Council, Finance Committee, Supervisory Committee, President's Office). |
| 6 · University Charter | `#charter` | Constitutive instruments and standing principles (Faculties, Academic Freedom, Student Rights, Institutional Principles). |
| 7 · University Identity | `#identity` | A coherent one-screen definition of the University (name, nature, campus, location, digital campus, motto). |
| 8 · Footer | — | Official contacts & services: President's Office, E-Campus, Campus Mail. |

> **Naming convention (current):** the locations module is titled *"Campuses & Locations"* (emphasis on place), and the governance module is titled *"University Institutions"* (emphasis on bodies/units).

---

## Authentication (E-Campus SSO)

The E-Campus link in the navigation points to the external portal `https://e.sibaihua.com`.

The `index.html` `<script>` block still contains a **legacy, unused** OAuth 2.0 *Authorization Code + PKCE* implementation (`login()`, `handleCallback()`, and PKCE helpers). It is a public-client, browser-only flow — there is **no `client_secret`** in the frontend. This code is currently **not referenced by the UI** (the nav E-Campus entry is a plain external link) and is retained only as a reference snippet.

---

## Editing guidelines

- **Single source of truth:** everything lives in `index.html`. Edit text, sections, and styles there.
- **Images:** swap CDN URLs in the `<style>` block (`.hero-bg`, `.campuses-bg`) or in `<img>` tags directly.
- **Brand colors:** adjust the `brand` palette in `tailwind.config.js`, then run `npm run build:css` and commit the regenerated `css/tailwind.css`.
- **Keep it lean:** the site is intentionally content-light; avoid stacking duplicate or redundant copy across sections.

---

## Deployment

The site is hosted on **Cloudflare Pages** and connected to this GitHub repository.

- Pushing to the `main` branch triggers an automatic rebuild and redeploy (typically ~1 minute).
- No build command or output directory is needed — Cloudflare serves `index.html` directly.

```bash
git add -A
git commit -m "Describe your change"
git push origin main      # → Cloudflare Pages auto-deploys
```

After pushing, allow ~60 seconds for the new version to appear on https://sibaihua.com.

---

## License

This is a fictional virtual-university showcase. All rights reserved © 2026 Sibaihua University.
