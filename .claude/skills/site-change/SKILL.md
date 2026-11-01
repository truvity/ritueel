---
name: site-change
description: Use when changing the ritueel site itself, not just a page's words - files in site/, site/public/ (headers, redirects), the theme, a home page or a section's first screen, the link check, or the deploy workflow.
---

Read "Changing the site" in `docs/contributing/pages.md` and follow it, with "The site" in `docs/contributing/tools.md` for how the build, the headers and the deploy work. Judge the change against the mission in `docs/contributing/design.md`.

Checklist:

- [ ] HSTS in `site/public/_headers` is not lowered (one year, `includeSubDomains`, `preload`), and no name is served over plain HTTP.
- [ ] The Content-Security-Policy stays `'self'` plus Cloudflare Web Analytics only: `https://static.cloudflareinsights.com` in `script-src` and `https://cloudflareinsights.com` in `connect-src`. Inline scripts are listed by hash; `site/scripts/check-csp.mjs` passes.
- [ ] No remote asset: no font, script, image, style or embed from another host. Inline SVG, or a CC0 icon (simple-icons) inlined and used nominatively, or a file in the repository.
- [ ] A moved or renamed page has a 301 line in `site/public/_redirects` in the same pull request.
- [ ] The link check stays bounded: `lychee` with a timeout, bounded retries and redirects, a wall-clock `timeout` around the run, and `-v`. A host that loops on redirects is excluded in `lychee.toml`. A job that runs long is a finding, not a rerun.
- [ ] A home page, or the first screen of a section, starts from the reader's pain, then the mission, then what the project does about each pain, with honest status.
- [ ] You built the site, served it, and took screenshots with headless Chrome at 1440 px and 390 px, in light and dark. You looked at all four, fixed what was off, and found no horizontal scroll at 375 px. Say so in the pull request.
- [ ] `devbox run -- just site-lint`, `site-build` and `check-rules` pass; CI is green.
- [ ] After the maintainer merges and the Site deploy is green, check with `curl` and report the result:

  ```sh
  curl -sI https://ritueel.id/learn/ | grep -iE '^(HTTP|strict-transport-security|content-security-policy)'
  curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' https://ritueel.id/<old-path>/
  ```

  The page answers 200, each moved page answers 301 to its new address, and both headers are intact.
