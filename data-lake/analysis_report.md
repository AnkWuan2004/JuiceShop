# Security Analysis Report (Tuần 3)

- Rows quét: **93** → nhóm: **74** → findings: **74** (drop no-evidence: 0)
- Phân bố: high **15** · medium **30** · low **29**
- LLM mode: **MOCK (offline)**

| # | Severity | Name | Location | Tools | Conf |
|---|---|---|---|---|---|
| F001 | high | yaml.github-actions.security.run-shell-injec | `juice-shop/.github/workflows/update-challenges-w` | Semgrep | 0.65 |
| F002 | high | yaml.github-actions.security.run-shell-injec | `juice-shop/.github/workflows/update-challenges-w` | Semgrep | 0.65 |
| F003 | high | generic.secrets.security.detected-jwt-token. | `juice-shop/frontend/src/app/last-login-ip/last-l` | Semgrep | 0.65 |
| F004 | high | yaml.github-actions.security.gha-curl-pipe-s | `juice-shop/.github/workflows/ci.yml` | Semgrep | 0.6 |
| F005 | high | yaml.github-actions.security.run-shell-injec | `juice-shop/.github/workflows/update-challenges-e` | Semgrep | 0.6 |
| F006 | high | javascript.sequelize.security.audit.sequeliz | `juice-shop/data/static/codefixes/dbSchemaChallen` | Semgrep | 0.6 |
| F007 | high | javascript.sequelize.security.audit.sequeliz | `juice-shop/data/static/codefixes/dbSchemaChallen` | Semgrep | 0.6 |
| F008 | high | javascript.sequelize.security.audit.sequeliz | `juice-shop/data/static/codefixes/unionSqlInjecti` | Semgrep | 0.6 |
| F009 | high | javascript.sequelize.security.audit.sequeliz | `juice-shop/data/static/codefixes/unionSqlInjecti` | Semgrep | 0.6 |
| F010 | high | generic.secrets.security.detected-generic-se | `juice-shop/data/static/users.yml` | Semgrep | 0.6 |
| F011 | high | generic.secrets.security.detected-jwt-token. | `juice-shop/frontend/src/app/app.guard.spec.ts` | Semgrep | 0.6 |
| F012 | high | javascript.express.security.audit.remote-pro | `juice-shop/routes/currentUser.ts` | Semgrep | 0.6 |
| F013 | high | javascript.sequelize.security.audit.sequeliz | `juice-shop/routes/login.ts` | Semgrep | 0.6 |
| F014 | high | javascript.sequelize.security.audit.sequeliz | `juice-shop/routes/search.ts` | Semgrep | 0.6 |
| F015 | high | javascript.lang.security.audit.code-string-c | `juice-shop/routes/userProfile.ts` | Semgrep | 0.6 |
| F016 | medium | javascript.express.security.audit.express-ch | `juice-shop/server.ts` | Semgrep | 0.6 |
| F017 | medium | yaml.github-actions.security.github-actions- | `juice-shop/.github/workflows/codeql-analysis.yml` | Semgrep | 0.6 |
| F018 | medium | yaml.github-actions.security.github-actions- | `juice-shop/.github/workflows/image_actions.yml` | Semgrep | 0.6 |
| F019 | medium | javascript.lang.security.audit.detect-non-li | `juice-shop/lib/codingChallenges.ts` | Semgrep | 0.5 |
| F020 | medium | javascript.lang.security.audit.hardcoded-hma | `juice-shop/lib/insecurity.ts` | Semgrep | 0.5 |
| F021 | medium | javascript.lang.security.audit.unknown-value | `juice-shop/routes/videoHandler.ts` | Semgrep | 0.5 |
| F022 | medium | yaml.github-actions.security.github-actions- | `juice-shop/.github/workflows/ci.yml` | Semgrep | 0.45 |
| F023 | medium | package_managers.npm.npm-missing-minimum-rel | `juice-shop/.npmrc` | Semgrep | 0.45 |
| F024 | medium | package_managers.npm.npm-missing-minimum-rel | `juice-shop/frontend/.npmrc` | Semgrep | 0.45 |
| F025 | medium | javascript.lang.security.audit.prototype-pol | `juice-shop/frontend/src/hacking-instructor/helpe` | Semgrep | 0.45 |
| F026 | medium | javascript.jsonwebtoken.security.jwt-hardcod | `juice-shop/lib/insecurity.ts` | Semgrep | 0.45 |
| F027 | medium | javascript.express.security.audit.express-de | `juice-shop/routes/b2bOrder.ts` | Semgrep | 0.45 |
| F028 | medium | javascript.browser.security.eval-detected.ev | `juice-shop/routes/captcha.ts` | Semgrep | 0.45 |
| F029 | medium | javascript.express.security.audit.express-re | `juice-shop/routes/fileServer.ts` | Semgrep | 0.45 |
| F030 | medium | javascript.express.security.audit.express-re | `juice-shop/routes/keyServer.ts` | Semgrep | 0.45 |
| F031 | medium | javascript.express.security.audit.express-re | `juice-shop/routes/logfileServer.ts` | Semgrep | 0.45 |
| F032 | medium | javascript.express.security.audit.express-re | `juice-shop/routes/quarantineServer.ts` | Semgrep | 0.45 |
| F033 | medium | javascript.express.security.audit.express-op | `juice-shop/routes/redirect.ts` | Semgrep | 0.45 |
| F034 | medium | javascript.browser.security.eval-detected.ev | `juice-shop/routes/userProfile.ts` | Semgrep | 0.45 |
| F035 | medium | javascript.express.security.audit.xss.pug.ex | `juice-shop/views/promotionVideo.pug` | Semgrep | 0.45 |
| F036 | medium | Content Security Policy (CSP) Header Not Set | `localhost:3000` | OWASP | 0.45 |
| F037 | medium | Content Security Policy (CSP) Header Not Set | `localhost:3000/ftp/coupons_2013.md.bak` | OWASP | 0.45 |
| F038 | medium | Content Security Policy (CSP) Header Not Set | `localhost:3000/ftp/eastere.gg` | OWASP | 0.45 |
| F039 | medium | Content Security Policy (CSP) Header Not Set | `localhost:3000/ftp/encrypt.pyc` | OWASP | 0.45 |
| F040 | medium | Content Security Policy (CSP) Header Not Set | `localhost:3000/sitemap.xml` | OWASP | 0.45 |
| F041 | medium | Cross-Domain Misconfiguration | `localhost:3000` | OWASP | 0.45 |
| F042 | medium | Cross-Domain Misconfiguration | `localhost:3000/assets/public/favicon_js.ico` | OWASP | 0.45 |
| F043 | medium | Cross-Domain Misconfiguration | `localhost:3000/chunk-5K74DZ2F.js` | OWASP | 0.45 |
| F044 | medium | Cross-Domain Misconfiguration | `localhost:3000/robots.txt` | OWASP | 0.45 |
| F045 | medium | Cross-Domain Misconfiguration | `localhost:3000/sitemap.xml` | OWASP | 0.45 |
| F046 | low | javascript.audit.detect-replaceall-sanitizat | `juice-shop/data/static/codefixes/restfulXssChall` | Semgrep | 0.35 |
| F047 | low | Cross-Origin-Embedder-Policy Header Missing  | `localhost:3000` | OWASP | 0.35 |
| F048 | low | Cross-Origin-Opener-Policy Header Missing or | `localhost:3000` | OWASP | 0.35 |
| F049 | low | Timestamp Disclosure - Unix | `localhost:3000` | OWASP | 0.35 |
| F050 | low | Timestamp Disclosure - Unix | `localhost:3000/sitemap.xml` | OWASP | 0.35 |
| F051 | low | Modern Web Application | `localhost:3000` | OWASP | 0.35 |
| F052 | low | javascript.lang.security.audit.unsafe-format | `juice-shop/server.ts` | Semgrep | 0.3 |
| F053 | low | Cross-Origin-Embedder-Policy Header Missing  | `localhost:3000/ftp` | OWASP | 0.3 |
| F054 | low | Cross-Origin-Embedder-Policy Header Missing  | `localhost:3000/juice-shop/build/routes/fileServe` | OWASP | 0.3 |
| F055 | low | Cross-Origin-Embedder-Policy Header Missing  | `localhost:3000/sitemap.xml` | OWASP | 0.3 |
| F056 | low | Cross-Origin-Opener-Policy Header Missing or | `localhost:3000/ftp` | OWASP | 0.3 |
| F057 | low | Cross-Origin-Opener-Policy Header Missing or | `localhost:3000/juice-shop/node_modules/express/l` | OWASP | 0.3 |
| F058 | low | Cross-Origin-Opener-Policy Header Missing or | `localhost:3000/sitemap.xml` | OWASP | 0.3 |
| F059 | low | Dangerous JS Functions | `localhost:3000/main.js` | OWASP | 0.3 |
| F060 | low | Deprecated Feature Policy Header Set | `localhost:3000` | OWASP | 0.3 |
| F061 | low | Deprecated Feature Policy Header Set | `localhost:3000/chunk-5K74DZ2F.js` | OWASP | 0.3 |
| F062 | low | Deprecated Feature Policy Header Set | `localhost:3000/chunk-PX7UKXVL.js` | OWASP | 0.3 |
| F063 | low | Deprecated Feature Policy Header Set | `localhost:3000/chunk-VS3A3LTT.js` | OWASP | 0.3 |
| F064 | low | Deprecated Feature Policy Header Set | `localhost:3000/sitemap.xml` | OWASP | 0.3 |
| F065 | low | Timestamp Disclosure - Unix | `localhost:3000/styles.css` | OWASP | 0.3 |
| F066 | low | Modern Web Application | `localhost:3000/juice-shop/build/routes/fileServe` | OWASP | 0.3 |
| F067 | low | Modern Web Application | `localhost:3000/juice-shop/node_modules/express/l` | OWASP | 0.3 |
| F068 | low | Modern Web Application | `localhost:3000/sitemap.xml` | OWASP | 0.3 |
| F069 | low | Storable and Cacheable Content | `localhost:3000/robots.txt` | OWASP | 0.3 |
| F070 | low | Storable but Non-Cacheable Content | `localhost:3000` | OWASP | 0.3 |
| F071 | low | Storable but Non-Cacheable Content | `localhost:3000/assets/public/favicon_js.ico` | OWASP | 0.3 |
| F072 | low | Storable but Non-Cacheable Content | `localhost:3000/chunk-5K74DZ2F.js` | OWASP | 0.3 |
| F073 | low | Storable but Non-Cacheable Content | `localhost:3000/sitemap.xml` | OWASP | 0.3 |
| F074 | low | Storable but Non-Cacheable Content | `localhost:3000/styles.css` | OWASP | 0.3 |
