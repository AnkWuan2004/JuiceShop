# Recon vs Manual Attack Surface (Tuần 4)

Agent endpoints: **20** | Manual note paths: **20**

## Overlap

| Path |
|---|
| `/api/Feedbacks` |
| `/api/Users` |
| `/ftp` |
| `/metrics` |
| `/rest/basket/{id}` |
| `/rest/products/search` |

## Chỉ agent

| Path |
|---|
| `/` |
| `/assets/public/favicon_js.ico` |
| `/chunk-5K74DZ2F.js` |
| `/chunk-PX7UKXVL.js` |
| `/chunk-VS3A3LTT.js` |
| `/ftp/eastere.gg` |
| `/ftp/encrypt.pyc` |
| `/juice-shop/build/routes/fileServer.js:69:18` |
| `/juice-shop/node_modules/express/lib/router/index.js:286:9` |
| `/main.js` |
| `/robots.txt` |
| `/sitemap.xml` |
| `/styles.css` |

## Chỉ manual note

| Path |
|---|
| `/#/administration` |
| `/api/Challenges` |
| `/api/Products` |
| `/api/Quantitys` |
| `/encryptionkeys` |
| `/rest/admin` |
| `/rest/admin/application-configuration` |
| `/rest/basket/{id}/checkout` |
| `/rest/memories` |
| `/rest/products/{id}/reviews` |
| `/rest/user/change-password` |
| `/rest/user/login` |
| `/rest/user/reset-password` |
| `/rest/user/security-question` |

## Kết luận

- Overlap: 6
- Agent-only: 13
- Manual-only: 14 (kỳ vọng — note thủ công rộng hơn DB sample)
- Map source: `vuln_data.db+baseline`, vuln_rows=40
