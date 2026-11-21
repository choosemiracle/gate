# choosemiracle/gate deployment notes

This fork is configured for the CheckSocks5 Worker.

## Required Actions secrets

Add these two repository secrets under **Settings → Secrets and variables → Actions**:

- `DOMAIN`: hostname of your deployed CheckSocks5 Worker, without `https://` or a path.
- `CHECK_TOKEN`: the same secret value configured as the Worker `CHECK_TOKEN`.

## GitHub Pages

Set **Settings → Pages → Build and deployment → Source** to **GitHub Actions**.

## Automation

The `VPN Gate Node Check` workflow runs every 30 minutes and can also be started manually from the Actions tab. It publishes `public/nodes.txt`, `public/data.json`, and `public/index.html`.

The workflow currently uses the two previously tested Cloudflare edge addresses as the front-door pool:

- `104.17.99.242:443`
- `104.17.212.202:443`

These are retained as known starting points, not a guarantee of current best performance. Update `HOSTS_ENTRY` in `.github/workflows/check.yml` if subsequent measurements identify better addresses.

## Connect to edgetunnel

After the first successful Pages deployment, set the edgetunnel admin panel's **自定义优选 IP** field to:

`https://choosemiracle.github.io/gate/nodes.txt`

Keep the existing edgetunnel UUID, domain, KV binding, and subscription token unchanged.
