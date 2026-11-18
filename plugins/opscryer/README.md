# @internal/backstage-plugin-opscryer

Frontend plugin that embeds the [OpsCryer](https://github.com/nahallacman/opscryer) browser (Port :8088) into Backstage as a page at `/opscryer`, reachable from the sidebar.

This plugin lives in the OpsCryer repository and is consumed by the Backstage 2.0 portal integration. It follows the same industrial-grade pattern as the existing `plugins/opscryer-browser` plugin: `createFrontendPlugin` + `PageBlueprint`, config-driven via `integrations.opscryer[].baseUrl`, with a rich Material UI component and a launch button.

## What it does

- Registers an `/opscryer` page in Backstage (`page:opscryer` route ref + `PageBlueprint` extension)
- Renders the OpsCryer browser inside a responsive iframe card
- Adds a "Launch in new tab" button and a "Read-only integration" chip
- Reads the browser origin from `app-config.yaml` under `integrations.opscryer[].baseUrl`, defaulting to `http://localhost:8088`

## Install

In the Backstage app workspace:

```bash
yarn --cwd packages/app add @internal/backstage-plugin-opscryer
```

## Register

`packages/app/src/App.tsx`:

```tsx
import opscryerBrowserPlugin from '@internal/backstage-plugin-opscryer';

export default createApp({
  features: [/* ... */, opscryerBrowserPlugin],
});
```

`packages/app/src/modules/nav/Sidebar.tsx` — add a `SidebarItem` inside the `Menu` group:

```tsx
import { rootRouteRef } from '@internal/backstage-plugin-opscryer';
// ...
<SidebarItem
  icon={() => <DashboardIcon />}
  to={rootRouteRef}
  text="OpsCryer"
/>
```

`app-config.yaml`:

```yaml
integrations:
  opscryer:
    - host: localhost
      baseUrl: http://localhost:8088

backend:
  csp:
    frame-src: ["'self'", 'http://localhost:8088']
```

## Notes

- This is a **frontend iframe integration only**. No Backstage backend plugin or Helm chart is added yet (Helm is deferred until the Backstage integration is serving).
- The iframe targets `integrations.opscryer[].baseUrl` from `app-config.yaml` (`http://localhost:8088` by default). In production, point it at the deployed OpsCryer browser and ensure its CSP allows being framed from your Backstage origin.
- Configure your VCS integration (GitLab or GitHub) in `app-config.yaml` according to your organization's standards.
