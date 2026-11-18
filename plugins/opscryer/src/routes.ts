import { createRouteRef } from '@backstage/core-plugin-api';

/**
 * Route ref for the OpsCryer page.
 *
 * Mounted at `/opscryer` and embeds the OpsCryer browser
 * (standalone spatial topology frontend, :8088) inside an iframe.
 */
export const rootRouteRef = createRouteRef({
  id: 'opscryer',
});
