import {
  createFrontendPlugin,
  PageBlueprint,
} from '@backstage/frontend-plugin-api';
import DashboardIcon from '@material-ui/icons/Dashboard';

import { rootRouteRef } from './routes';

const OpsCryerBrowserPage = PageBlueprint.make({
  name: 'OpsCryerBrowserPage',
  params: {
    path: '/opscryer',
    routeRef: rootRouteRef,
    loader: () =>
      import('./components/OpsCryerBrowserComponent').then(m => (
        <m.OpsCryerBrowserComponent />
      )),
    title: 'OpsCryer Spatial Browser',
    icon: <DashboardIcon />,
  },
});

export const opscryerBrowserPlugin = createFrontendPlugin({
  pluginId: 'opscryer',
  routes: {
    root: rootRouteRef,
  },
  extensions: [OpsCryerBrowserPage],
});
