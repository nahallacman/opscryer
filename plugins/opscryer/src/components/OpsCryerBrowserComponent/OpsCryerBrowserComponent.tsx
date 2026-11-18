import {
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Chip,
  Typography,
} from '@material-ui/core';
import OpenInNewIcon from '@material-ui/icons/OpenInNew';
import { ContentHeader, InfoCard } from '@backstage/core-components';
import { useApi, configApiRef } from '@backstage/core-plugin-api';

const DEFAULT_OPSCRYER_URL = 'http://localhost:8088';

export const OpsCryerBrowserComponent = () => {
  const configApi = useApi(configApiRef);
  const opscryerConfigs =
    configApi.getOptionalConfigArray('integrations.opscryer') ?? [];
  const opscryerUrl =
    opscryerConfigs[0]?.getOptionalString('baseUrl') ?? DEFAULT_OPSCRYER_URL;

  return (
    <Box sx={{ flexGrow: 1, p: 3, width: '100%' }}>
      <ContentHeader title="OpsCryer Spatial Browser" />
      <Box sx={{ mt: 2 }}>
        <InfoCard title="OpsCryer">
          <CardContent>
            <Typography variant="body1">
              Embedded OpsCryer spatial browser ({opscryerUrl}). Displays the
              SpatialGraphContract v1 knowledge graph synced from the Central
              Brain via the OpsCryer bridge.
            </Typography>
          </CardContent>
        </InfoCard>
      </Box>
      <Box sx={{ mt: 2 }}>
        <Card>
          <CardHeader
            title="Spatial Browser"
            subheader={`Loading from ${opscryerUrl}`}
            action={
              <Button
                size="small"
                color="primary"
                startIcon={<OpenInNewIcon />}
                href={opscryerUrl}
                target="_blank"
                rel="noopener noreferrer"
              >
                Launch in new tab
              </Button>
            }
          />
          <CardContent>
            <iframe
              src={opscryerUrl}
              title="OpsCryer Spatial Browser"
              style={{
                width: '100%',
                height: '80vh',
                border: 'none',
                display: 'block',
              }}
              sandbox="allow-same-origin allow-scripts allow-popups allow-forms"
            />
          </CardContent>
        </Card>
      </Box>
      <Box sx={{ mt: 2 }}>
        <Chip label="Read-only integration" color="default" size="small" variant="outlined" />
      </Box>
      <Box sx={{ mt: 2 }}>
        <Typography variant="caption" color="textSecondary">
          OpsCryer is an independent service. This Backstage plugin renders it
          in an iframe with a launch button for full-screen access.
        </Typography>
      </Box>
    </Box>
  );
};
