import { createDevApp } from '@backstage/frontend-dev-utils';
import alpha from '../src';

createDevApp({ features: [alpha] });
