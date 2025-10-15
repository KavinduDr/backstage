/*
 * Copyright 2020 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  ScmIntegrationsApi,
  scmIntegrationsApiRef,
  ScmAuth,
} from '@backstage/integration-react';
import {
  AnyApiFactory,
  BackstageIdentityApi,
  configApiRef,
  createApiFactory,
  createApiRef,
  discoveryApiRef,
  fetchApiRef,
  identityApiRef,
  oauthRequestApiRef,
  OpenIdConnectApi,
  ProfileInfoApi,
  SessionApi,
} from '@backstage/core-plugin-api';
import { AuthProxyDiscoveryApi } from './AuthProxyDiscoveryApi';
import { formDecoratorsApiRef } from '@backstage/plugin-scaffolder/alpha';
import { DefaultScaffolderFormDecoratorsApi } from '@backstage/plugin-scaffolder/alpha';
import { mockDecorator } from './components/scaffolder/decorators';
import { scaffolderApiRef } from '@backstage/plugin-scaffolder-react';
import { ScaffolderClient } from '@backstage/plugin-scaffolder';
import { OAuth2 } from '@backstage/core-app-api';

export const asgardeoOidcAuthApiRef = createApiRef<
  OpenIdConnectApi & ProfileInfoApi & BackstageIdentityApi & SessionApi
>({
  id: 'auth.asgardeo',
});

export const apis: AnyApiFactory[] = [
  createApiFactory({
    api: discoveryApiRef,
    deps: { configApi: configApiRef },
    factory: ({ configApi }) => AuthProxyDiscoveryApi.fromConfig(configApi),
  }),
  createApiFactory({
    api: scmIntegrationsApiRef,
    deps: { configApi: configApiRef },
    factory: ({ configApi }) => ScmIntegrationsApi.fromConfig(configApi),
  }),

  createApiFactory({
    api: scaffolderApiRef,
    deps: {
      discoveryApi: discoveryApiRef,
      fetchApi: fetchApiRef,
      scmIntegrationsApi: scmIntegrationsApiRef,
      identityApi: identityApiRef,
    },
    factory: ({ discoveryApi, fetchApi, scmIntegrationsApi, identityApi }) =>
      new ScaffolderClient({
        useLongPollingLogs: true,
        discoveryApi,
        fetchApi,
        scmIntegrationsApi,
        identityApi,
      }),
  }),

  createApiFactory({
    api: formDecoratorsApiRef,
    deps: {},
    factory: () =>
      DefaultScaffolderFormDecoratorsApi.create({
        decorators: [mockDecorator],
      }),
  }),

  createApiFactory({
    api: asgardeoOidcAuthApiRef,
    deps: {
      discoveryApi: discoveryApiRef,
      oauthRequestApi: oauthRequestApiRef,
      configApi: configApiRef,
    },
    factory: ({ discoveryApi, oauthRequestApi, configApi }) =>
      OAuth2.create({
        discoveryApi,
        oauthRequestApi,
        configApi,
        provider: {
          id: 'asgardeo',
          title: 'Asgardeo',
          icon: () => null,
        },
        environment: configApi.getOptionalString('auth.environment'),
        defaultScopes: ['openid', 'profile', 'email'],
        popupOptions: {},
      }),
  }),

  ScmAuth.createDefaultApiFactory(),
];
