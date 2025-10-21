/*
 * Copyright 2025 The Backstage Authors
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
  createBackendModule,
  coreServices,
} from '@backstage/backend-plugin-api';
import {
  authProvidersExtensionPoint,
  createOAuthProviderFactory,
} from '@backstage/plugin-auth-node';
import { OAuth2 } from 'oauth';
import type {
  OAuthAuthenticator,
  OAuthAuthenticatorAuthenticateInput,
  OAuthAuthenticatorStartInput,
} from '@backstage/plugin-auth-node';
import type { Profile as PassportProfile } from 'passport';

type OAuthCtx = Parameters<
  OAuthAuthenticator<unknown, PassportProfile>['start']
>[1];
type OAuthAuthenticateCtx = Parameters<
  OAuthAuthenticator<OAuthCtx, PassportProfile>['authenticate']
>[1];

type PassportProfileWithJson = PassportProfile & {
  _json?: Record<string, unknown>;
};

export const asgardeoAuthProvider = createBackendModule({
  pluginId: 'auth',
  moduleId: 'asgardeo-provider',
  register(reg) {
    reg.registerInit({
      deps: {
        providers: authProvidersExtensionPoint,
        logger: coreServices.logger,
      },
      async init({ providers, logger }) {
        providers.registerProvider({
          providerId: 'asgardeo',
          factory: createOAuthProviderFactory({
            authenticator: {
              defaultProfileTransform: async (result: any) => {
                logger.info(
                  `🔍 Profile transformation: ${JSON.stringify(result)}`,
                );

                return {
                  profile: {
                    email: result.session.email || result.session.sub,
                    displayName: result.session.name || result.session.username,
                    picture: result.session.picture,
                  },
                };
              },
              initialize({ config }) {
                const clientId = config.getString('clientId');
                const clientSecret = config.getString('clientSecret');
                const callbackUrl = config.getString('callbackUrl');
                const authorizationUrl = config.getString('authorizationUrl');
                const tokenUrl = config.getString('tokenUrl');

                return new OAuth2(
                  clientId,
                  clientSecret,
                  '',
                  authorizationUrl,
                  tokenUrl,
                  {
                    redirect_uri: callbackUrl,
                  },
                );
              },
              async start(input: OAuthAuthenticatorStartInput, ctx: OAuthCtx) {
                const scopes = ctx.config.getOptionalStringArray('scopes') ?? [
                  'openid',
                  'profile',
                  'email',
                ];

                return {
                  url: ctx.strategy.getAuthorizeUrl({
                    redirect_uri: input.callbackUrl,
                    scope: scopes.join(' '),
                    state: input.state,
                  }),
                  status: 302,
                };
              },
              async authenticate(
                input: OAuthAuthenticatorAuthenticateInput,
                ctx: OAuthAuthenticateCtx,
              ) {
                const { code } = input.query;

                if (!code) {
                  throw new Error('Authorization code not found in callback');
                }

                const accessToken = await new Promise<string>(
                  (resolve, reject) => {
                    ctx.strategy.getOAuthAccessToken(
                      code as string,
                      {
                        grant_type: 'authorization_code',
                        redirect_uri: input.callbackUrl,
                      },
                      (err: any, token: string) => {
                        if (err) {
                          reject(err);
                        } else {
                          resolve(token);
                        }
                      },
                    );
                  },
                );

                const userInfoUrl = ctx.config.getString('userInfoUrl');
                const userInfoResponse = await fetch(userInfoUrl, {
                  headers: {
                    Authorization: `Bearer ${accessToken}`,
                  },
                });

                if (!userInfoResponse.ok) {
                  throw new Error(
                    `Failed to fetch user info: ${userInfoResponse.status}`,
                  );
                }

                const userInfo = await userInfoResponse.json();

                logger.info(`👤 User info: ${JSON.stringify(userInfo)}`);

                const fullProfile: PassportProfileWithJson = {
                  provider: 'asgardeo',
                  id:
                    userInfo.sub ??
                    userInfo.id ??
                    userInfo.email ??
                    userInfo.username ??
                    '',
                  displayName:
                    userInfo.name ??
                    userInfo.username ??
                    userInfo.preferred_username ??
                    userInfo.email ??
                    '',
                  emails: userInfo.email
                    ? [{ value: userInfo.email }]
                    : undefined,
                  photos: userInfo.picture
                    ? [{ value: userInfo.picture }]
                    : undefined,
                  _json: userInfo,
                };

                return {
                  fullProfile,
                  session: {
                    ...userInfo,
                    accessToken,
                  },
                };
              },
              async refresh() {
                throw new Error('Refresh not supported');
              },
            },
            signInResolverFactories: {
              emailLocalPartMatchingUserEntityName: () => async (info, ctx) => {
                const { profile } = info;

                logger.info(
                  `🔍 Sign-in resolver: emailLocalPartMatchingUserEntityName`,
                );
                logger.info(`📧 Profile: ${JSON.stringify(profile)}`);

                if (!profile.email) {
                  throw new Error('Asgardeo profile does not contain an email');
                }

                const emailLocalPart = profile.email.split('@')[0];
                const name = emailLocalPart
                  .toLowerCase()
                  .replace(/[^a-z0-9_-]/g, '_');

                logger.info(
                  `✅ Issuing token for user without catalog requirement: ${name}`,
                );

                return ctx.issueToken({
                  claims: {
                    sub: name,
                    ent: [`user:default/${name}`],
                  },
                });
              },
            },
          }),
        });
      },
    });
  },
});

export default asgardeoAuthProvider;
