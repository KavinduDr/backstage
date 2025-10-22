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
  createOAuthAuthenticator,
  PassportOAuthAuthenticatorHelper,
  PassportOAuthDoneCallback,
  PassportProfile,
} from '@backstage/plugin-auth-node';
import { Strategy as OAuth2Strategy } from 'passport-oauth2';

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
            authenticator: createOAuthAuthenticator({
              defaultProfileTransform:
                PassportOAuthAuthenticatorHelper.defaultProfileTransform,
              scopes: {
                persist: true,
                required: ['openid', 'profile', 'email'],
              },
              initialize({ callbackUrl, config }) {
                const clientId = config.getString('clientId');
                const clientSecret = config.getString('clientSecret');
                const authorizationUrl = config.getString('authorizationUrl');
                const tokenUrl = config.getString('tokenUrl');
                const userInfoUrl = config.getString('userInfoUrl');

                const providerStrategy = new OAuth2Strategy(
                  {
                    clientID: clientId,
                    clientSecret: clientSecret,
                    callbackURL: callbackUrl,
                    authorizationURL: authorizationUrl,
                    tokenURL: tokenUrl,
                    passReqToCallback: false,
                    pkce: true,
                    state: false,
                  },
                  async (
                    accessToken: string,
                    refreshToken: string,
                    params: any,
                    _fullProfile: PassportProfile,
                    done: PassportOAuthDoneCallback,
                  ) => {
                    try {
                      // Fetch user info from Asgardeo
                      const userInfoResponse = await fetch(userInfoUrl, {
                        headers: { Authorization: `Bearer ${accessToken}` },
                      });

                      if (!userInfoResponse.ok) {
                        throw new Error(
                          `Failed to fetch user info: ${userInfoResponse.status}`,
                        );
                      }

                      const userInfo = await userInfoResponse.json();
                      const asgardeoProfile: PassportProfile = {
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
                      };

                      done(
                        undefined,
                        { fullProfile: asgardeoProfile, params, accessToken },
                        { refreshToken },
                      );
                    } catch (error) {
                      done(error as Error);
                    }
                  },
                );

                return PassportOAuthAuthenticatorHelper.from(providerStrategy);
              },
              async start(input, helper) {
                return helper.start(input, {
                  scope: 'openid profile email',
                });
              },
              async authenticate(input, helper) {
                return helper.authenticate(input);
              },
              async refresh(input, helper) {
                return helper.refresh(input);
              },
            }),
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

                logger.info(`🔍 Attempting to sign in user: ${name}`);

                // Try to find existing user in catalog first
                try {
                  return await ctx.signInWithCatalogUser(
                    {
                      entityRef: { name },
                    },
                    {
                      // If user doesn't exist in catalog, create a fallback entity reference
                      dangerousEntityRefFallback: { entityRef: { name } },
                    },
                  );
                } catch (error) {
                  logger.warn(
                    `User ${name} not found in catalog, creating fallback entity reference`,
                  );

                  // Fallback: create entity reference without catalog lookup
                  return ctx.issueToken({
                    claims: {
                      sub: `user:default/${name}`,
                      ent: [`user:default/${name}`],
                    },
                  });
                }
              },
            },
          }),
        });
      },
    });
  },
});

export default asgardeoAuthProvider;
