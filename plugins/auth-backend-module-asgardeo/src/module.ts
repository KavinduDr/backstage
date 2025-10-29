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
import { createBackendModule, coreServices } from '@backstage/backend-plugin-api';
import {
  authProvidersExtensionPoint,
  commonSignInResolvers,
  createOAuthAuthenticator,
  createOAuthProviderFactory,
  PassportOAuthAuthenticatorHelper,
  PassportOAuthDoneCallback,
} from '@backstage/plugin-auth-node';
import { CatalogClient } from '@backstage/catalog-client';
import { Strategy as OAuth2Strategy } from 'passport-oauth2';
import { emailMatchingUserEntityNameProfileResolver } from './createUserIfMissingResolver';

const asgardeoAuthenticator = createOAuthAuthenticator({
  defaultProfileTransform:
    PassportOAuthAuthenticatorHelper.defaultProfileTransform,
  scopes: {
    required: ['openid', 'profile', 'email'],
  },
  initialize({ callbackUrl, config }) {
    console.log('🔧 Initializing Asgardeo authenticator...');
    console.log('📍 Callback URL:', callbackUrl);

    const clientID = config.getString('clientId');
    const clientSecret = config.getString('clientSecret');
    const authorizationURL = config.getString('authorizationUrl');
    const tokenURL = config.getString('tokenUrl');
    const userInfoURL = config.getString('userInfoUrl');

    console.log('⚙️  Config loaded:', {
      clientID: `${clientID.substring(0, 10)}...`,
      authorizationURL,
      tokenURL,
      userInfoURL,
    });

    const strategy = new OAuth2Strategy(
      {
        clientID,
        clientSecret,
        callbackURL: callbackUrl,
        authorizationURL,
        tokenURL,
        scope: ['openid', 'profile', 'email'],
      },
      (
        accessToken: string,
        refreshToken: string,
        params: any,
        fullProfile: any,
        done: PassportOAuthDoneCallback,
      ) => {
        console.log('🎫 OAuth callback received');
        console.log('✅ Access token received:', accessToken ? 'Yes' : 'No');
        console.log('🔄 Refresh token received:', refreshToken ? 'Yes' : 'No');
        console.log('📦 Params:', params);

        done(undefined, {
          fullProfile,
          accessToken,
          params,
        });
      },
    );

    // Override userProfile to fetch from Asgardeo's userinfo endpoint with proper headers
    strategy.userProfile = async function (accessToken: string, done: any) {
      console.log('👤 Fetching user profile from:', userInfoURL);
      console.log(
        '🔑 Using access token:',
        `${accessToken.substring(0, 20)}...`,
      );

      try {
        // Use fetch instead of OAuth2's get method for better control over headers
        const response = await fetch(userInfoURL, {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
        });

        console.log('📡 Response status:', response.status);
        console.log(
          '📡 Response headers:',
          Object.fromEntries(response.headers.entries()),
        );
        console.log('📡 Response content:', response);

        if (!response.ok) {
          const errorText = await response.text();
          console.error('❌ Error response:', errorText);
          throw new Error(
            `Failed to fetch user profile: ${response.status} ${errorText}`,
          );
        }

        const profile = await response.json();
        console.log('📋 Parsed profile:', profile);

        // Transform Asgardeo profile to Passport format
        const passportProfile = {
          provider: 'asgardeo',
          id: profile.sub,
          displayName:
            profile.name ||
            profile.displayName ||
            profile.username ||
            profile.email,
          username: profile.username || profile.email?.split('@')[0],
          // eslint-disable-next-line no-nested-ternary
          emails: profile.email
            ? [{ value: profile.email }]
            : profile.username?.includes('@')
            ? [{ value: profile.username }]
            : [],
          email:
            profile.email ||
            (profile.username?.includes('@') ? profile.username : undefined),
          name: {
            familyName: profile.family_name,
            givenName: profile.given_name,
          },
          _raw: JSON.stringify(profile),
          _json: profile,
        };

        console.log('✨ Transformed profile:', {
          id: passportProfile.id,
          displayName: passportProfile.displayName,
          email: passportProfile.email,
          username: passportProfile.username,
        });

        done(null, passportProfile);
      } catch (error) {
        console.error('❌ Error fetching user profile:', error);
        done(error);
      }
    };

    return PassportOAuthAuthenticatorHelper.from(strategy);
  },
  async start(input, helper) {
    console.log('🚀 Starting OAuth flow...');
    const result = await helper.start(input, {
      accessType: 'offline',
      prompt: 'consent',
    });
    console.log('✅ OAuth flow started successfully');
    return result;
  },
  async authenticate(input, helper) {
    console.log('🔐 Authenticating user...');
    try {
      const result = await helper.authenticate(input);
      console.log('✅ Authentication successful');
      console.log('👤 Authenticated profile:', result.fullProfile);
      return result;
    } catch (error) {
      console.error('❌ Authentication failed:', error);
      throw error;
    }
  },
  async refresh(input, helper) {
    console.log('🔄 Refreshing session...');
    console.log('📥 Refresh input:', {
      hasRefreshToken: !!input.refreshToken,
      scope: input.scope,
    });

    try {
      const result = await helper.refresh(input);
      console.log('✅ Session refreshed successfully');
      return result;
    } catch (error) {
      console.error('❌ Session refresh failed:', error);
      throw error;
    }
  },
});

export const authModuleAsgardeoProvider = createBackendModule({
  pluginId: 'auth',
  moduleId: 'asgardeo-provider',
  register(reg) {
    reg.registerInit({
      deps: {
        providers: authProvidersExtensionPoint,
        discovery: coreServices.discovery,
      },
      async init({ providers, discovery }) {
        console.log('🎯 Registering Asgardeo auth provider...');

        // Create a CatalogClient instance scoped to this backend using discovery
        const catalogClient = new CatalogClient({ discoveryApi: discovery });

        providers.registerProvider({
          providerId: 'asgardeo',
          factory: createOAuthProviderFactory({
            authenticator: asgardeoAuthenticator,
            // Provide resolver factories so the declarative resolver configured
            // in app-config.local.yaml (emailMatchingUserEntityNameProfile) is used.
            // The factory below closes over `catalogClient` so it can create
            // entities when missing.
            signInResolverFactories: {
              emailMatchingUserEntityNameProfile: () => {
                // SignInResolver receives a SignInInfo object as the first arg,
                // which contains { profile, result } — not the profile directly.
                return async (info: any, ctx: any) => {
                  console.log(info);
                  const profile = info?.profile ?? info;
                  const email = profile?.email?.toLowerCase?.();
                  if (!email) {
                    throw new Error('No email in profile');
                  }

                  // Try to find an existing User by spec.profile.email
                  // Build filter and cast to any to satisfy the CatalogClient types in this repo
                  const filter = [{ kind: 'User', 'spec.profile.email': email }] as any;
                  const resp = await catalogClient.getEntities({ filter } as any);
                  const found = resp.items?.[0];

                  if (found) {
                    const entityRef = `${found.kind?.toLowerCase()}:${found.metadata?.name}`;
                    return ctx.signInWithCatalogUser({ entityRef });
                  }

                  // Not found - automatic entity creation via the public
                  // CatalogClient is not supported. The backend catalog exposes
                  // locations and entity providers as the standard ingestion
                  // mechanism, so creating entities programmatically requires
                  // backend-side processing or a dedicated entity-provider.
                  //
                  // For now, issue a token using a "dangerous fallback" entity
                  // ref. This allows sign-in to proceed, but does NOT create a
                  // catalog User. Longer-term options:
                  //  - Implement an entity-provider that syncs Asgardeo users
                  //    into the catalog (recommended for production).
                  //  - Add a backend API that invokes the catalog processing
                  //    orchestrator to add entities (more invasive).
                  const safeName = email.replace(/[@.]/g, '-').replace(/[^a-z0-9-_]/gi, '').toLowerCase();
                  const fallbackRef = `User:default/${safeName}`;

                  // Log so operators can notice that the user was allowed to
                  // sign in without an existing catalog entity.
                  console.warn(
                    `No catalog User found for email=${email}; issuing token for fallback entityRef=${fallbackRef} (no catalog entity created)`,
                  );

                  return ctx.signInWithCatalogUser(
                    { entityRef: fallbackRef },
                    { dangerousEntityRefFallback: { entityRef: fallbackRef } },
                  );
                };
              },
              ...commonSignInResolvers,
            },
          }),
        });

        console.log('✅ Asgardeo provider registered successfully');
      },
    });
  },
});

// Export a resolvers map so the auth-backend can pick up the resolver by name
// The key matches the resolver referenced in your app-config.yaml / app-config.local.yaml
export const resolvers = {
  // keep same resolver name used in config so no config changes needed
  emailMatchingUserEntityNameProfile: async (params: any) =>
    emailMatchingUserEntityNameProfileResolver({
      profile: params.profile,
      // In the auth-backend environment the Catalog client is available as params.catalogClient.
      // If your module wiring provides it under a different name, adjust accordingly.
      catalogClient: params.catalogClient,
    }),
};

export default authModuleAsgardeoProvider;
