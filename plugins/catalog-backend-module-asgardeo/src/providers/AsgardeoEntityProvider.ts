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
  EntityProvider,
  EntityProviderConnection,
} from '@backstage/plugin-catalog-node';
import { TaskRunner } from '@backstage/backend-tasks';
import { Config } from '@backstage/config';
import { LoggerService } from '@backstage/backend-plugin-api';
import {
  GroupEntity,
  UserEntity,
  ANNOTATION_LOCATION,
  ANNOTATION_ORIGIN_LOCATION,
} from '@backstage/catalog-model';

/**
 * Configuration options for the Asgardeo entity provider.
 *
 * @public
 */
export interface AsgardeoEntityProviderConfig {
  /**
   * The Asgardeo organization URL.
   */
  orgUrl: string;

  /**
   * The client ID for authentication.
   */
  clientId: string;

  /**
   * The client secret for authentication.
   */
  clientSecret: string;

  /**
   * The schedule for running the provider.
   */
  schedule?: TaskRunner;
}

interface AsgardeoUser {
  id: string;
  userName: string;
  displayName?: string;
  emails?: Array<{ value: string; primary?: boolean }>;
  photos?: Array<{ value: string }>;
  groups?: Array<{ value: string; display: string }>;
}

interface AsgardeoGroup {
  id: string;
  displayName: string;
  members?: Array<{ value: string; display: string }>;
}

/**
 * Provides entities from Asgardeo.
 *
 * @public
 */
export class AsgardeoEntityProvider implements EntityProvider {
  private readonly config: AsgardeoEntityProviderConfig;
  private readonly logger: LoggerService;
  private connection?: EntityProviderConnection;

  static fromConfig(
    config: Config,
    options: {
      logger: LoggerService;
      schedule?: TaskRunner;
    },
  ): AsgardeoEntityProvider {
    const providerConfig: AsgardeoEntityProviderConfig = {
      orgUrl: config.getString('catalog.providers.asgardeo.orgUrl'),
      clientId: config.getString('catalog.providers.asgardeo.clientId'),
      clientSecret: config.getString('catalog.providers.asgardeo.clientSecret'),
      schedule: options.schedule,
    };

    console.log(providerConfig);

    return new AsgardeoEntityProvider(providerConfig, options.logger);
  }

  constructor(config: AsgardeoEntityProviderConfig, logger: LoggerService) {
    this.config = config;
    this.logger = logger.child({ target: this.getProviderName() });
  }

  getProviderName(): string {
    return 'asgardeo';
  }

  async connect(connection: EntityProviderConnection): Promise<void> {
    this.connection = connection;

    if (this.config.schedule) {
      await this.config.schedule.run({
        id: `${this.getProviderName()}:refresh`,
        fn: async () => {
          await this.refresh();
        },
      });
    }
  }

  async refresh(): Promise<void> {
    if (!this.connection) {
      throw new Error('Not initialized');
    }

    this.logger.info('Discovering Asgardeo users and groups');

    try {
      const { users, groups } = await this.fetchAsgardeoData();

      const entities = [...users, ...groups];

      await this.connection.applyMutation({
        type: 'full',
        entities: entities.map(entity => ({
          locationKey: this.getProviderName(),
          entity,
        })),
      });

      this.logger.info(
        `Discovered ${users.length} users and ${groups.length} groups from Asgardeo`,
      );
    } catch (error) {
      this.logger.error('Failed to discover Asgardeo entities', error);
      throw error;
    }
  }

  private async fetchAsgardeoData(): Promise<{
    users: UserEntity[];
    groups: GroupEntity[];
  }> {
    const accessToken = await this.getAccessToken();

    const users = await this.fetchUsers(accessToken);
    const groups = await this.fetchGroups(accessToken);

    return { users, groups };
  }

  private async getAccessToken(): Promise<string> {
    const { orgUrl, clientId, clientSecret } = this.config;

    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString(
      'base64',
    );

    const response = await fetch(`${orgUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${credentials}`,
      },
      body: 'grant_type=client_credentials&scope=internal_user_mgt_view internal_group_mgt_view',
    });

    if (!response.ok) {
      throw new Error(
        `Failed to get access token: ${response.status} ${response.statusText}`,
      );
    }

    const data = await response.json();
    return data.access_token;
  }

  private async fetchUsers(accessToken: string): Promise<UserEntity[]> {
    const { orgUrl } = this.config;

    // Try different API endpoints for user management
    const endpoints = [
      `${orgUrl}/scim2/Users`,
      `${orgUrl}/scim/Users`,
      `${orgUrl}/api/scim2/Users`,
      `${orgUrl}/api/scim/Users`,
    ];

    let response: Response | null = null;
    let lastError: string = '';

    for (const endpoint of endpoints) {
      this.logger.debug(`Trying to fetch users from ${endpoint}`);

      try {
        response = await fetch(endpoint, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
            Accept: 'application/scim+json',
          },
        });

        if (response.ok) {
          this.logger.info(`Successfully connected to ${endpoint}`);
          break;
        } else {
          const errorText = await response.text();
          lastError = `${endpoint}: ${response.status} ${response.statusText} - ${errorText}`;
          this.logger.warn(`Failed to fetch from ${endpoint}: ${lastError}`);
        }
      } catch (error) {
        lastError = `${endpoint}: ${error}`;
        this.logger.warn(`Error fetching from ${endpoint}: ${error}`);
      }
    }

    if (!response || !response.ok) {
      this.logger.error(`All user endpoints failed. Last error: ${lastError}`);
      this.logger.warn(
        'This might be due to insufficient permissions or incorrect API endpoints.',
      );
      this.logger.warn(
        'Please check that your Asgardeo client has the necessary SCIM permissions.',
      );

      // Return empty array instead of throwing error to prevent catalog provider from failing
      return [];
    }

    const data = await response.json();
    this.logger.debug(
      `Fetched ${data.Resources?.length || 0} users from Asgardeo`,
    );

    if (!data.Resources || !Array.isArray(data.Resources)) {
      this.logger.warn('No users found in Asgardeo response');
      return [];
    }

    return data.Resources.map((user: AsgardeoUser) => this.transformUser(user));
  }

  private async fetchGroups(accessToken: string): Promise<GroupEntity[]> {
    const { orgUrl } = this.config;

    // Try different API endpoints for group management
    const endpoints = [
      `${orgUrl}/scim2/Groups`,
      `${orgUrl}/scim/Groups`,
      `${orgUrl}/api/scim2/Groups`,
      `${orgUrl}/api/scim/Groups`,
    ];

    let response: Response | null = null;
    let lastError: string = '';

    for (const endpoint of endpoints) {
      this.logger.debug(`Trying to fetch groups from ${endpoint}`);

      try {
        response = await fetch(endpoint, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
            Accept: 'application/scim+json',
          },
        });

        if (response.ok) {
          this.logger.info(`Successfully connected to ${endpoint}`);
          break;
        } else {
          const errorText = await response.text();
          lastError = `${endpoint}: ${response.status} ${response.statusText} - ${errorText}`;
          this.logger.warn(`Failed to fetch from ${endpoint}: ${lastError}`);
        }
      } catch (error) {
        lastError = `${endpoint}: ${error}`;
        this.logger.warn(`Error fetching from ${endpoint}: ${error}`);
      }
    }

    if (!response || !response.ok) {
      this.logger.error(`All group endpoints failed. Last error: ${lastError}`);
      this.logger.warn(
        'This might be due to insufficient permissions or incorrect API endpoints.',
      );
      this.logger.warn(
        'Please check that your Asgardeo client has the necessary SCIM permissions.',
      );

      // Return empty array instead of throwing error to prevent catalog provider from failing
      return [];
    }

    const data = await response.json();
    this.logger.debug(
      `Fetched ${data.Resources?.length || 0} groups from Asgardeo`,
    );

    if (!data.Resources || !Array.isArray(data.Resources)) {
      this.logger.warn('No groups found in Asgardeo response');
      return [];
    }

    return data.Resources.map((group: AsgardeoGroup) =>
      this.transformGroup(group),
    );
  }

  private transformUser(asgardeoUser: AsgardeoUser): UserEntity {
    const email =
      asgardeoUser.emails?.find(e => e.primary)?.value ||
      asgardeoUser.emails?.[0]?.value ||
      asgardeoUser.userName;
    const displayName = asgardeoUser.displayName || asgardeoUser.userName;

    // Normalize email to valid entity name - match auth resolver logic
    const emailLocalPart = email.split('@')[0];
    const name = emailLocalPart.toLowerCase().replace(/[^a-z0-9_-]/g, '_');

    this.logger.debug(`Transforming user: ${asgardeoUser.userName} -> ${name}`);

    return {
      apiVersion: 'backstage.io/v1alpha1',
      kind: 'User',
      metadata: {
        name,
        annotations: {
          [ANNOTATION_LOCATION]: `${this.getProviderName()}:default/${
            asgardeoUser.id
          }`,
          [ANNOTATION_ORIGIN_LOCATION]: `${this.getProviderName()}:default/${
            asgardeoUser.id
          }`,
          'asgardeo.io/user-id': asgardeoUser.id,
        },
      },
      spec: {
        profile: {
          displayName,
          email,
          picture: asgardeoUser.photos?.[0]?.value,
        },
        memberOf:
          asgardeoUser.groups?.map(g => this.normalizeGroupName(g.display)) ||
          [],
      },
    };
  }

  private transformGroup(asgardeoGroup: AsgardeoGroup): GroupEntity {
    const name = this.normalizeGroupName(asgardeoGroup.displayName);

    return {
      apiVersion: 'backstage.io/v1alpha1',
      kind: 'Group',
      metadata: {
        name,
        annotations: {
          [ANNOTATION_LOCATION]: `${this.getProviderName()}:default/${
            asgardeoGroup.id
          }`,
          [ANNOTATION_ORIGIN_LOCATION]: `${this.getProviderName()}:default/${
            asgardeoGroup.id
          }`,
          'asgardeo.io/group-id': asgardeoGroup.id,
        },
      },
      spec: {
        type: 'team',
        profile: {
          displayName: asgardeoGroup.displayName,
        },
        children: [],
        members:
          asgardeoGroup.members?.map(m => {
            // Match the same naming pattern as users
            const emailLocalPart = m.display.split('@')[0];
            return emailLocalPart.toLowerCase().replace(/[^a-z0-9_-]/g, '_');
          }) || [],
      },
    };
  }

  private normalizeGroupName(displayName: string): string {
    return displayName.toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  }
}
