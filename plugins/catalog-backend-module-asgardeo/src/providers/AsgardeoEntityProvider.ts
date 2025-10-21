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

    const response = await fetch(`${orgUrl}/scim2/Users`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(
        `Failed to fetch users: ${response.status} ${response.statusText}`,
      );
    }

    const data = await response.json();

    return data.Resources.map((user: AsgardeoUser) => this.transformUser(user));
  }

  private async fetchGroups(accessToken: string): Promise<GroupEntity[]> {
    const { orgUrl } = this.config;

    const response = await fetch(`${orgUrl}/scim2/Groups`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(
        `Failed to fetch groups: ${response.status} ${response.statusText}`,
      );
    }

    const data = await response.json();

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

    // Normalize email to valid entity name
    const name = email.toLowerCase().replace(/[@.]/g, '_');

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
          asgardeoGroup.members?.map(m =>
            m.display.toLowerCase().replace(/[@.]/g, '_'),
          ) || [],
      },
    };
  }

  private normalizeGroupName(displayName: string): string {
    return displayName.toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  }
}
