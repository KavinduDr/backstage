import { CatalogClient } from '@backstage/catalog-client';

export type ResolverParams = {
  profile: { email?: string; displayName?: string; name?: string; [k: string]: any };
  catalogClient: CatalogClient;
};

/**
 * Resolver that tries to match a User by spec.profile.email.
 * If none is found, it will create a minimal User entity in the catalog and return its ref.
 *
 * Notes:
 * - Uses catalogueClient.getEntities and addEntity. Adjust if your CatalogClient version differs.
 * - Produces a simple metadata.name derived from the email; change naming strategy in production.
 */
export async function emailMatchingUserEntityNameProfileResolver({
  profile,
  catalogClient,
}: ResolverParams): Promise<any> {
  const email = profile?.email?.toLowerCase?.();
  if (!email) {
    return { result: { type: 'error', message: 'No email in profile' } };
  }

  // Try to find an existing User by spec.profile.email
  // Use a single filter object with both keys to satisfy the EntityFilterQuery typing.
  const filter = [{ kind: 'User', 'spec.profile.email': email }];
  const resp = await catalogClient.getEntities({ filter });
  const found = resp.items?.[0];

  if (found) {
    const entityRef = `${found.kind?.toLowerCase() ?? 'user'}:${found.metadata?.name}`;
    return { result: { type: 'resolved', entityRef } };
  }

  // Not found - create a new User entity
  const safeName = email.replace(/[@.]/g, '-').replace(/[^a-z0-9-_]/gi, '').toLowerCase();
  const newUser = {
    apiVersion: 'backstage.io/v1alpha1',
    kind: 'User',
    metadata: {
      name: safeName,
      title: profile.displayName || profile.name || email,
    },
    spec: {
      profile: {
        displayName: profile.displayName || profile.name || email,
        email,
      },
    },
  };

  // Cast to any because the CatalogClient type in your environment may not expose addEntity.
  const created = await (catalogClient as any).addEntity({ entity: newUser as any });
  const createdRef = `${created.kind?.toLowerCase()}:${created.metadata?.name}`;

  return { result: { type: 'resolved', entityRef: createdRef } };
}