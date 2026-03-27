/**
 * Migration: OAuth2 social login support
 * Version:   20260328000000_oauth_accounts
 *
 * Adds:
 *   - oauth_accounts table — links provider identities to users
 *   - users.password made nullable (OAuth-only accounts have no password)
 */

/**
 * @param {import('@prisma/client').PrismaClient} prisma
 */
export async function up(prisma) {
  // Make password nullable for OAuth-only accounts
  await prisma.$executeRawUnsafe(`
    ALTER TABLE users
      ALTER COLUMN password DROP NOT NULL
  `);

  // OAuth accounts table
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS oauth_accounts (
      id               SERIAL PRIMARY KEY,
      user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      provider         TEXT    NOT NULL,
      provider_user_id TEXT    NOT NULL,
      access_token     TEXT,
      name             TEXT,
      avatar_url       TEXT,
      created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT uq_oauth_provider_user UNIQUE (provider, provider_user_id)
    )
  `);

  await prisma.$executeRawUnsafe(`
    CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts (user_id)
  `);
}

/**
 * @param {import('@prisma/client').PrismaClient} prisma
 */
export async function down(prisma) {
  await prisma.$executeRawUnsafe(`DROP TABLE IF EXISTS oauth_accounts`);

  // Restore NOT NULL — only safe if no null passwords exist
  await prisma.$executeRawUnsafe(`
    ALTER TABLE users
      ALTER COLUMN password SET NOT NULL
  `);
}
