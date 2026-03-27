/**
 * OAuth2 Service
 *
 * Handles Google and GitHub OAuth2 flows without a heavy passport dependency.
 * Uses the standard authorization-code flow:
 *   1. Build provider authorization URL  → redirect user
 *   2. Exchange code for tokens          → fetch user profile
 *   3. Upsert OAuthAccount + User        → return JWT pair
 *
 * Account linking: if a user with the same email already exists (email/password
 * or another provider), the OAuth account is linked to that existing user.
 *
 * @module services/oauthService
 */

import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import prisma from '../lib/prisma.js';
import { log, AuditCategory, AuditAction } from './auditService.js';

// ── Provider configs ──────────────────────────────────────────────────────────

const PROVIDERS = {
  google: {
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
    scope: 'openid email profile',
    clientIdEnv: 'GOOGLE_CLIENT_ID',
    clientSecretEnv: 'GOOGLE_CLIENT_SECRET',
  },
  github: {
    authUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userUrl: 'https://api.github.com/user',
    emailUrl: 'https://api.github.com/user/emails',
    scope: 'read:user user:email',
    clientIdEnv: 'GITHUB_CLIENT_ID',
    clientSecretEnv: 'GITHUB_CLIENT_SECRET',
  },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function getCallbackUrl(provider) {
  const base = process.env.OAUTH_CALLBACK_BASE_URL || `http://localhost:${process.env.PORT || 4000}`;
  return `${base}/api/auth/oauth/${provider}/callback`;
}

function generateTokens(user) {
  const payload = { userId: user.id, tenantId: user.tenantId };
  const accessToken = jwt.sign(
    payload,
    process.env.JWT_ACCESS_SECRET || 'fallback_access_secret',
    { expiresIn: process.env.JWT_ACCESS_EXPIRATION || '15m' },
  );
  const refreshToken = jwt.sign(
    payload,
    process.env.JWT_REFRESH_SECRET || 'fallback_refresh_secret',
    { expiresIn: process.env.JWT_REFRESH_EXPIRATION || '7d' },
  );
  return { accessToken, refreshToken };
}

function getProviderConfig(provider) {
  const config = PROVIDERS[provider];
  if (!config) throw new Error(`Unsupported OAuth provider: ${provider}`);
  return config;
}

// ── State management (CSRF protection) ───────────────────────────────────────

// In-memory store for OAuth state tokens (short-lived, 10 min TTL).
// For multi-instance deployments, swap this for Redis.
const stateStore = new Map();
const STATE_TTL_MS = 10 * 60 * 1000;

function createState(tenantId) {
  const state = crypto.randomBytes(16).toString('hex');
  stateStore.set(state, { tenantId, createdAt: Date.now() });
  // Auto-cleanup
  setTimeout(() => stateStore.delete(state), STATE_TTL_MS);
  return state;
}

function consumeState(state) {
  const entry = stateStore.get(state);
  if (!entry) return null;
  stateStore.delete(state);
  if (Date.now() - entry.createdAt > STATE_TTL_MS) return null;
  return entry;
}

// ── Step 1: Build authorization URL ──────────────────────────────────────────

/**
 * Build the provider's authorization URL and return it along with the state token.
 *
 * @param {'google'|'github'} provider
 * @param {string} tenantId
 * @returns {{ url: string, state: string }}
 */
export function getAuthorizationUrl(provider, tenantId) {
  const config = getProviderConfig(provider);
  const clientId = process.env[config.clientIdEnv];
  if (!clientId) throw new Error(`${config.clientIdEnv} is not configured`);

  const state = createState(tenantId);
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: getCallbackUrl(provider),
    response_type: 'code',
    scope: config.scope,
    state,
    ...(provider === 'google' ? { access_type: 'offline', prompt: 'select_account' } : {}),
  });

  return { url: `${config.authUrl}?${params}`, state };
}

// ── Step 2: Exchange code for profile ────────────────────────────────────────

async function exchangeCodeForTokens(provider, code) {
  const config = getProviderConfig(provider);
  const body = new URLSearchParams({
    code,
    client_id: process.env[config.clientIdEnv],
    client_secret: process.env[config.clientSecretEnv],
    redirect_uri: getCallbackUrl(provider),
    grant_type: 'authorization_code',
  });

  const res = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token exchange failed (${res.status}): ${text}`);
  }

  return res.json();
}

async function fetchGoogleProfile(accessToken) {
  const res = await fetch(PROVIDERS.google.userUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`Failed to fetch Google profile (${res.status})`);
  const data = await res.json();
  return {
    providerUserId: data.sub,
    email: data.email,
    name: data.name || null,
    avatarUrl: data.picture || null,
  };
}

async function fetchGithubProfile(accessToken) {
  const [userRes, emailsRes] = await Promise.all([
    fetch(PROVIDERS.github.userUrl, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github+json' },
    }),
    fetch(PROVIDERS.github.emailUrl, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github+json' },
    }),
  ]);

  if (!userRes.ok) throw new Error(`Failed to fetch GitHub profile (${userRes.status})`);

  const user = await userRes.json();
  let email = user.email;

  // GitHub may hide the primary email — fetch from /user/emails
  if (!email && emailsRes.ok) {
    const emails = await emailsRes.json();
    const primary = emails.find((e) => e.primary && e.verified);
    email = primary?.email || emails[0]?.email || null;
  }

  if (!email) throw new Error('GitHub account has no accessible email address');

  return {
    providerUserId: String(user.id),
    email,
    name: user.name || user.login || null,
    avatarUrl: user.avatar_url || null,
  };
}

// ── Step 3: Upsert user + OAuth account ──────────────────────────────────────

/**
 * Handle the OAuth callback: validate state, exchange code, upsert user.
 *
 * @param {'google'|'github'} provider
 * @param {string} code
 * @param {string} state
 * @param {string} [ipAddress]
 * @returns {Promise<{ accessToken: string, refreshToken: string, userId: number, isNewUser: boolean }>}
 */
export async function handleCallback(provider, code, state, ipAddress) {
  // Validate CSRF state
  const stateEntry = consumeState(state);
  if (!stateEntry) throw Object.assign(new Error('Invalid or expired OAuth state'), { status: 400 });

  const { tenantId } = stateEntry;

  // Exchange code for access token
  const tokens = await exchangeCodeForTokens(provider, code);
  const accessToken = tokens.access_token;

  // Fetch profile from provider
  const profile = provider === 'google'
    ? await fetchGoogleProfile(accessToken)
    : await fetchGithubProfile(accessToken);

  const { providerUserId, email, name, avatarUrl } = profile;

  // Upsert in a transaction: find/create user, link OAuth account
  const { user, isNewUser } = await prisma.$transaction(async (tx) => {
    // Check if this OAuth account already exists
    const existingOAuth = await tx.oAuthAccount.findUnique({
      where: { provider_providerUserId: { provider, providerUserId } },
      include: { user: true },
    });

    if (existingOAuth) {
      // Update profile data and return existing user
      await tx.oAuthAccount.update({
        where: { id: existingOAuth.id },
        data: { accessToken, name, avatarUrl, updatedAt: new Date() },
      });
      return { user: existingOAuth.user, isNewUser: false };
    }

    // Try to link to an existing user by email (account linking)
    let user = await tx.user.findFirst({ where: { email, tenantId } });
    let isNewUser = false;

    if (!user) {
      // Create a new user — no password (OAuth-only accounts have null password)
      user = await tx.user.create({
        data: { tenantId, email, password: null },
      });
      isNewUser = true;
    }

    // Create the OAuth account link
    await tx.oAuthAccount.create({
      data: { userId: user.id, provider, providerUserId, accessToken, name, avatarUrl },
    });

    return { user, isNewUser };
  });

  // Issue JWT pair
  const jwtTokens = generateTokens(user);
  await prisma.user.update({
    where: { id: user.id },
    data: { refreshToken: jwtTokens.refreshToken },
  });

  await log({
    category: AuditCategory.AUTH,
    action: isNewUser ? 'OAUTH_REGISTER' : 'OAUTH_LOGIN',
    actor: String(user.id),
    resourceId: String(user.id),
    metadata: { provider, email, isNewUser },
    ipAddress,
  });

  return { ...jwtTokens, userId: user.id, isNewUser };
}

/**
 * List all OAuth accounts linked to a user.
 *
 * @param {number} userId
 * @returns {Promise<Array>}
 */
export async function getLinkedAccounts(userId) {
  return prisma.oAuthAccount.findMany({
    where: { userId },
    select: { id: true, provider: true, name: true, avatarUrl: true, createdAt: true },
  });
}

/**
 * Unlink an OAuth account from a user.
 * Prevents unlinking if it's the only auth method (no password set).
 *
 * @param {number} userId
 * @param {string} provider
 */
export async function unlinkAccount(userId, provider) {
  const [oauthAccounts, user] = await Promise.all([
    prisma.oAuthAccount.findMany({ where: { userId } }),
    prisma.user.findUnique({ where: { id: userId }, select: { password: true } }),
  ]);

  const accountToRemove = oauthAccounts.find((a) => a.provider === provider);
  if (!accountToRemove) throw Object.assign(new Error(`No ${provider} account linked`), { status: 404 });

  // Safety: must have another login method
  const otherOAuth = oauthAccounts.filter((a) => a.provider !== provider);
  if (otherOAuth.length === 0 && !user?.password) {
    throw Object.assign(
      new Error('Cannot unlink the only authentication method. Set a password first.'),
      { status: 400 },
    );
  }

  await prisma.oAuthAccount.delete({ where: { id: accountToRemove.id } });
}

export default { getAuthorizationUrl, handleCallback, getLinkedAccounts, unlinkAccount };
