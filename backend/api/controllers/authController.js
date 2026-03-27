/* eslint-disable no-unused-vars */
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import prisma from '../../lib/prisma.js';
import {
  getAuthorizationUrl,
  handleCallback,
  getLinkedAccounts as getLinkedAccountsService,
  unlinkAccount as unlinkAccountService,
} from '../../services/oauthService.js';

const STELLAR_ADDRESS_RE = /^G[A-Z2-7]{55}$/;

function normalizeWalletAddress(body = {}) {
  return body.walletAddress || body.stellarAddress || null;
}

// Helper to generate tokens
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { userId: user.id, tenantId: user.tenantId },
    process.env.JWT_ACCESS_SECRET || 'fallback_access_secret',
    { expiresIn: process.env.JWT_ACCESS_EXPIRATION || '15m' },
  );

  const refreshToken = jwt.sign(
    { userId: user.id, tenantId: user.tenantId },
    process.env.JWT_REFRESH_SECRET || 'fallback_refresh_secret',
    { expiresIn: process.env.JWT_REFRESH_EXPIRATION || '7d' },
  );

  return { accessToken, refreshToken };
};

export const register = async (req, res) => {
  try {
    const { email, password } = req.body;
    const tenantId = req.tenant?.id;

    if (!tenantId) {
      return res.status(400).json({ error: 'Tenant context is required' });
    }

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (walletAddress && !STELLAR_ADDRESS_RE.test(walletAddress)) {
      return res.status(400).json({ error: 'Invalid Stellar wallet address' });
    }

    // Check if user exists
    const existingUser = await prisma.user.findFirst({
      where: { email, tenantId },
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    if (walletAddress) {
      const existingWalletUser = await prisma.user.findFirst({
        where: { tenantId, walletAddress },
        select: { id: true },
      });

      if (existingWalletUser) {
        return res.status(400).json({ error: 'Wallet address is already linked to another user' });
      }
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = await prisma.user.create({
      data: {
        tenantId,
        email,
        walletAddress,
        password: hashedPassword,
      },
    });

    res.status(201).json({
      message: 'User registered successfully',
      userId: user.id,
      tenant: { id: req.tenant.id, slug: req.tenant.slug },
    });
  } catch (error) {
    console.error('[Register] Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const tenantId = req.tenant?.id;

    if (!tenantId) {
      return res.status(400).json({ error: 'Tenant context is required' });
    }

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await prisma.user.findFirst({
      where: { email, tenantId },
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    // Save refresh token to user in DB
    await prisma.user.update({
      where: { id: user.id },
      data: { refreshToken },
    });

    res.json({
      accessToken,
      refreshToken,
      userId: user.id,
      tenant: { id: req.tenant.id, slug: req.tenant.slug },
    });
  } catch (error) {
    console.error('[Login] Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

export const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const tenantId = req.tenant?.id;

    if (!tenantId) {
      return res.status(400).json({ error: 'Tenant context is required' });
    }

    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token is required' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(
        refreshToken,
        process.env.JWT_REFRESH_SECRET || 'fallback_refresh_secret',
      );
    } catch (_err) {
      return res.status(403).json({ error: 'Invalid or expired refresh token' });
    }

    if (decoded.tenantId && decoded.tenantId !== tenantId) {
      return res.status(403).json({ error: 'Refresh token does not belong to this tenant' });
    }

    // Verify against database
    const user = await prisma.user.findFirst({
      where: { id: decoded.userId, tenantId },
    });

    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    // Generate NEW tokens
    const tokens = generateTokens(user);

    // Update refresh token in DB
    await prisma.user.update({
      where: { id: user.id },
      data: { refreshToken: tokens.refreshToken },
    });

    res.json({ ...tokens, walletAddress: user.walletAddress });
  } catch (error) {
    console.error('[Refresh] Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

export const logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const tenantId = req.tenant?.id;

    // We could extract userId from auth middleware here if this route was protected.
    // However, logout is often called just with the token to revoke.
    // If the route is protected, we can just use req.user.userId

    // Attempt to decode the token to find the user
    let decoded;
    try {
      if (refreshToken) {
        decoded = jwt.verify(
          refreshToken,
          process.env.JWT_REFRESH_SECRET || 'fallback_refresh_secret',
          { ignoreExpiration: true }, // allow logout even if expired
        );
      }
    } catch (_err) {
      // If we can't decode, just move on
    }

    if (decoded && decoded.userId) {
      if (decoded.tenantId && tenantId && decoded.tenantId !== tenantId) {
        return res.status(403).json({ error: 'Refresh token does not belong to this tenant' });
      }

      await prisma.user.updateMany({
        where: { id: decoded.userId, tenantId: tenantId ?? decoded.tenantId },
        data: { refreshToken: null },
      });
    }

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('[Logout] Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// ── OAuth2 handlers ───────────────────────────────────────────────────────────

const SUPPORTED_PROVIDERS = ['google', 'github'];

/**
 * GET /api/auth/oauth/:provider
 * Redirect the user to the provider's authorization page.
 */
export const oauthRedirect = (req, res) => {
  try {
    const { provider } = req.params;
    if (!SUPPORTED_PROVIDERS.includes(provider)) {
      return res.status(400).json({ error: `Unsupported provider: ${provider}` });
    }

    const tenantId = req.tenant?.id;
    if (!tenantId) return res.status(400).json({ error: 'Tenant context is required' });

    const { url } = getAuthorizationUrl(provider, tenantId);
    res.redirect(url);
  } catch (err) {
    console.error('[OAuth Redirect] Error:', err);
    res.status(500).json({ error: err.message });
  }
};

/**
 * GET /api/auth/oauth/:provider/callback
 * Handle the authorization code callback from the provider.
 */
export const oauthCallback = async (req, res) => {
  try {
    const { provider } = req.params;
    const { code, state, error: providerError } = req.query;

    if (providerError) {
      return res.status(400).json({ error: `Provider error: ${providerError}` });
    }

    if (!code || !state) {
      return res.status(400).json({ error: 'Missing code or state parameter' });
    }

    if (!SUPPORTED_PROVIDERS.includes(provider)) {
      return res.status(400).json({ error: `Unsupported provider: ${provider}` });
    }

    const ipAddress = req.ip || req.headers['x-forwarded-for'];
    const result = await handleCallback(provider, code, state, ipAddress);

    // In a real app you'd redirect to the frontend with tokens in query params
    // or set an httpOnly cookie. Returning JSON here for API consumers.
    res.json(result);
  } catch (err) {
    console.error('[OAuth Callback] Error:', err);
    res.status(err.status ?? 500).json({ error: err.message });
  }
};

/**
 * GET /api/auth/linked-accounts
 * List all OAuth providers linked to the authenticated user.
 */
export const getLinkedAccounts = async (req, res) => {
  try {
    const accounts = await getLinkedAccountsService(req.user.userId);
    res.json(accounts);
  } catch (err) {
    console.error('[Linked Accounts] Error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * DELETE /api/auth/linked-accounts/:provider
 * Unlink a social login provider from the authenticated user.
 */
export const unlinkAccount = async (req, res) => {
  try {
    const { provider } = req.params;
    if (!SUPPORTED_PROVIDERS.includes(provider)) {
      return res.status(400).json({ error: `Unsupported provider: ${provider}` });
    }
    await unlinkAccountService(req.user.userId, provider);
    res.json({ message: `${provider} account unlinked successfully` });
  } catch (err) {
    console.error('[Unlink Account] Error:', err);
    res.status(err.status ?? 500).json({ error: err.message });
  }
};

export default { register, login, refresh, logout, oauthRedirect, oauthCallback, getLinkedAccounts, unlinkAccount };
