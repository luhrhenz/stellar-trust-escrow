import express from 'express';
import authController from '../controllers/authController.js';
import authMiddleware from '../middleware/auth.js';

const router = express.Router();

// ── Email / password ──────────────────────────────────────────────────────────
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/refresh', authController.refresh);
router.post('/logout', authMiddleware, authController.logout);

// ── OAuth2 social login ───────────────────────────────────────────────────────

/** GET /api/auth/oauth/:provider — redirect to provider authorization page */
router.get('/oauth/:provider', authController.oauthRedirect);

/** GET /api/auth/oauth/:provider/callback — handle provider callback */
router.get('/oauth/:provider/callback', authController.oauthCallback);

// ── Account linking (requires auth) ──────────────────────────────────────────

/** GET /api/auth/linked-accounts — list linked OAuth providers */
router.get('/linked-accounts', authMiddleware, authController.getLinkedAccounts);

/** DELETE /api/auth/linked-accounts/:provider — unlink a provider */
router.delete('/linked-accounts/:provider', authMiddleware, authController.unlinkAccount);

export default router;
