import type { Request, Response, NextFunction } from 'express'
import { getDb } from './db.js'
import jwt, { SignOptions, VerifyOptions } from 'jsonwebtoken'

export type AuthUser = { id: string; email: string; name: string; role: 'admin' | 'manager' | 'agent' | 'viewer' }

type JwtPayload = { sub: string; email: string; name: string; role: string; iat?: number; exp?: number }

const JWT_SECRET = (() => {
  const secret = process.env.JWT_SECRET
  const env = process.env.NODE_ENV || 'development'
  if (!secret) {
    if (env === 'development' || env === 'test') {
      console.warn('[auth] JWT_SECRET is not set. Falling back to an insecure development secret. Do not use this in production.')
      return 'dev-secret'
    }
    throw new Error('JWT_SECRET must be configured for secure token signing')
  }
  if (secret.length < 32) {
    console.warn('[auth] JWT_SECRET should be at least 32 characters. Consider using a longer secret for better security.')
  }
  return secret
})()

const SIGN_OPTIONS: SignOptions = {
  expiresIn: (process.env.JWT_EXPIRES || '15m') as any,
  algorithm: 'HS256'
}
if (process.env.JWT_ISSUER) {
  SIGN_OPTIONS.issuer = process.env.JWT_ISSUER
}
if (process.env.JWT_AUDIENCE) {
  SIGN_OPTIONS.audience = process.env.JWT_AUDIENCE
}

const VERIFY_OPTIONS: VerifyOptions = {
  algorithms: ['HS256']
}
if (process.env.JWT_ISSUER) {
  VERIFY_OPTIONS.issuer = process.env.JWT_ISSUER
}
if (process.env.JWT_AUDIENCE) {
  VERIFY_OPTIONS.audience = process.env.JWT_AUDIENCE
}

export function signToken(u: { id: string; email: string; name: string; role: string }) {
  return jwt.sign({ sub: u.id, email: u.email, name: u.name, role: normalizeRole(u.role) } as JwtPayload, JWT_SECRET, SIGN_OPTIONS)
}

export function verifyToken(token: string): JwtPayload | null {
  try {
    return jwt.verify(token, JWT_SECRET, VERIFY_OPTIONS) as JwtPayload
  } catch {
    return null
  }
}

function normalizeRole(role?: string | null): AuthUser['role'] {
  switch ((role || '').toLowerCase()) {
    case 'admin': return 'admin'
    case 'manager': return 'manager'
    case 'viewer': return 'viewer'
    case 'agent': return 'agent'
    case 'employee': return 'agent'
    default: return 'agent'
  }
}

// Attach req.user based on Authorization bearer token
export async function authenticateOptional(req: Request, _res: Response, next: NextFunction) {
  try {
    const auth = req.header('authorization') || ''
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : ''
    if (!token) return next()
    const payload = verifyToken(token)
    if (!payload) return next()
    const [rows] = await getDb().execute('SELECT id, email, name, role FROM users WHERE id = ?', [payload.sub])
    const record = (rows as any[])[0]
    if (!record) return next()
    const role = normalizeRole(record.role)
    ;(req as any).user = { id: record.id, email: record.email, name: record.name, role }
  } catch {
    // ignore; fall through to next
  }
  next()
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const u = (req as any).user as AuthUser | undefined
  if (!u) return res.status(401).json({ error: 'unauthorized' })
  next()
}

export function requireRole(...roles: Array<AuthUser['role']>) {
  return (req: Request, res: Response, next: NextFunction) => {
    const u = (req as any).user as AuthUser | undefined
    if (!u) return res.status(401).json({ error: 'unauthorized' })
    if (!roles.includes(u.role)) return res.status(403).json({ error: 'forbidden' })
    next()
  }
}
