import 'dotenv/config'
import express, { type Request, type Response, type NextFunction } from 'express'
import cors, { type CorsOptions } from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import { migrate, getDb } from './db.js'
import { v4 as uuid } from 'uuid'
import { z } from 'zod'
import bcrypt from 'bcrypt'
import { createHash, createHmac } from 'node:crypto'
import path from 'node:path'
import { promises as fs } from 'node:fs'
import { fileTypeFromFile } from 'file-type'
import pdfParse from 'pdf-parse/lib/pdf-parse.js'
import mammoth from 'mammoth'
import multer, { MulterError } from 'multer'
import Sentiment from 'sentiment'
import { authenticateOptional, requireAuth, requireRole, signToken, type AuthUser } from './rbac.js'
import { createEnterpriseRouter, createEnterpriseSchema } from './enterpriseAnalytics.js'

const DOCUMENT_UPLOAD_DIR = process.env.DOCUMENTS_DIR || path.resolve(process.cwd(), 'uploads')
const MAX_DOCUMENT_BYTES = Number(process.env.MAX_DOCUMENT_BYTES || 25 * 1024 * 1024)
const MAX_TEXT_SNAPSHOT_LEN = Number(process.env.MAX_TEXT_SNAPSHOT_LEN || 50_000)
const SEARCH_RESULT_LIMIT = Number(process.env.SEARCH_RESULT_LIMIT || 20)
const EMAIL_SYNC_TOKEN = process.env.EMAIL_SYNC_TOKEN || ''
const EMAIL_DEFAULT_FROM = process.env.EMAIL_DEFAULT_FROM || 'noreply@example.com'
const EMAIL_DELIVERY_MODE = (process.env.EMAIL_DELIVERY_MODE || 'log').toLowerCase()
const CHAT_WEBHOOK_TIMEOUT = Number(process.env.CHAT_WEBHOOK_TIMEOUT || 8000)
const CHAT_WEBHOOK_TOKEN = process.env.CHAT_WEBHOOK_TOKEN || ''
const DEFAULT_TENANT_KEY = process.env.TENANT_KEY || 'default'
const WEBHOOK_TIMEOUT_MS = Number(process.env.WEBHOOK_TIMEOUT_MS || 7000)
const WEBHOOK_SIGNATURE_HEADER = process.env.WEBHOOK_SIGNATURE_HEADER || 'X-CRM-Signature'
const INTEGRATION_EVENT_VALUES = [
  'tender.created',
  'tender.updated',
  'task.created',
  'task.updated',
  'approval.decision',
  'custom_field.updated',
  'communication.email.sent'
] as const
const SUPPORTED_INTEGRATION_EVENTS = new Set<string>(INTEGRATION_EVENT_VALUES)

const documentStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, DOCUMENT_UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '')
    const name = `${uuid()}${ext}`
    cb(null, name)
  }
})

const documentUpload = multer({ storage: documentStorage, limits: { fileSize: MAX_DOCUMENT_BYTES } })

const sentimentAnalyzer = new Sentiment()
const ALLOWED_DOCUMENT_MIME_TYPES = new Set<string>([
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/plain',
  'text/csv',
  'application/json',
  'application/xml',
  'text/xml',
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp'
])
const BLOCKED_USER_AGENT_PATTERNS: RegExp[] = [
  /burp/i,
  /owasp/i,
  /acunetix/i,
  /nessus/i,
  /sqlmap/i,
  /metasploit/i,
  /fiddler/i,
  /postman-runtime/i
]
const SUSPICIOUS_URL_PATTERNS: RegExp[] = [
  /\.\.(?:\\|\/)/,
  /\/etc\/passwd/i,
  /\/wp-admin/i,
  /\/phpmyadmin/i,
  /\/server-status/i,
  /\.(?:ini|env|log)(?:\?|$)/i
]
const MAGIC_PACKET_SIGNATURES = [
  'ff:ff:ff:ff:ff:ff',
  'ffffffffffff',
  'wake-on-lan',
  'magic packet',
  'magic-packet',
  'sec-tcp-probe'
]

function normalizeSignatureForComparison(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '')
}
const MAGIC_PACKET_SIGNATURES_NORMALIZED = MAGIC_PACKET_SIGNATURES
  .map(normalizeSignatureForComparison)
  .filter(Boolean)
const IP_ALLOWLIST_MATCHERS: Array<(ip: string) => boolean> = (process.env.SECURITY_IP_ALLOWLIST || '')
  .split(',')
  .map(value => value.trim())
  .filter(value => value.length > 0)
  .map(value => {
    if (value === '*') {
      return () => true
    }
    const pattern = '^' + escapeRegExp(value).replace(/\\\*/g, '.*') + '$'
    const regex = new RegExp(pattern)
    return (ip: string) => regex.test(ip)
  })
const IS_IP_ALLOWLIST_ENABLED = IP_ALLOWLIST_MATCHERS.length > 0

function numberFromEnv(name: string, fallback: number): number {
  const raw = process.env[name]
  if (!raw) return fallback
  const parsed = Number(raw)
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback
  return parsed
}

function createTimestamps(date = new Date()): { iso: string; sql: string } {
  const iso = date.toISOString()
  const sql = iso.slice(0, 19).replace('T', ' ')
  return { iso, sql }
}

const SECURITY_STRIKE_LIMIT = numberFromEnv('SECURITY_STRIKE_LIMIT', 3)
const SECURITY_STRIKE_WINDOW_MS = numberFromEnv('SECURITY_STRIKE_WINDOW_MINUTES', 15) * 60 * 1000
const SECURITY_BLOCK_DURATION_MS = numberFromEnv('SECURITY_QUARANTINE_MINUTES', 30) * 60 * 1000
const HSTS_MAX_AGE_SECONDS = numberFromEnv('HSTS_MAX_AGE_SECONDS', 60 * 60 * 24 * 30)
const MAX_SECURITY_LOG_SNIPPET = numberFromEnv('SECURITY_LOG_SNIPPET', 160)

type SecurityStrikeState = {
  strikes: number
  lastStrikeAt: number
  blockedUntil: number
}

const securityStrikeState = new Map<string, SecurityStrikeState>()

function securityLog(event: string, payload: Record<string, unknown>) {
  const entry = { event, ...payload, at: new Date().toISOString() }
  console.warn('[security]', entry)
  const summaryParts = [
    event,
    typeof payload.ip === 'string' ? `ip=${payload.ip}` : null,
    typeof payload.reason === 'string' ? `reason=${payload.reason}` : null,
    payload.requestId ? `requestId=${payload.requestId}` : null
  ].filter(Boolean)
  if (summaryParts.length > 0) {
    console.log(`[security] ${summaryParts.join(' | ')}`)
  } else {
    console.log(`[security] ${event}`)
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function normalizeClientIp(ip: string | undefined | null): string {
  if (!ip) return 'unknown'
  if (ip.startsWith('::ffff:') && ip.length > 7) {
    return ip.slice(7)
  }
  if (ip === '::1') return '127.0.0.1'
  return ip
}

function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for']
  let raw: string | undefined
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    raw = forwarded.split(',')[0].trim()
  } else if (Array.isArray(forwarded) && forwarded.length > 0) {
    raw = forwarded[0]
  } else {
    raw = req.socket?.remoteAddress || req.ip || 'unknown'
  }
  return normalizeClientIp(raw)
}

function truncateMeta(value: string | undefined): string | undefined {
  if (!value) return undefined
  return value.length > MAX_SECURITY_LOG_SNIPPET ? `${value.slice(0, MAX_SECURITY_LOG_SNIPPET)}…` : value
}

function containsMagicSignature(value: string | undefined): boolean {
  if (!value) return false
  const normalized = normalizeSignatureForComparison(value)
  if (!normalized) return false
  return MAGIC_PACKET_SIGNATURES_NORMALIZED.some(sig => normalized.includes(sig))
}

function recordSecurityStrike(ip: string, reason: string, meta?: Record<string, unknown>): boolean {
  const now = Date.now()
  const existing = securityStrikeState.get(ip)
  let nextState: SecurityStrikeState
  if (!existing || now - existing.lastStrikeAt > SECURITY_STRIKE_WINDOW_MS) {
    nextState = { strikes: 1, lastStrikeAt: now, blockedUntil: 0 }
  } else {
    nextState = {
      strikes: existing.strikes + 1,
      lastStrikeAt: now,
      blockedUntil: existing.blockedUntil
    }
  }
  if (nextState.strikes >= SECURITY_STRIKE_LIMIT && SECURITY_BLOCK_DURATION_MS > 0) {
    nextState.blockedUntil = now + SECURITY_BLOCK_DURATION_MS
  }
  securityStrikeState.set(ip, nextState)
  securityLog('strike', {
    ip,
    reason,
    strikes: nextState.strikes,
    blockedUntil: nextState.blockedUntil || undefined,
    meta
  })
  return nextState.blockedUntil > now
}

function isIpQuarantined(ip: string): boolean {
  const entry = securityStrikeState.get(ip)
  if (!entry) return false
  const now = Date.now()
  if (entry.blockedUntil && entry.blockedUntil > now) {
    return true
  }
  if ((entry.blockedUntil && entry.blockedUntil <= now) || now - entry.lastStrikeAt > SECURITY_STRIKE_WINDOW_MS) {
    securityStrikeState.delete(ip)
  }
  return false
}

function isIpAllowlisted(ip: string): boolean {
  if (!IS_IP_ALLOWLIST_ENABLED) return true
  return IP_ALLOWLIST_MATCHERS.some(match => {
    try {
      return match(ip)
    } catch {
      return false
    }
  })
}

function shouldAttemptEmailDelivery() {
  return EMAIL_DELIVERY_MODE === 'smtp' || EMAIL_DELIVERY_MODE === 'webhook'
}

async function deliverEmailMessage(input: {
  to: string[]
  subject: string
  html?: string | null
  text?: string | null
}) {
  if (!shouldAttemptEmailDelivery()) {
    console.log('[email] Delivery mode set to log; recording only')
    return { status: 'logged' as const, detail: 'Email delivery is disabled; logged only.' }
  }

  try {
    if (EMAIL_DELIVERY_MODE === 'webhook') {
      const webhookUrl = process.env.EMAIL_WEBHOOK_URL
      if (webhookUrl) {
        const controller = new AbortController()
        const timeout = setTimeout(() => controller.abort(), 8000)
        try {
          const response = await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            signal: controller.signal,
            body: JSON.stringify({
              to: input.to,
              subject: input.subject,
              html: input.html,
              text: input.text,
              sentAt: new Date().toISOString()
            })
          })
          clearTimeout(timeout)
          if (!response.ok) {
            const detail = await response.text().catch(() => response.statusText)
            console.warn('[email] Webhook returned non-200:', detail)
            return { status: 'webhook_failed' as const, detail }
          }
          return { status: 'sent' as const, detail: 'Webhook accepted message.' }
        } finally {
          clearTimeout(timeout)
        }
      }
    }
    // SMTP delivery not implemented; treat as queued
    return { status: 'queued' as const, detail: 'SMTP delivery not configured.' }
  } catch (err: any) {
    console.error('[email] Delivery error:', err)
    return { status: 'failed' as const, detail: err?.message || 'Delivery failed' }
  }
}

type ChatDeliveryResult = { status: 'failed'; detail: string } | { status: 'sent'; detail: string }

async function postChatWebhook(connector: {
  type: string
  webhookUrl?: string | null
}, payload: Record<string, unknown>): Promise<ChatDeliveryResult> {
  if (!connector?.webhookUrl) {
    return { status: 'failed' as const, detail: 'Missing webhook URL' }
  }
  try {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), CHAT_WEBHOOK_TIMEOUT)
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    const body = JSON.stringify(payload)
    const response = await fetch(connector.webhookUrl, { method: 'POST', headers, body, signal: controller.signal })
    clearTimeout(timeout)
    if (!response.ok) {
      const detail = await response.text().catch(() => response.statusText)
      return { status: 'failed' as const, detail }
    }
    return { status: 'sent' as const, detail: 'Webhook accepted message.' }
  } catch (err: any) {
    console.error('[chat] Webhook error:', err)
    return { status: 'failed' as const, detail: err?.message || 'Webhook failed' }
  }
}

type WebhookRecord = {
  id: string
  name: string
  event_type: string
  target_url: string
  shared_secret?: string | null
  headers?: any
}

async function listActiveWebhooks(eventType: string): Promise<WebhookRecord[]> {
  if (!SUPPORTED_INTEGRATION_EVENTS.has(eventType)) return []
  const [rows] = await getDb().execute(
    'SELECT id, name, event_type, target_url, shared_secret, headers FROM webhook_subscriptions WHERE event_type = ? AND is_active = 1',
    [eventType]
  )
  return rows as WebhookRecord[]
}

function computeWebhookSignature(secret: string | null | undefined, body: string) {
  if (!secret) return null
  return createHmac('sha256', secret).update(body).digest('hex')
}

async function dispatchWebhooks(eventType: string, payload: Record<string, unknown>) {
  const hooks = await listActiveWebhooks(eventType)
  if (!hooks.length) return
  const body = JSON.stringify({ event: eventType, payload, emittedAt: new Date().toISOString() })
  await Promise.allSettled(hooks.map(async hook => {
    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS)
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-CRM-Event': eventType,
        'X-CRM-Hook-Id': hook.id
      }
      if (hook.shared_secret) {
        const sig = computeWebhookSignature(hook.shared_secret, body)
        if (sig) headers[WEBHOOK_SIGNATURE_HEADER] = sig
      }
      if (hook.headers && typeof hook.headers === 'object') {
        Object.entries(hook.headers).forEach(([key, value]) => {
          if (typeof value === 'string' && key) headers[key] = value
        })
      }
      const response = await fetch(hook.target_url, {
        method: 'POST',
        headers,
        body,
        signal: controller.signal
      })
      clearTimeout(timeout)
      if (!response.ok) {
        const detail = await response.text().catch(() => response.statusText)
        console.warn('[webhook]', hook.id, 'returned non-200', detail)
      }
    } catch (err: any) {
      console.error('[webhook] dispatch error', hook.id, err?.message || err)
    }
  }))
}

function queueIntegrationEvent(eventType: string, payload: Record<string, unknown>) {
  if (!SUPPORTED_INTEGRATION_EVENTS.has(eventType)) return
  // Fire and forget
  dispatchWebhooks(eventType, payload).catch(err => console.error('[webhook] unhandled error', err))
}

const REQUEST_BODY_LIMIT = process.env.REQUEST_BODY_LIMIT || '1mb'
const ENFORCE_HTTPS = process.env.ENFORCE_HTTPS === 'true'
const app = express()
const corsOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5173').split(',').map(s => s.trim()).filter(Boolean)
if (corsOrigins.length === 0) {
  corsOrigins.push('http://localhost:5173')
}
const trustProxySetting = process.env.TRUST_PROXY
if (trustProxySetting !== undefined) {
  if (trustProxySetting === 'true') {
    app.set('trust proxy', true)
  } else if (trustProxySetting === 'false') {
    app.set('trust proxy', false)
  } else if (!Number.isNaN(Number(trustProxySetting))) {
    app.set('trust proxy', Number(trustProxySetting))
  } else {
    app.set('trust proxy', trustProxySetting)
  }
} else {
  app.set('trust proxy', false)
}
const corsOptions: CorsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true) // allow curl/postman
    if (corsOrigins.includes(origin)) return cb(null, true)
    const corsError = new Error('CORS not allowed')
    ;(corsError as any).status = 403
    return cb(corsError, false)
  },
  credentials: process.env.COOKIES_AUTH === 'true'
}
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: numberFromEnv('GLOBAL_RATE_LIMIT', 300),
  standardHeaders: true,
  legacyHeaders: false
})
app.use(cors(corsOptions))
app.options('*', cors(corsOptions))
app.use(globalLimiter)
app.use(express.json({ limit: REQUEST_BODY_LIMIT }))
app.use(express.urlencoded({ extended: false, limit: REQUEST_BODY_LIMIT }))
app.use((req, res, next) => {
  const headerValue = req.headers['x-request-id']
  const incoming = typeof headerValue === 'string' && headerValue.trim().length >= 8 ? headerValue.trim() : undefined
  const requestId = incoming || uuid()
  res.setHeader('X-Request-Id', requestId)
  ;(req as any).requestId = requestId
  next()
})
app.disable('x-powered-by')
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-site' },
  hsts: {
    maxAge: HSTS_MAX_AGE_SECONDS,
    includeSubDomains: true,
    preload: false
  },
  referrerPolicy: { policy: 'no-referrer' }
}))
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Expires', '0')
  next()
})
if (ENFORCE_HTTPS) {
  app.use((req, res, next) => {
    const proto = (req.headers['x-forwarded-proto'] || req.protocol || '').toString().toLowerCase()
    if (proto === 'https' || req.secure) {
      return next()
    }
    const host = req.headers.host
    if (!host) {
      return res.status(400).json({ error: 'HTTPS required', requestId: res.getHeader('X-Request-Id') })
    }
    if (req.method === 'GET' || req.method === 'HEAD') {
      return res.redirect(301, `https://${host}${req.originalUrl}`)
    }
    return res.status(400).json({ error: 'HTTPS required', requestId: res.getHeader('X-Request-Id') })
  })
}

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: numberFromEnv('AUTH_RATE_LIMIT', 20),
  standardHeaders: true,
  legacyHeaders: false
})
app.use((req, res, next) => {
  const ip = getClientIp(req)
  if (!isIpAllowlisted(ip)) {
    securityLog('ip_not_allowlisted', {
      ip,
      path: req.originalUrl,
      method: req.method,
      requestId: res.getHeader('X-Request-Id')
    })
    return res.status(403).json({ error: 'Forbidden', requestId: res.getHeader('X-Request-Id') })
  }
  if (isIpQuarantined(ip)) {
    securityLog('blocked_request', {
      ip,
      path: req.originalUrl,
      method: req.method,
      requestId: res.getHeader('X-Request-Id')
    })
    return res.status(403).json({ error: 'Forbidden', requestId: res.getHeader('X-Request-Id') })
  }

  const userAgent = req.get('user-agent') || ''
  const url = req.originalUrl || req.url
  const headersSample = truncateMeta(Object.entries(req.headers)
    .map(([key, value]) => `${key}:${Array.isArray(value) ? value.join(',') : value ?? ''}`)
    .join('|'))

  const deny = (reason: string, meta?: Record<string, unknown>) => {
    const blockedNow = recordSecurityStrike(ip, reason, meta)
    if (blockedNow) {
      securityLog('ip_quarantined', { ip, reason, requestId: res.getHeader('X-Request-Id') })
    }
    return res.status(403).json({ error: 'Forbidden', requestId: res.getHeader('X-Request-Id') })
  }

  if (userAgent && BLOCKED_USER_AGENT_PATTERNS.some(pattern => pattern.test(userAgent))) {
    return deny('blocked_user_agent', { userAgent })
  }

  if (SUSPICIOUS_URL_PATTERNS.some(pattern => pattern.test(url))) {
    return deny('suspicious_url', { url })
  }

  if (containsMagicSignature(headersSample)) {
    return deny('magic_packet_header', { headersSample })
  }

  const loweredUrl = url.toLowerCase()
  if (containsMagicSignature(loweredUrl)) {
    return deny('magic_packet_url', { url })
  }

  if (typeof req.body === 'string' && containsMagicSignature(req.body)) {
    return deny('magic_packet_body', { bodySample: truncateMeta(req.body) })
  }

  if (req.body && typeof req.body === 'object') {
    try {
      const serialized = JSON.stringify(req.body)
      if (containsMagicSignature(serialized)) {
        return deny('magic_packet_body', { bodySample: truncateMeta(serialized) })
      }
    } catch {
      // ignore serialization errors
    }
  }

  next()
})
app.use(authenticateOptional)

// Initialize database and start server
async function initializeApp() {
  try {
    await ensureUploadDirectory()
    await migrate()
    console.log('Database migration completed successfully')
  await createEnterpriseSchema()
    await ensureAdminSeed()
    
    const port = Number(process.env.PORT || 4000)
    app.listen(port, () => {
      console.log(`CRM backend listening on http://localhost:${port}`)
    })
  } catch (error) {
    console.error('Failed to initialize application:', error)
    process.exit(1)
  }
}

// Start the application
initializeApp().catch(err => {
  console.error('Unhandled error during startup:', err)
  process.exit(1)
})

async function ensureUploadDirectory() {
  try {
    await fs.mkdir(DOCUMENT_UPLOAD_DIR, { recursive: true })
  } catch (error) {
    console.error('Failed to ensure upload directory:', error)
    throw error
  }
}

// Health
app.get('/health', (_req: Request, res: Response) => { res.json({ ok: true }) })

// Seed admin user from env if not present
async function ensureAdminSeed() {
  const email = (process.env.ADMIN_EMAIL || '').trim().toLowerCase()
  const name = (process.env.ADMIN_NAME || 'Admin').trim()
  const password = process.env.ADMIN_PASSWORD || ''
  if (!email || !password) {
    console.warn('Admin seed skipped: set ADMIN_EMAIL and ADMIN_PASSWORD in .env to seed an admin account')
    return
  }
  const [rows] = await getDb().execute('SELECT id FROM users WHERE email = ?', [email])
  if ((rows as any[]).length > 0) return
  const saltRounds = 12
  const salt = await bcrypt.genSalt(saltRounds)
  const passwordHash = await bcrypt.hash(password, salt)
  const id = uuid()
  await getDb().execute('INSERT INTO users (id, email, name, password_hash, salt, role) VALUES (?, ?, ?, ?, ?, ?)', [id, email, name, passwordHash, salt, 'admin'])
  console.log(`Seeded admin user: ${email}`)
}

// Authentication endpoints
const PasswordSchema = z.string()
  .min(12, 'Password must be at least 12 characters')
  .superRefine((value, ctx) => {
    if (!/[A-Z]/.test(value)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Password must include at least one uppercase letter' })
    }
    if (!/[a-z]/.test(value)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Password must include at least one lowercase letter' })
    }
    if (!/[0-9]/.test(value)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Password must include at least one number' })
    }
    if (!/[^A-Za-z0-9]/.test(value)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Password must include at least one special character' })
    }
  })

const SignupSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  email: z.string().email('Invalid email format'),
  password: PasswordSchema
})

const LoginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required')
})

app.post('/api/signup', authLimiter, async (req: Request, res: Response) => {
  try {
    const { name, email, password } = SignupSchema.parse(req.body)
    const emailLower = email.toLowerCase().trim()
    
    // Check if user already exists
    const [existing] = await getDb().execute('SELECT id FROM users WHERE email = ?', [emailLower])
    if ((existing as any[]).length > 0) {
      return res.status(400).json({ error: 'Email already registered' })
    }

  // New users default to agent; admin is seeded via env (see ensureAdminSeed)
  const role = 'agent'
    
    // Hash password
    const saltRounds = 12
    const salt = await bcrypt.genSalt(saltRounds)
    const passwordHash = await bcrypt.hash(password, salt)
    
    // Create user
    const userId = uuid()
    await getDb().execute(
      'INSERT INTO users (id, email, name, password_hash, salt, role) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, emailLower, name.trim(), passwordHash, salt, role]
    )
    
    // Return user session (JWT)
    const token = signToken({ id: userId, email: emailLower, name: name.trim(), role })
    return res.status(201).json({ token, userId, email: emailLower, name: name.trim(), role })
  } catch (err: any) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: err.errors[0].message })
    }
    console.error('Signup error:', err)
    if (res.headersSent) return
    return res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/login', authLimiter, async (req: Request, res: Response) => {
  try {
    const { email, password } = LoginSchema.parse(req.body)
    const emailLower = email.toLowerCase().trim()
    
    // Find user
    const [rows] = await getDb().execute('SELECT id, email, name, password_hash, role FROM users WHERE email = ?', [emailLower])
    const users = rows as any[]
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    
    const user = users[0]
    
    // Verify password
    const isValid = await bcrypt.compare(password, user.password_hash)
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    
    // Normalize role (legacy 'employee' => 'agent')
    const role = (user.role === 'employee') ? 'agent' : user.role
    // Return JWT session
    const token = signToken({ id: user.id, email: user.email, name: user.name, role })
    return res.json({ token, userId: user.id, email: user.email, name: user.name, role })
  } catch (err: any) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: err.errors[0].message })
    }
    console.error('Login error:', err)
    if (res.headersSent) return
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Basic session info endpoint
app.get('/api/me', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  res.json({ id: user.id, email: user.email, name: user.name, role: user.role })
})

app.get('/api/tenders', requireAuth, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user as AuthUser
    if (user.role === 'viewer') {
      return res.status(403).json({ error: 'forbidden' })
    }
    let sql = `
      SELECT t.*, e.email AS employee_email, owner.role AS owner_role
      FROM tenders t
      LEFT JOIN employees e ON t.employee_id = e.id OR t.employee_id = e.employee_id
      LEFT JOIN users owner ON t.owner_user_id = owner.id
    `
    const params: unknown[] = []
    if (user.role === 'agent') {
  const conditions: string[] = []
  const seenValues = new Set<string>()

  conditions.push('t.owner_user_id = ?')
  params.push(user.id)
  conditions.push('t.owner_user_id IS NULL')
  conditions.push("owner.role IN ('admin','manager')")

      if (user.email) {
        const normalizedEmail = user.email.toLowerCase()
        conditions.push('LOWER(t.allotted_to) = ?')
        params.push(normalizedEmail)
        conditions.push('LOWER(e.email) = ?')
        params.push(normalizedEmail)
      }

      if (user.email) {
        const employee = await findEmployeeRecord(user.email)
        if (employee) {
          const identifiers = new Set<string>()
          if (employee.id) identifiers.add(String(employee.id))
          if (employee.employee_id) identifiers.add(String(employee.employee_id))
          identifiers.forEach(identifier => {
            if (!seenValues.has(identifier)) {
              conditions.push('t.employee_id = ?')
              params.push(identifier)
              seenValues.add(identifier)
            }
          })
        }
      }

      if (conditions.length > 0) {
        sql += ` WHERE ${conditions.join(' OR ')}`
      }
    }
    sql += ' ORDER BY t.created_at DESC'
    const [rows] = await getDb().execute(sql, params)
    const mapped = (rows as any[]).map((r: any) => ({
      id: r.id,
      dateOfService: r.date_of_service,
      serialToken: r.serial_token,
      allottedTo: r.allotted_to,
      source: r.source,
      priority: r.priority,
      status: r.status,
      customerId: r.customer_id,
      customerName: r.customer_name,
      employeeId: r.employee_id,
      employeeName: r.employee_name,
      employeeEmail: r.employee_email,
      leadTitle: r.lead_title,
      leadDescription: r.lead_description,
      estimatedValue: r.estimated_value,
      followUpDate: r.follow_up_date,
      ownerUserId: r.owner_user_id,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    }))
    res.json(mapped)
  } catch (err: any) {
    console.error('Failed to load tenders:', err)
    if (res.headersSent) return
    res.status(500).json({ error: 'Internal server error' })
  }
})

// Tenders minimal REST
const TenderSchema = z.object({
  dateOfService: z.string().optional(),
  serialToken: z.string(),
  allottedTo: z.string().optional(),
  source: z.string().optional(),
  priority: z.string().optional(),
  status: z.string().optional(),
  customerId: z.string().optional(),
  customerName: z.string().optional(),
  employeeId: z.string().optional(),
  employeeName: z.string().optional(),
  leadTitle: z.string().optional(),
  leadDescription: z.string().optional(),
  estimatedValue: z.string().optional(),
  followUpDate: z.string().optional(),
  ownerUserId: z.string().optional()
})

const TaskStatusEnum = z.enum(['Pending', 'In Progress', 'Blocked', 'Completed'])
const TaskPriorityEnum = z.enum(['Low', 'Medium', 'High', 'Urgent'])
const TaskSchema = z.object({
  title: z.string().min(1, 'Title is required'),
  description: z.string().max(5000).optional(),
  priority: TaskPriorityEnum.default('Medium'),
  status: TaskStatusEnum.optional(),
  dueDate: z.string().optional(),
  employeeId: z.string().min(1, 'Employee is required'),
  team: z.string().max(128).optional(),
  remindBeforeMinutes: z.preprocess((value) => {
    if (value === null || value === undefined || value === '') return undefined
    return value
  }, z.coerce.number().int().min(5).max(60 * 24 * 14)).optional(),
  notes: z.string().max(10000).optional(),
  dependencies: z.array(z.string().min(1)).max(32).optional()
})

const ActivityEntityEnum = z.enum(['tender', 'customer', 'employee'])
const ActivityTypeEnum = z.enum(['comment', 'system', 'communication'])
const CommunicationDirectionEnum = z.enum(['inbound', 'outbound'])
const ActivityQuerySchema = z.object({
  entityType: ActivityEntityEnum,
  entityKey: z.string().min(1, 'entityKey is required')
})
const ActivityCreateSchema = ActivityQuerySchema.extend({
  text: z.string().trim().min(1, 'Text is required'),
  type: ActivityTypeEnum.optional(),
  channel: z.string().trim().max(32).optional(),
  direction: CommunicationDirectionEnum.optional(),
  subject: z.string().trim().max(255).optional(),
  occurredAt: z.string().datetime().optional(),
  metadata: z.record(z.unknown()).optional()
}).superRefine((data, ctx) => {
  if (data.type === 'communication') {
    if (!data.channel) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['channel'], message: 'Channel is required for communications' })
    }
    if (!data.direction) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['direction'], message: 'Direction is required for communications' })
    }
  }
})

const CommunicationCreateSchema = z.object({
  channel: z.string().trim().min(2, 'Channel is required').max(32),
  direction: CommunicationDirectionEnum,
  subject: z.string().trim().max(255).optional(),
  text: z.string().trim().min(1, 'Text is required'),
  occurredAt: z.string().datetime().optional(),
  metadata: z.record(z.unknown()).optional()
})

const CustomFieldTypeEnum = z.enum(['text', 'textarea', 'number', 'date', 'select', 'multiselect', 'boolean', 'json'])
const CustomFieldOptionSchema = z.object({ value: z.string().min(1, 'Option value required'), label: z.string().optional() })
const CustomFieldConfigSchema = z.object({
  options: z.array(CustomFieldOptionSchema).max(64).optional(),
  placeholder: z.string().max(255).optional(),
  helperText: z.string().max(255).optional(),
  min: z.number().optional(),
  max: z.number().optional(),
  step: z.number().positive().optional()
}).partial()
const CustomFieldDefaultValueSchema = z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.array(z.union([z.string(), z.number()])),
  z.record(z.unknown()),
  z.null()
])
const CustomFieldCreateSchema = z.object({
  entityType: z.string().trim().min(1).max(64),
  fieldKey: z.string().trim().min(1).max(64).regex(/^[a-zA-Z0-9_]+$/, 'Use alphanumeric characters or underscore'),
  label: z.string().trim().min(1).max(255),
  description: z.string().trim().max(2000).optional(),
  fieldType: CustomFieldTypeEnum,
  required: z.boolean().optional().default(false),
  config: CustomFieldConfigSchema.optional(),
  defaultValue: CustomFieldDefaultValueSchema.optional(),
  orderIndex: z.number().int().min(0).max(1000).optional()
})
const CustomFieldUpdateSchema = CustomFieldCreateSchema.partial().refine(data => Object.keys(data).length > 0, {
  message: 'No updates provided'
})
const CustomFieldValuesUpsertSchema = z.object({
  values: z.record(z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.array(z.any()),
    z.record(z.any()),
    z.null()
  ])).default({})
})

const LayoutSectionSchema = z.object({
  id: z.string().trim().min(1).max(64),
  label: z.string().trim().min(1).max(255),
  description: z.string().trim().max(1000).optional(),
  fieldKeys: z.array(z.string().trim().min(1).max(64)).max(64)
})
const EntityLayoutSchema = z.object({
  sections: z.array(LayoutSectionSchema).min(1)
})

const ColorSchema = z.string().regex(/^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{4}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})$/, 'Invalid hex color').optional().nullable()
const BrandingUpdateSchema = z.object({
  brandName: z.string().trim().max(255).optional().nullable(),
  logoUrl: z.string().trim().url().optional().nullable(),
  faviconUrl: z.string().trim().url().optional().nullable(),
  primaryColor: ColorSchema,
  accentColor: ColorSchema,
  backgroundColor: ColorSchema,
  textColor: ColorSchema,
  defaultLocale: z.string().trim().min(2).max(10).optional(),
  availableLocales: z.array(z.string().trim().min(2).max(10)).min(1).max(12).optional(),
  whiteLabel: z.record(z.unknown()).optional()
}).refine((data) => {
  if (data.availableLocales && data.defaultLocale && !data.availableLocales.includes(data.defaultLocale)) {
    return false
  }
  return true
}, {
  message: 'Default locale must be part of available locales',
  path: ['defaultLocale']
})

const WebhookHeadersSchema = z.record(z.string().min(1)).optional()
const IntegrationEventEnum = z.enum(INTEGRATION_EVENT_VALUES)
const WebhookCreateSchema = z.object({
  name: z.string().trim().min(1).max(255),
  eventType: IntegrationEventEnum,
  targetUrl: z.string().trim().url(),
  sharedSecret: z.string().max(255).optional().nullable(),
  headers: WebhookHeadersSchema,
  isActive: z.boolean().optional()
})
const WebhookUpdateSchema = WebhookCreateSchema.partial().refine(data => Object.keys(data).length > 0, {
  message: 'No updates provided'
})

const AssistantAskSchema = z.object({
  prompt: z.string().trim().min(4).max(2000)
})

const SegmentCreateSchema = z.object({
  segment: z.string().trim().min(2, 'Segment name is required').max(64),
  description: z.string().trim().max(500).optional(),
  color: z.string().trim().regex(/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/, 'Provide a valid hex color').optional()
})

const DocumentCategoryEnum = z.enum(['Tender', 'Customer', 'Team', 'Internal'])
const AttachmentEntityEnum = z.enum(['tender', 'customer'])
const DocumentPayloadSchema = z.object({
  name: z.string().trim().min(1, 'Name is required'),
  owner: z.string().trim().max(255).optional(),
  relatedTo: z.string().trim().max(255).optional(),
  category: DocumentCategoryEnum.optional(),
  tags: z.array(z.string().trim().min(1)).max(64).optional(),
  summary: z.string().trim().max(10000).optional(),
  link: z.string().trim().max(2000).optional(),
  fileName: z.string().trim().max(255).optional(),
  entityType: z.preprocess(val => typeof val === 'string' ? val.trim().toLowerCase() : val, AttachmentEntityEnum).optional(),
  entityId: z.preprocess(val => typeof val === 'string' ? val.trim() : val, z.string().min(1, 'entityId is required')).optional()
}).superRefine((data, ctx) => {
  if (data.entityType && !data.entityId) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['entityId'], message: 'entityId is required when entityType is provided' })
  }
  if (!data.entityType && data.entityId) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['entityType'], message: 'entityType is required when entityId is provided' })
  }
})

const DocumentQuerySchema = z.object({
  q: z.string().trim().optional(),
  category: DocumentCategoryEnum.optional(),
  tag: z.string().trim().optional()
})

type AttachmentEntity = z.infer<typeof AttachmentEntityEnum>

const isManager = (user: AuthUser | undefined) => user?.role === 'admin' || user?.role === 'manager'
const systemUser: AuthUser = { id: 'system', email: 'system@crm.local', name: 'System', role: 'admin' }

const EmailTemplateSchema = z.object({
  name: z.string().trim().min(3).max(128),
  description: z.string().trim().max(255).optional(),
  subject: z.string().trim().min(3).max(255),
  bodyHtml: z.string().optional(),
  bodyText: z.string().optional(),
  tags: z.array(z.string().trim().min(1)).max(32).optional(),
  isActive: z.boolean().optional()
})

const EmailSendSchema = z.object({
  templateId: z.string().uuid().optional(),
  to: z.array(z.string().trim().email()).min(1).max(16),
  subject: z.string().trim().min(1).max(255).optional(),
  body: z.string().trim().min(1).optional(),
  notes: z.string().trim().max(2000).optional()
}).superRefine((data, ctx) => {
  if (!data.templateId && (!data.subject || !data.body)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['subject'], message: 'Subject is required when not using a template' })
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['body'], message: 'Body is required when not using a template' })
  }
})

const InboundEmailSchema = z.object({
  tenderId: z.string().trim().min(1),
  externalId: z.string().trim().max(255).optional(),
  subject: z.string().trim().min(1).max(255),
  body: z.string().trim().min(1),
  from: z.string().trim().max(255),
  headers: z.record(z.string()).optional()
})

const ChatConnectorSchema = z.object({
  name: z.string().trim().min(3).max(128),
  type: z.enum(['slackWebhook', 'teamsWebhook', 'customWebhook']),
  webhookUrl: z.string().url().optional(),
  metadata: z.record(z.unknown()).optional(),
  isActive: z.boolean().optional()
})

const ChatMessageSendSchema = z.object({
  text: z.string().trim().min(1).max(5000),
  entityType: ActivityEntityEnum,
  entityId: z.string().trim().min(1).max(64)
})

const VoiceCallStatusEnum = z.enum(['completed', 'missed', 'scheduled', 'cancelled'])
const VoiceCallCreateSchema = z.object({
  entityType: ActivityEntityEnum,
  entityId: z.string().trim().min(1).max(64),
  subject: z.string().trim().max(255).optional(),
  participants: z.array(z.string().trim().min(1)).max(16).optional(),
  status: VoiceCallStatusEnum.default('completed'),
  outcome: z.string().trim().max(64).optional(),
  summary: z.string().trim().max(5000).optional(),
  recordingUrl: z.string().url().optional(),
  durationSeconds: z.number().int().min(0).max(24 * 3600).optional()
})

const VoiceCallUpdateSchema = VoiceCallCreateSchema.partial().extend({
  status: VoiceCallStatusEnum.optional()
})

const ApprovalPolicySchema = z.object({
  name: z.string().trim().min(3).max(128),
  description: z.string().trim().max(2000).optional(),
  criteria: z.record(z.unknown()).optional(),
  steps: z.array(z.object({
    label: z.string().trim().min(1),
    role: z.enum(['admin', 'manager', 'agent', 'viewer']).optional(),
    daysToRespond: z.number().int().min(1).max(30).optional()
  })).max(10).optional(),
  isActive: z.boolean().optional()
})

const ApprovalRequestSchema = z.object({
  policyId: z.string().uuid(),
  entityType: ActivityEntityEnum,
  entityId: z.string().trim().min(1),
  context: z.record(z.unknown()).optional()
})

const ApprovalDecisionSchema = z.object({
  status: z.enum(['approved', 'rejected', 'escalated', 'in_review']),
  notes: z.string().trim().max(2000).optional()
})

function normalizeString(value: unknown) {
  if (typeof value !== 'string') return undefined
  const trimmed = value.trim()
  return trimmed.length === 0 ? undefined : trimmed
}

function parseDocumentTags(raw: unknown): string[] {
  if (!raw) return []
  if (Array.isArray(raw)) {
    return raw
      .map(tag => normalizeString(tag))
      .filter((tag): tag is string => Boolean(tag))
  }
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw)
      if (Array.isArray(parsed)) {
        return parsed
          .map(tag => normalizeString(tag))
          .filter((tag): tag is string => Boolean(tag))
      }
    } catch {
      // ignore and fallback to CSV parsing
    }
    return raw
      .split(',')
      .map(tag => tag.trim())
      .filter(Boolean)
  }
  return []
}

function buildDocumentPayload(req: Request & { file?: Express.Multer.File }) {
  const base = req.body || {}
  const normalizedName = normalizeString(base.name)
  const fallbackName = (() => {
    if (req.file?.originalname) {
      const parsed = path.parse(req.file.originalname)
      return parsed.name || req.file.originalname
    }
    return undefined
  })()
  const payload = {
    name: normalizedName || fallbackName,
    owner: normalizeString(base.owner),
    relatedTo: normalizeString(base.relatedTo ?? base.related_to),
    category: (() => {
      const cat = normalizeString(base.category)
      if (!cat) return undefined
      const match = DocumentCategoryEnum.options.find(option => option.toLowerCase() === cat.toLowerCase())
      return match
    })(),
    tags: parseDocumentTags(base.tags),
    summary: normalizeString(base.summary),
    link: normalizeString(base.link),
    fileName: normalizeString(base.fileName ?? base.file_name) || req.file?.originalname || undefined,
    entityType: (() => {
      const value = normalizeString(base.entityType ?? base.entity_type)
      if (!value) return undefined
      const lower = value.toLowerCase()
      return AttachmentEntityEnum.options.includes(lower as any) ? lower as z.infer<typeof AttachmentEntityEnum> : undefined
    })(),
    entityId: normalizeString(base.entityId ?? base.entity_id)
  }
  return payload
}

type DocumentEntityLink = { entityType: string; entityId: string }

function mapDocumentRow(row: any, entities: DocumentEntityLink[] = []) {
  let tags: string[] = []
  try {
    if (Array.isArray(row.tags)) {
      tags = row.tags as string[]
    } else if (typeof row.tags === 'string') {
      tags = JSON.parse(row.tags)
    }
    if (!Array.isArray(tags)) tags = []
  } catch {
    tags = []
  }

  const normalizedTags = tags.filter(tag => typeof tag === 'string')
  return {
    id: row.id,
    name: row.name,
    owner: row.owner ?? undefined,
    relatedTo: row.related_to ?? undefined,
    category: row.category ?? undefined,
    tags: normalizedTags,
    summary: row.summary ?? undefined,
    link: row.link ?? undefined,
    fileName: row.file_name ?? undefined,
    fileSize: typeof row.file_size === 'number' ? row.file_size : undefined,
    mimeType: row.mime_type ?? undefined,
    uploadedAt: row.uploaded_at,
    updatedAt: row.updated_at,
    uploadedByUserId: row.uploaded_by_user_id ?? undefined,
    downloadUrl: row.storage_key ? `/api/documents/${row.id}/download` : undefined,
    textSnippet: typeof row.text_content === 'string' ? row.text_content.slice(0, 280) : undefined,
    entities
  }
}

function groupDocumentRows(rows: any[]): Array<ReturnType<typeof mapDocumentRow>> {
  const grouped = new Map<string, { row: any; entities: DocumentEntityLink[] }>()
  for (const raw of rows) {
    const id = raw.id
    if (!grouped.has(id)) {
      grouped.set(id, { row: raw, entities: [] })
    }
    const bucket = grouped.get(id)!
    if (raw.entity_type && raw.entity_id) {
      bucket.entities.push({ entityType: raw.entity_type, entityId: raw.entity_id })
    }
  }
  return Array.from(grouped.values()).map(({ row, entities }) => mapDocumentRow(row, entities))
}

function documentUploadMiddleware(req: Request, res: Response, next: NextFunction) {
  if (req.is('multipart/form-data')) {
    documentUpload.single('file')(req, res, (err: any) => {
      if (err) {
        const message = err instanceof MulterError ? err.message : (err?.message || 'Upload failed')
        return res.status(400).json({ error: message })
      }
      next()
    })
  } else {
    next()
  }
}

async function cleanupUploadedFile(file?: Express.Multer.File | null) {
  if (!file) return
  await removeStoredFile(file.filename)
}

async function removeStoredFile(storageKey?: string | null) {
  if (!storageKey) return
  try {
    await fs.unlink(path.join(DOCUMENT_UPLOAD_DIR, storageKey))
  } catch {
    // ignore cleanup errors
  }
}

async function detectMimeType(filePath: string, fallback?: string | null): Promise<string | undefined> {
  try {
    const type = await fileTypeFromFile(filePath)
    if (type?.mime) return type.mime
  } catch (err) {
    console.warn('Failed to detect mime type:', err)
  }
  return fallback ?? undefined
}

function truncateExtractedText(text: string): string {
  if (text.length <= MAX_TEXT_SNAPSHOT_LEN) return text
  return text.slice(0, MAX_TEXT_SNAPSHOT_LEN)
}

function buildSnippet(text: string, query: string, radius = 90): string {
  const clean = text.replace(/\s+/g, ' ').trim()
  if (!clean) return ''
  const lower = clean.toLowerCase()
  const needle = query.trim().toLowerCase()
  const index = lower.indexOf(needle)
  if (index === -1) {
    return clean.slice(0, radius * 2) + (clean.length > radius * 2 ? '…' : '')
  }
  const start = Math.max(0, index - radius)
  const end = Math.min(clean.length, index + needle.length + radius)
  const prefix = start > 0 ? '…' : ''
  const suffix = end < clean.length ? '…' : ''
  return `${prefix}${clean.slice(start, end)}${suffix}`
}

function parseJsonSafe<T>(value: unknown, fallback: T): T {
  if (value === null || value === undefined) return fallback
  if (typeof value === 'object') return value as T
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as T
    } catch {
      return fallback
    }
  }
  return fallback
}

type SentimentLabel = 'positive' | 'neutral' | 'negative'

function analyzeSentimentText(text: string): { score: number; magnitude: number; label: SentimentLabel } {
  const normalized = text.trim()
  if (!normalized) {
    return { score: 0, magnitude: 0, label: 'neutral' }
  }

  try {
    const result = sentimentAnalyzer.analyze(normalized)
    const rawComparative = typeof result.comparative === 'number' && Number.isFinite(result.comparative)
      ? result.comparative
      : 0
    const score = Number(rawComparative.toFixed(3))
    const magnitude = Number(Math.min(1, Math.abs(result.score ?? 0) / 10).toFixed(3))
    const label: SentimentLabel = score > 0.1 ? 'positive' : score < -0.1 ? 'negative' : 'neutral'
    return { score, magnitude, label }
  } catch (err) {
    console.error('Sentiment analysis failed:', err)
    return { score: 0, magnitude: 0, label: 'neutral' }
  }
}

function computeEngagementScore(input: {
  totalTenders: number
  activeTenders: number
  documentCount: number
  activityCount: number
  lastInteractionAt?: string | null
}): number {
  const recencyFactor = (() => {
    if (!input.lastInteractionAt) return 0
    const diffDays = Math.floor((Date.now() - new Date(input.lastInteractionAt).getTime()) / (1000 * 60 * 60 * 24))
    if (Number.isNaN(diffDays)) return 0
    if (diffDays <= 7) return 25
    if (diffDays <= 14) return 15
    if (diffDays <= 30) return 5
    if (diffDays <= 60) return 0
    return -10
  })()

  const base = input.totalTenders * 10 + input.activeTenders * 6 + input.documentCount * 4 + input.activityCount * 5
  const score = base + recencyFactor
  return Math.max(0, Math.min(100, Math.round(score)))
}

function classifyEngagementStage(score: number): 'Champion' | 'Healthy' | 'At Risk' | 'Dormant' {
  if (score >= 80) return 'Champion'
  if (score >= 55) return 'Healthy'
  if (score >= 30) return 'At Risk'
  return 'Dormant'
}

type CustomFieldDefinition = {
  id: string
  entityType: string
  fieldKey: string
  label: string
  description: string | null
  fieldType: z.infer<typeof CustomFieldTypeEnum>
  required: boolean
  config?: Record<string, unknown> | null
  defaultValue?: unknown
  orderIndex: number
  createdByUserId?: string | null
  createdAt: string
  updatedAt: string
}

type EntityLayoutConfig = z.infer<typeof EntityLayoutSchema>

type BrandingSettings = {
  brandName?: string | null
  logoUrl?: string | null
  faviconUrl?: string | null
  primaryColor?: string | null
  accentColor?: string | null
  backgroundColor?: string | null
  textColor?: string | null
  defaultLocale: string
  availableLocales: string[]
  whiteLabel?: Record<string, unknown>
  updatedAt?: string
}

function mapCustomFieldRow(row: any): CustomFieldDefinition {
  return {
    id: row.id,
    entityType: row.entity_type,
    fieldKey: row.field_key,
    label: row.label,
    description: row.description ?? null,
    fieldType: row.field_type,
    required: Boolean(row.required),
    config: parseJsonSafe<Record<string, unknown> | null>(row.config, null) ?? undefined,
    defaultValue: parseJsonSafe<unknown>(row.default_value, null) ?? undefined,
    orderIndex: typeof row.order_index === 'number' ? row.order_index : Number(row.order_index ?? 0) || 0,
    createdByUserId: row.created_by_user_id ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  }
}

async function listCustomFields(entityType?: string): Promise<CustomFieldDefinition[]> {
  let sql = 'SELECT * FROM custom_fields'
  const params: unknown[] = []
  if (entityType) {
    sql += ' WHERE entity_type = ?'
    params.push(entityType)
  }
  sql += ' ORDER BY entity_type, order_index, label'
  const [rows] = await getDb().execute(sql, params)
  return (rows as any[]).map(mapCustomFieldRow)
}

function coerceFieldValue(field: CustomFieldDefinition, raw: unknown) {
  const type = field.fieldType
  if (raw === undefined || raw === null) {
    return { text: null, number: null, date: null, json: null }
  }
  switch (type) {
    case 'number': {
      const parsed = Number(raw)
      if (Number.isNaN(parsed)) return { text: null, number: null, date: null, json: null }
      return { text: String(parsed), number: parsed, date: null, json: null }
    }
    case 'date': {
      const str = typeof raw === 'string' ? raw : ''
      const normalized = str.slice(0, 10)
      return { text: normalized || null, number: null, date: normalized || null, json: null }
    }
    case 'boolean': {
      const boolVal = typeof raw === 'string' ? raw === 'true' || raw === '1' : Boolean(raw)
      return { text: boolVal ? 'true' : 'false', number: boolVal ? 1 : 0, date: null, json: null }
    }
    case 'multiselect': {
      const arr = Array.isArray(raw) ? raw.filter(item => typeof item === 'string' || typeof item === 'number').map(String) : []
      return { text: arr.join(', '), number: null, date: null, json: arr }
    }
    case 'json': {
      return { text: null, number: null, date: null, json: raw }
    }
    case 'textarea':
    case 'select':
    case 'text':
    default:
      return { text: String(raw), number: null, date: null, json: null }
  }
}

function inflateFieldValue(field: CustomFieldDefinition, row: any) {
  const json = parseJsonSafe<unknown | null>(row.value_json, null)
  switch (field.fieldType) {
    case 'number':
      return row.value_number !== null && row.value_number !== undefined ? Number(row.value_number) : null
    case 'date':
      return row.value_date ?? null
    case 'boolean':
      if (row.value_text === 'true' || row.value_number === 1) return true
      if (row.value_text === 'false' || row.value_number === 0) return false
      return null
    case 'multiselect':
    case 'json':
      return json ?? null
    default:
      return row.value_text ?? null
  }
}

async function saveCustomFieldValues(entityType: string, entityId: string, values: Record<string, unknown>) {
  const definitions = await listCustomFields(entityType)
  if (!definitions.length) return { definitions, updatedKeys: [] as string[] }
  const definitionsByKey = new Map<string, CustomFieldDefinition>()
  definitions.forEach(def => definitionsByKey.set(def.fieldKey, def))
  const db = getDb()
  const updatedKeys: string[] = []
  await Promise.all(Object.entries(values).map(async ([fieldKey, rawValue]) => {
    const definition = definitionsByKey.get(fieldKey)
    if (!definition) return
    const normalized = coerceFieldValue(definition, rawValue)
    const id = uuid()
    await db.execute(
      `INSERT INTO custom_field_values (id, field_id, entity_type, entity_id, value_text, value_number, value_date, value_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE value_text = VALUES(value_text), value_number = VALUES(value_number), value_date = VALUES(value_date), value_json = VALUES(value_json), updated_at = CURRENT_TIMESTAMP`,
      [
        id,
        definition.id,
        entityType,
        entityId,
        normalized.text,
        normalized.number,
        normalized.date,
        normalized.json !== null && normalized.json !== undefined ? JSON.stringify(normalized.json) : null
      ]
    )
    updatedKeys.push(fieldKey)
  }))
  return { definitions, updatedKeys }
}

async function loadCustomFieldValues(entityType: string, entityId: string) {
  const definitions = await listCustomFields(entityType)
  if (!definitions.length) return { definitions, values: {} as Record<string, unknown> }
  const definitionsById = new Map<string, CustomFieldDefinition>()
  definitions.forEach(def => definitionsById.set(def.id, def))
  const [rows] = await getDb().execute(
    'SELECT field_id, value_text, value_number, value_date, value_json FROM custom_field_values WHERE entity_type = ? AND entity_id = ?',
    [entityType, entityId]
  )
  const values: Record<string, unknown> = {}
  for (const row of rows as any[]) {
    const def = definitionsById.get(row.field_id)
    if (!def) continue
    values[def.fieldKey] = inflateFieldValue(def, row)
  }
  return { definitions, values }
}

async function getEntityLayoutConfig(entityType: string): Promise<EntityLayoutConfig> {
  const [rows] = await getDb().execute('SELECT layout FROM entity_layouts WHERE entity_type = ?', [entityType])
  const record = (rows as any[])[0]
  if (!record) {
    const definitions = await listCustomFields(entityType)
    return {
      sections: [
        {
          id: 'primary',
          label: 'Details',
          fieldKeys: definitions.map(def => def.fieldKey)
        }
      ]
    }
  }
  const layout = parseJsonSafe<EntityLayoutConfig | null>(record.layout, null)
  if (!layout) {
    return { sections: [] }
  }
  return layout
}

async function saveEntityLayoutConfig(entityType: string, layout: EntityLayoutConfig) {
  const db = getDb()
  const [rows] = await db.execute('SELECT id FROM entity_layouts WHERE entity_type = ?', [entityType])
  const record = (rows as any[])[0]
  const payload = JSON.stringify(layout)
  if (record) {
    await db.execute('UPDATE entity_layouts SET layout = ?, updated_at = CURRENT_TIMESTAMP WHERE entity_type = ?', [payload, entityType])
  } else {
    await db.execute('INSERT INTO entity_layouts (id, entity_type, layout) VALUES (?, ?, ?)', [uuid(), entityType, payload])
  }
}

async function getBrandingSettings(): Promise<BrandingSettings> {
  const [rows] = await getDb().execute('SELECT * FROM branding_settings WHERE tenant_key = ?', [DEFAULT_TENANT_KEY])
  const record = (rows as any[])[0]
  if (!record) {
    return {
      brandName: 'Vensysco CRM',
      logoUrl: null,
      faviconUrl: null,
      primaryColor: '#ff5e2b',
      accentColor: '#2563eb',
      backgroundColor: '#ffffff',
      textColor: '#111827',
      defaultLocale: 'en',
      availableLocales: ['en'],
      whiteLabel: {}
    }
  }
  return {
    brandName: record.brand_name ?? null,
    logoUrl: record.logo_url ?? null,
    faviconUrl: record.favicon_url ?? null,
    primaryColor: record.primary_color ?? null,
    accentColor: record.accent_color ?? null,
    backgroundColor: record.background_color ?? null,
    textColor: record.text_color ?? null,
    defaultLocale: record.default_locale || 'en',
    availableLocales: parseJsonSafe<string[]>(record.available_locales, ['en']),
    whiteLabel: parseJsonSafe<Record<string, unknown> | undefined>(record.white_label, undefined),
    updatedAt: record.updated_at
  }
}

async function saveBrandingSettings(input: z.infer<typeof BrandingUpdateSchema>) {
  const db = getDb()
  const [rows] = await db.execute('SELECT id FROM branding_settings WHERE tenant_key = ?', [DEFAULT_TENANT_KEY])
  const record = (rows as any[])[0]
  const payload = {
    brand_name: input.brandName ?? null,
    logo_url: input.logoUrl ?? null,
    favicon_url: input.faviconUrl ?? null,
    primary_color: input.primaryColor ?? null,
    accent_color: input.accentColor ?? null,
    background_color: input.backgroundColor ?? null,
    text_color: input.textColor ?? null,
    default_locale: input.defaultLocale ?? 'en',
    available_locales: input.availableLocales ? JSON.stringify(input.availableLocales) : JSON.stringify(['en']),
    white_label: input.whiteLabel ? JSON.stringify(input.whiteLabel) : null
  }
  if (record) {
    await db.execute(
      `UPDATE branding_settings SET brand_name = ?, logo_url = ?, favicon_url = ?, primary_color = ?, accent_color = ?, background_color = ?, text_color = ?, default_locale = ?, available_locales = ?, white_label = ?, updated_at = CURRENT_TIMESTAMP WHERE tenant_key = ?`,
      [...Object.values(payload), DEFAULT_TENANT_KEY]
    )
  } else {
    await db.execute(
      `INSERT INTO branding_settings (id, tenant_key, brand_name, logo_url, favicon_url, primary_color, accent_color, background_color, text_color, default_locale, available_locales, white_label)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [uuid(), DEFAULT_TENANT_KEY, ...Object.values(payload)]
    )
  }
}

type AssistantSnapshot = {
  mode?: string
  totals?: { tenders?: number; open?: number }
  statusCounts?: Record<string, number>
  priorityCounts?: Record<string, number>
  highPriority?: Array<{ title?: string; status?: string; priority?: string; owner?: string | null; followUpDate?: string | null }>
  upcomingFollowUps?: Array<{ title?: string; followUpDate?: string }>
}

function extractSnapshot(prompt: string): AssistantSnapshot | null {
  const marker = 'Snapshot:'
  const index = prompt.lastIndexOf(marker)
  if (index === -1) return null
  const slice = prompt.slice(index + marker.length).trim()
  if (!slice) return null
  try {
    return JSON.parse(slice) as AssistantSnapshot
  } catch {
    return null
  }
}

function formatDateLabel(input: string | undefined | null): string | null {
  if (!input) return null
  const parsed = Date.parse(input)
  if (Number.isNaN(parsed)) return null
  return new Date(parsed).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

async function generateAssistantResponse(prompt: string, user: AuthUser) {
  const snapshot = extractSnapshot(prompt)
  if (snapshot) {
    const total = snapshot.totals?.tenders ?? 0
    const open = snapshot.totals?.open ?? 0
    const highPriority = snapshot.highPriority ?? []
    const urgentCount = snapshot.priorityCounts ? (snapshot.priorityCounts['Urgent'] ?? 0) : highPriority.filter(item => item.priority === 'Urgent').length
    const modeLabel = snapshot.mode === 'server' ? 'live' : 'local'
    const followUps = snapshot.upcomingFollowUps ?? []
    const nextFollowUp = followUps[0]

    const summaryParts: string[] = []
    summaryParts.push(`${modeLabel} data shows ${total} tenders with ${open} still open.`)
    if (urgentCount > 0) {
      summaryParts.push(`${urgentCount} marked urgent need attention.`)
    } else if (highPriority.length > 0) {
      summaryParts.push(`${highPriority.length} high-priority records are in focus.`)
    }
    if (nextFollowUp?.title && nextFollowUp?.followUpDate) {
      const label = formatDateLabel(nextFollowUp.followUpDate)
      if (label) summaryParts.push(`Next follow-up is ${nextFollowUp.title} on ${label}.`)
    }

    const answer = summaryParts.join(' ')

    const suggestions: string[] = []
    if (highPriority.length > 0) {
      const first = highPriority[0]
      const owner = first.owner ? ` with ${first.owner}` : ''
      suggestions.push(`Review ${first.title} (${first.priority})${owner} to confirm next steps.`)
    }
    if (followUps.length > 0) {
      const follow = followUps[0]
      const label = formatDateLabel(follow.followUpDate)
      if (label) suggestions.push(`Prepare outreach ahead of the ${label} follow-up for ${follow.title}.`)
    }
    const stalledStatus = Object.entries(snapshot.statusCounts ?? {}).find(([status, count]) => ['Blocked', 'Pending Review', 'On Hold'].includes(status) && count > 0)
    if (stalledStatus) {
      suggestions.push(`Unblock ${stalledStatus[1]} ${stalledStatus[0].toLowerCase()} item${stalledStatus[1] === 1 ? '' : 's'} to maintain momentum.`)
    }
    if (suggestions.length < 3) {
      const remaining = ['Share this update with the sales huddle.', 'Log new insights in Activities so the team stays aligned.', 'Check Tasks for any linked work items needing updates.']
      for (const idea of remaining) {
        if (suggestions.length >= 3) break
        suggestions.push(idea)
      }
    }
    return {
      answer,
      suggestions: suggestions.slice(0, 3)
    }
  }

  const db = getDb()
  const lower = prompt.toLowerCase()
  const suggestions: string[] = []
  const blocks: string[] = []

  if (lower.includes('task')) {
    const [taskRows] = await db.execute(
      `SELECT title, status, priority, due_date
       FROM tasks
       ORDER BY FIELD(status,'Pending','In Progress','Blocked','Completed'), COALESCE(due_date, '9999-12-31')
       LIMIT 5`
    )
    const tasks = (taskRows as any[])
    if (tasks.length) {
      blocks.push('Top tasks:')
      tasks.forEach(row => {
        const due = row.due_date ? ` (due ${row.due_date})` : ''
        blocks.push(`• ${row.title} – ${row.status}${due}`)
      })
    } else {
      blocks.push('No tasks found right now. Create one to get started.')
    }
    suggestions.push('Open the Tasks tab to update progress or reassign.')
  }

  if (lower.includes('approval')) {
    const [approvalRows] = await db.execute(
      `SELECT ar.status, ar.entity_type, ar.entity_id, ap.name AS policy_name, ar.submitted_at
       FROM approval_requests ar
       LEFT JOIN approval_policies ap ON ap.id = ar.policy_id
       WHERE ar.status IN ('pending','in_review')
       ORDER BY ar.submitted_at ASC
       LIMIT 5`
    )
    const approvals = (approvalRows as any[])
    if (approvals.length) {
      blocks.push('Pending approvals:')
      approvals.forEach(row => {
        blocks.push(`• ${row.policy_name || row.entity_type} ${row.entity_id} – ${row.status}`)
      })
    } else {
      blocks.push('No approvals are waiting at the moment.')
    }
    suggestions.push('Visit Approvals to review or advance routed items.')
  }

  if (lower.includes('tender') || lower.includes('deal')) {
    const [tenderRows] = await db.execute(
      `SELECT lead_title, priority, status, serial_token
       FROM tenders
       ORDER BY FIELD(priority,'Urgent','High','Medium','Low'), updated_at DESC
       LIMIT 5`
    )
    const tenders = (tenderRows as any[])
    if (tenders.length) {
      blocks.push('High-signal tenders:')
      tenders.forEach(row => {
        blocks.push(`• ${row.lead_title || row.serial_token} – ${row.priority} (${row.status})`)
      })
    } else {
      blocks.push('No tenders found. Import or create a new opportunity.')
    }
    suggestions.push('Use Communications to nudge stakeholders tied to these tenders.')
  }

  if (!blocks.length) {
    const [[taskStats]] = await db.query('SELECT COUNT(*) AS total, SUM(status = "Completed") AS completed FROM tasks') as any
    const [[approvalStats]] = await db.query('SELECT COUNT(*) AS total, SUM(status IN ("pending","in_review")) AS pending FROM approval_requests') as any
    const [[tenderStats]] = await db.query('SELECT COUNT(*) AS total, SUM(priority IN ("Urgent","High")) AS critical FROM tenders') as any
    blocks.push(`You have ${taskStats?.total ?? 0} tasks (${taskStats?.completed ?? 0} done), ${approvalStats?.pending ?? 0} approvals awaiting, and ${tenderStats?.critical ?? 0} critical tenders.`)
    suggestions.push('Ask about “tasks” or “approvals” for deeper insight, or request a summary for a specific serial token.')
  }

  const answer = blocks.join('\n')
  return { answer, suggestions }
}

type TimelineEntityType = 'tender' | 'customer'

type TimelineInsights = {
  entityType: TimelineEntityType
  entityId: string
  name: string
  summary: string
  followUpDraft: string
  probability: { score: number; label: 'Low' | 'Medium' | 'High' }
  activityMetrics: {
    total: number
    lastTouchAt: string | null
    lastTouchBy: string | null
    avgSpacingDays: number | null
    spanDays: number | null
  }
  recommendedActions: string[]
  timeline: Array<{
    id: string
    occurredAt: string
    author: string | null
    type: string
    text: string
  }>
}

function computeProbabilityLabel(score: number): 'Low' | 'Medium' | 'High' {
  if (score >= 70) return 'High'
  if (score >= 40) return 'Medium'
  return 'Low'
}

function daysBetween(a: Date, b: Date): number {
  return Math.abs(a.getTime() - b.getTime()) / (1000 * 60 * 60 * 24)
}

function formatName(first?: string | null, last?: string | null, fallback?: string | null): string {
  const parts = [first, last].filter(Boolean) as string[]
  if (parts.length) return parts.join(' ').trim()
  if (fallback) return fallback
  return 'Unknown'
}

async function fetchTimelineInsights(entityType: TimelineEntityType, entityId: string): Promise<TimelineInsights | null> {
  const db = getDb()
  if (!entityId) return null

  if (entityType === 'tender') {
    const [rows] = await db.execute(`
      SELECT id, serial_token, lead_title, status, priority, customer_id, allotted_to, estimated_value,
             created_at, updated_at, follow_up_date
      FROM tenders
      WHERE id = ? OR serial_token = ?
      LIMIT 1
    `, [entityId, entityId])
    const tender = (rows as any[])[0]
    if (!tender) return null

    const [activityRows] = await db.execute(`
      SELECT id, entity_type, entity_key, text, type, created_at, occurred_at, user_name
      FROM activities
      WHERE entity_type = 'tender' AND (entity_key = ? OR entity_key = ?)
      ORDER BY COALESCE(occurred_at, created_at) ASC
    `, [tender.id, tender.serial_token])
    const activities = activityRows as any[]
    const timeline = activities.map((row) => ({
      id: row.id,
      occurredAt: (row.occurred_at || row.created_at) as string,
      author: row.user_name || null,
      type: row.type,
      text: row.text
    }))
    const lastTouch = timeline.length ? timeline[timeline.length - 1] : null
    const createdAt = tender.created_at ? new Date(tender.created_at) : null
    const lastTouchDate = lastTouch?.occurredAt ? new Date(lastTouch.occurredAt) : null
    const now = new Date()
    const spanDays = createdAt ? Math.round(daysBetween(now, createdAt)) : null
    const avgSpacingDays = timeline.length > 1 ? Math.round(daysBetween(new Date(timeline[0].occurredAt), new Date(timeline[timeline.length - 1].occurredAt)) / (timeline.length - 1)) : null

    let score = 55
    const status = (tender.status || '').toLowerCase()
    if (status.includes('closed won') || status.includes('won')) score = 92
    if (status.includes('closed lost') || status.includes('lost')) score = 15
    if (status.includes('negotiation') || status.includes('in progress')) score += 15
    if (status.includes('open') || status.includes('new')) score += 5
    const priority = (tender.priority || '').toLowerCase()
    if (priority === 'urgent') score += 10
    if (priority === 'high') score += 5
    if (priority === 'low') score -= 5
    if (lastTouchDate) {
      const daysSinceTouch = daysBetween(now, lastTouchDate)
      if (daysSinceTouch > 14) score -= 25
      else if (daysSinceTouch > 7) score -= 15
      else if (daysSinceTouch < 2) score += 10
    }
    if (tender.follow_up_date) {
      const followUpDate = new Date(tender.follow_up_date)
      if (followUpDate < now) score -= 10
      else if (daysBetween(followUpDate, now) <= 2) score += 6
    }
    score = Math.max(5, Math.min(95, Math.round(score)))

    const name = tender.lead_title || tender.serial_token
    const summaryParts: string[] = []
    summaryParts.push(`${name} has ${timeline.length || 'no'} recorded activities over ${spanDays ?? 'unknown'} day${spanDays === 1 ? '' : 's'}.`)
    if (lastTouch) {
      const lastBy = lastTouch.author ? ` by ${lastTouch.author}` : ''
      summaryParts.push(`Last touch was ${lastTouchDate ? Math.round(daysBetween(now, lastTouchDate)) : '0'} day${lastTouchDate && Math.round(daysBetween(now, lastTouchDate)) === 1 ? '' : 's'} ago${lastBy}.`)
    } else {
      summaryParts.push('No timeline activity has been logged yet.')
    }
    if (priority) summaryParts.push(`Priority is ${tender.priority}.`)
    const summary = summaryParts.join(' ')

    const followUpDraft = (() => {
      const greeting = tender.allotted_to ? `Hi ${tender.allotted_to},` : 'Hi team,'
      const body = lastTouch
        ? `Following up on ${name}. The last update (${lastTouch.type}) was "${lastTouch.text}".`
        : `I wanted to follow up on ${name}. I have not seen any activity yet.`
      const ask = 'Let me know the latest outcome, blockers, or if you need support before the next milestone.'
      return `${greeting}\n\n${body} Could you share the current status and next steps?\n\n${ask}\n\nThanks!`
    })()

    const recommendedActions: string[] = []
    if (!timeline.length) recommendedActions.push('Log at least one customer touchpoint to seed the timeline.')
    if (lastTouchDate && daysBetween(now, lastTouchDate) > 5) recommendedActions.push('Reach out to the customer and document the conversation to keep momentum.')
    if (score < 40) recommendedActions.push('Schedule a review with the owner to unblock decision risks.')
    if (tender.follow_up_date && new Date(tender.follow_up_date) < now) recommendedActions.push('Follow-up date passed—reschedule and confirm availability.')

    return {
      entityType,
      entityId: tender.id,
      name,
      summary,
      followUpDraft,
      probability: { score, label: computeProbabilityLabel(score) },
      activityMetrics: {
        total: timeline.length,
        lastTouchAt: lastTouch?.occurredAt ?? null,
        lastTouchBy: lastTouch?.author ?? null,
        avgSpacingDays,
        spanDays
      },
      recommendedActions,
      timeline
    }
  }

  if (entityType === 'customer') {
    const [rows] = await db.execute(`
      SELECT id, first_name, last_name, organization_name, email, mobile, created_at
      FROM customers
      WHERE id = ?
      LIMIT 1
    `, [entityId])
    const customer = (rows as any[])[0]
    if (!customer) return null

    const [activityRows] = await db.execute(`
      SELECT id, entity_type, entity_key, text, type, created_at, occurred_at, user_name
      FROM activities
      WHERE entity_type = 'customer' AND entity_key = ?
      ORDER BY COALESCE(occurred_at, created_at) ASC
    `, [customer.id])
    const activities = activityRows as any[]
    const timeline = activities.map(row => ({
      id: row.id,
      occurredAt: (row.occurred_at || row.created_at) as string,
      author: row.user_name || null,
      type: row.type,
      text: row.text
    }))
    const lastTouch = timeline.length ? timeline[timeline.length - 1] : null
    const lastTouchDate = lastTouch?.occurredAt ? new Date(lastTouch.occurredAt) : null
    const now = new Date()

    const [tenderStatsRows] = await db.execute(`
      SELECT
        COUNT(*) AS total,
        SUM(status IN ('Closed Won','Won')) AS closedWon,
        SUM(status IN ('Closed Lost','Lost')) AS closedLost,
        SUM(status IN ('Open','In Progress','Negotiation')) AS active,
        SUM(priority IN ('High','Urgent')) AS highPriority
      FROM tenders
      WHERE customer_id = ?
    `, [customer.id])
    const tenderStats = (tenderStatsRows as any[])[0] || { total: 0, closedWon: 0, closedLost: 0, active: 0, highPriority: 0 }

    let score = 50
    if (tenderStats.total > 0) {
      const winRate = tenderStats.closedWon / Math.max(1, tenderStats.total)
      score += Math.round(winRate * 30)
      if (tenderStats.active > 0) score += 10
      if (tenderStats.highPriority > 0) score += 5
      if (tenderStats.closedLost > tenderStats.closedWon) score -= 10
    }
    if (lastTouchDate) {
      const daysSinceTouch = daysBetween(now, lastTouchDate)
      if (daysSinceTouch > 30) score -= 20
      else if (daysSinceTouch > 14) score -= 10
      else score += 5
    } else {
      score -= 15
    }
    score = Math.max(5, Math.min(95, Math.round(score)))

    const name = formatName(customer.first_name, customer.last_name, customer.organization_name)
    const summary = `${name} has ${tenderStats.total} lifetime tender${tenderStats.total === 1 ? '' : 's'} (${tenderStats.closedWon} won, ${tenderStats.closedLost} lost). ${timeline.length ? `Latest activity recorded ${lastTouchDate ? Math.round(daysBetween(now, lastTouchDate)) : '0'} day${lastTouchDate && Math.round(daysBetween(now, lastTouchDate)) === 1 ? '' : 's'} ago.` : 'No recent activity logged.'}`

    const followUpDraft = (() => {
      const greeting = `Hi ${name.split(' ')[0] || 'there'},`
      const recap = timeline.length && lastTouch ? `I appreciated our last interaction about "${lastTouch.text}".` : `I wanted to reconnect and share updates from our team.`
      const ask = tenderStats.active > 0
        ? `We currently have ${tenderStats.active} active engagement${tenderStats.active === 1 ? '' : 's'} with you. Is there anything else we should prepare to keep momentum?`
        : `Let me know if there are new initiatives we can support or any questions on previous work.`
      return `${greeting}\n\n${recap}\n\n${ask}\n\nThanks!`
    })()

    const recommendedActions: string[] = []
    if (!timeline.length) recommendedActions.push('Log a touchpoint for this customer to start a relationship timeline.')
    if (lastTouchDate && daysBetween(now, lastTouchDate) > 21) recommendedActions.push('Send a check-in email or schedule a catch-up call to re-engage the customer.')
    if (tenderStats.highPriority > 0) recommendedActions.push('Review high-priority opportunities with the account owner and ensure next steps are clear.')

    return {
      entityType,
      entityId: customer.id,
      name,
      summary,
      followUpDraft,
      probability: { score, label: computeProbabilityLabel(score) },
      activityMetrics: {
        total: timeline.length,
        lastTouchAt: lastTouch?.occurredAt ?? null,
        lastTouchBy: lastTouch?.author ?? null,
        avgSpacingDays: timeline.length > 1 ? Math.round(daysBetween(new Date(timeline[0].occurredAt), new Date(timeline[timeline.length - 1].occurredAt)) / (timeline.length - 1)) : null,
        spanDays: customer.created_at ? Math.round(daysBetween(now, new Date(customer.created_at))) : null
      },
      recommendedActions,
      timeline
    }
  }

  return null
}

type AnalyticsOverview = {
  totals: {
    tenders: number
    open: number
    closed: number
    highPriority: number
  }
  pipeline: Array<{ status: string; count: number }>
  velocity: {
    createdLast7: number
    closedLast7: number
    avgOpenAgeDays: number | null
  }
  teamLeaders: Array<{ owner: string | null; openCount: number; highPriority: number }>
}

async function fetchAnalyticsOverview(): Promise<AnalyticsOverview> {
  const db = getDb()
  const [[totals]] = await db.query(`
    SELECT
      COUNT(*) AS tenders,
      SUM(status NOT IN ('Closed','Closed Won','Closed Lost','Lost','Closed - Lost')) AS open,
      SUM(status IN ('Closed','Closed Won','Closed Lost','Won','Lost','Closed - Lost')) AS closed,
      SUM(priority IN ('High','Urgent')) AS highPriority
    FROM tenders
  `) as any

  const [pipelineRows] = await db.query(`
    SELECT status, COUNT(*) AS count
    FROM tenders
    GROUP BY status
    ORDER BY count DESC
  `) as any

  const [[velocity]] = await db.query(`
    SELECT
      SUM(created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) AS createdLast7,
      SUM(status IN ('Closed Won','Closed','Won') AND updated_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) AS closedLast7,
      AVG(CASE WHEN status NOT IN ('Closed','Closed Won','Closed Lost','Lost','Closed - Lost') THEN TIMESTAMPDIFF(DAY, created_at, COALESCE(updated_at, NOW())) END) AS avgOpenAgeDays
    FROM tenders
  `) as any

  const [leaderRows] = await db.query(`
    SELECT allotted_to AS owner, COUNT(*) AS openCount,
      SUM(priority IN ('High','Urgent')) AS highPriority
    FROM tenders
    WHERE status NOT IN ('Closed','Closed Won','Closed Lost','Won','Lost','Closed - Lost')
    GROUP BY allotted_to
    ORDER BY openCount DESC
    LIMIT 5
  `) as any

  return {
    totals: {
      tenders: Number(totals?.tenders ?? 0),
      open: Number(totals?.open ?? 0),
      closed: Number(totals?.closed ?? 0),
      highPriority: Number(totals?.highPriority ?? 0)
    },
    pipeline: pipelineRows.map((row: any) => ({ status: row.status || 'Unspecified', count: Number(row.count) })),
    velocity: {
      createdLast7: Number(velocity?.createdLast7 ?? 0),
      closedLast7: Number(velocity?.closedLast7 ?? 0),
      avgOpenAgeDays: velocity?.avgOpenAgeDays != null ? Math.round(Number(velocity.avgOpenAgeDays)) : null
    },
    teamLeaders: leaderRows.map((row: any) => ({
      owner: row.owner || null,
      openCount: Number(row.openCount || 0),
      highPriority: Number(row.highPriority || 0)
    }))
  }
}

function mapWebhookRow(row: any) {
  return {
    id: row.id,
    name: row.name,
    eventType: row.event_type,
    targetUrl: row.target_url,
    sharedSecret: row.shared_secret ?? null,
    headers: parseJsonSafe<Record<string, string> | undefined>(row.headers, undefined),
    isActive: Boolean(row.is_active),
    createdByUserId: row.created_by_user_id ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  }
}

async function recordEngagementSnapshot(customerId: string, score: number, stage: string, drivers: Record<string, unknown>) {
  const nowIso = new Date().toISOString()
  const nowDb = nowIso.slice(0, 19).replace('T', ' ')

  const [lastRows] = await getDb().execute(
    'SELECT id, score, stage, computed_at FROM engagement_scores WHERE customer_id = ? ORDER BY computed_at DESC LIMIT 1',
    [customerId]
  )
  const last = (lastRows as any[])[0]
  const lastScore = typeof last?.score === 'number' ? Number(last.score) : Number(last?.score ?? 0)
  const lastStage: string | undefined = last?.stage
  const lastComputedAt = last?.computed_at ? new Date(last.computed_at) : null
  const elapsedMs = lastComputedAt ? Date.now() - lastComputedAt.getTime() : Number.POSITIVE_INFINITY
  const shouldInsert = !last
    || Math.abs(lastScore - score) >= 2
    || lastStage !== stage
    || elapsedMs > 1000 * 60 * 60 * 6 // every 6 hours

  if (shouldInsert) {
    await getDb().execute(
      'INSERT INTO engagement_scores (id, customer_id, score, stage, drivers, computed_at) VALUES (?, ?, ?, ?, ?, ?)',
      [uuid(), customerId, score, stage, JSON.stringify(drivers), nowDb]
    )
  }

  const [trendRows] = await getDb().execute(
    'SELECT score, stage, drivers, computed_at FROM engagement_scores WHERE customer_id = ? ORDER BY computed_at DESC LIMIT 12',
    [customerId]
  )
  return (trendRows as any[]).map(row => ({
    score: Number(row.score ?? 0),
    stage: row.stage,
    computedAt: row.computed_at ? new Date(row.computed_at).toISOString() : nowIso,
    drivers: parseJsonSafe<Record<string, unknown>>(row.drivers, {})
  }))
}

type CustomerSegmentRecord = {
  id: string
  customerId: string
  segment: string
  description?: string | null
  color?: string | null
  source: 'manual' | 'system'
  createdByUserId?: string | null
  createdAt: string
}

async function fetchCustomerSegments(customerId: string): Promise<CustomerSegmentRecord[]> {
  const [rows] = await getDb().execute(
    'SELECT id, customer_id, segment, description, color, source, created_by_user_id, created_at FROM customer_segments WHERE customer_id = ? ORDER BY created_at DESC',
    [customerId]
  )
  return (rows as any[]).map(row => ({
    id: row.id,
    customerId: row.customer_id,
    segment: row.segment,
    description: row.description,
    color: row.color,
    source: (row.source as string) === 'system' ? 'system' : 'manual',
    createdByUserId: row.created_by_user_id,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString()
  }))
}

async function fetchCustomerCommunications(customerId: string, limit = 50) {
  const [rows] = await getDb().execute(
    `SELECT * FROM activities
     WHERE entity_type = 'customer' AND entity_key = ? AND type = 'communication'
     ORDER BY COALESCE(occurred_at, created_at) DESC, created_at DESC
     LIMIT ?`,
    [customerId, limit]
  )
  return (rows as any[]).map(mapActivityRow)
}

async function extractPdfText(filePath: string): Promise<string> {
  try {
    const buffer = await fs.readFile(filePath)
    const result = await pdfParse(buffer)
    return result?.text ? result.text.trim() : ''
  } catch (err) {
    console.error('PDF text extraction failed:', err)
    return ''
  }
}

async function extractDocxText(filePath: string): Promise<string> {
  try {
    const result = await mammoth.extractRawText({ path: filePath })
    return result?.value ? result.value.trim() : ''
  } catch (err) {
    console.error('DOCX text extraction failed:', err)
    return ''
  }
}

async function extractImageText(filePath: string): Promise<string> {
  try {
    const tesseractModule = await import('tesseract.js')
    const result = await tesseractModule.recognize(filePath, 'eng')
    return result?.data?.text ? result.data.text.trim() : ''
  } catch (err) {
    console.error('OCR failed:', err)
    return ''
  }
}

async function extractTextFromFile(filePath: string, mimeHint?: string | null): Promise<string> {
  const mimeType = (mimeHint && mimeHint.toLowerCase()) || await detectMimeType(filePath)
  if (!mimeType) {
    try {
      const text = await fs.readFile(filePath, 'utf8')
      return truncateExtractedText(text)
    } catch {
      return ''
    }
  }

  if (mimeType.startsWith('text/') || mimeType.includes('json') || mimeType.includes('xml') || mimeType.includes('csv')) {
    try {
      const text = await fs.readFile(filePath, 'utf8')
      return truncateExtractedText(text)
    } catch (err) {
      console.error('Text file extraction failed:', err)
      return ''
    }
  }

  if (mimeType === 'application/pdf') {
    return truncateExtractedText(await extractPdfText(filePath))
  }

  if (mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
    return truncateExtractedText(await extractDocxText(filePath))
  }

  if (mimeType.startsWith('image/')) {
    return truncateExtractedText(await extractImageText(filePath))
  }

  try {
    const text = await fs.readFile(filePath, 'utf8')
    return truncateExtractedText(text)
  } catch (err) {
    console.warn('Fallback text extraction failed:', err)
    return ''
  }
}

async function fetchDocumentWithAttachments(id: string) {
  const [rows] = await getDb().execute(`
    SELECT d.*, ra.entity_type, ra.entity_id
    FROM documents d
    LEFT JOIN record_attachments ra ON ra.document_id = d.id
    WHERE d.id = ?
  `, [id])
  if ((rows as any[]).length === 0) return null
  return groupDocumentRows(rows as any[])[0]
}

type DocumentPayload = z.infer<typeof DocumentPayloadSchema>

async function insertDocumentRecord(data: DocumentPayload, file: Express.Multer.File | null, userId: string) {
  const id = uuid()
  let storageKey: string | null = null
  let fileSize: number | null = null
  let mimeType: string | undefined
  let textContent: string | null = null

  if (file) {
    storageKey = file.filename
    fileSize = file.size ?? null
    const filePath = path.join(DOCUMENT_UPLOAD_DIR, storageKey)
    mimeType = await detectMimeType(filePath, file.mimetype)
    if (mimeType && !ALLOWED_DOCUMENT_MIME_TYPES.has(mimeType)) {
      await cleanupUploadedFile(file)
      const error = Object.assign(new Error('Unsupported file type uploaded'), { status: 415 })
      throw error
    }
    textContent = await extractTextFromFile(filePath, mimeType)
  } else if (data.summary) {
    textContent = truncateExtractedText(data.summary)
  }

  const normalizedText = (() => {
    if (!textContent) return null
    const trimmed = textContent.trim()
    return trimmed.length === 0 ? null : truncateExtractedText(trimmed)
  })()

  await getDb().execute(`
    INSERT INTO documents (
      id, name, owner, related_to, category, tags, summary, link,
      file_name, file_size, mime_type, storage_key, uploaded_by_user_id, text_content
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    id,
    data.name,
    data.owner ?? null,
    data.relatedTo ?? null,
    data.category ?? null,
    JSON.stringify(data.tags ?? []),
    data.summary ?? null,
    data.link ?? null,
    data.fileName ?? null,
    fileSize,
    mimeType ?? null,
    storageKey,
    userId,
    normalizedText
  ])

  const document = await fetchDocumentWithAttachments(id)
  if (!document) {
    throw new Error('Failed to load created document')
  }
  return document
}

async function ensureEntityExists(entityType: AttachmentEntity, entityId: string) {
  const table = entityType === 'tender' ? 'tenders' : 'customers'
  const [rows] = await getDb().execute(`SELECT id FROM ${table} WHERE id = ?`, [entityId])
  if ((rows as any[]).length === 0) {
    const error = Object.assign(new Error(`${entityType} not found`), { status: 404 })
    throw error
  }
}

async function attachDocumentToEntity(documentId: string, entityType: AttachmentEntity, entityId: string, userId?: string | null) {
  await ensureEntityExists(entityType, entityId)
  try {
    await getDb().execute(`
      INSERT INTO record_attachments (id, entity_type, entity_id, document_id, created_by_user_id)
      VALUES (?, ?, ?, ?, ?)
    `, [uuid(), entityType, entityId, documentId, userId ?? null])
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_ENTRY') {
      throw err
    }
  }
  return fetchDocumentWithAttachments(documentId)
}

async function fetchAttachmentsForEntity(entityType: AttachmentEntity, entityId: string) {
  await ensureEntityExists(entityType, entityId)
  const [rows] = await getDb().execute(`
    SELECT d.*, ra.entity_type, ra.entity_id
    FROM record_attachments ra
    JOIN documents d ON d.id = ra.document_id
    WHERE ra.entity_type = ? AND ra.entity_id = ?
    ORDER BY d.updated_at DESC
  `, [entityType, entityId])
  return groupDocumentRows(rows as any[])
}
async function detachDocumentFromEntity(entityType: AttachmentEntity, entityId: string, documentId: string) {
  await getDb().execute('DELETE FROM record_attachments WHERE entity_type = ? AND entity_id = ? AND document_id = ?', [entityType, entityId, documentId])
}

async function listEntityDocuments(entityType: AttachmentEntity, entityId: string) {
  return fetchAttachmentsForEntity(entityType, entityId)
}

type DocumentCreationOptions = {
  entityType?: AttachmentEntity
  entityId?: string
}

type DocumentCreationResult =
  | { ok: true; document: ReturnType<typeof mapDocumentRow> }
  | { ok: false; status: number; payload: any }

async function createDocumentRecord(req: Request & { file?: Express.Multer.File }, user: AuthUser, options?: DocumentCreationOptions): Promise<DocumentCreationResult> {
  const file = req.file ?? null
  try {
    const payload = buildDocumentPayload(req) as ReturnType<typeof buildDocumentPayload> & DocumentCreationOptions
    if (options?.entityType) payload.entityType = options.entityType
    if (options?.entityId) payload.entityId = options.entityId

    const parsed = DocumentPayloadSchema.safeParse(payload)
    if (!parsed.success) {
      await cleanupUploadedFile(file)
      return { ok: false, status: 400, payload: { error: parsed.error.flatten() } }
    }

    const data = parsed.data

    if (data.entityType && data.entityId) {
      await ensureEntityExists(data.entityType, data.entityId)
    }

    let createdDocument: ReturnType<typeof mapDocumentRow> | null = null
    try {
      createdDocument = await insertDocumentRecord(data, file, user.id)
      if (!createdDocument) {
        throw new Error('Failed to create document')
      }

      if (data.entityType && data.entityId) {
        const updated = await attachDocumentToEntity(createdDocument.id, data.entityType, data.entityId, user.id)
        if (updated) {
          createdDocument = updated
        }
      }

      return { ok: true, document: createdDocument }
    } catch (err) {
      if (createdDocument?.id) {
        await getDb().execute('DELETE FROM documents WHERE id = ?', [createdDocument.id])
      }
      throw err
    }
  } catch (err: any) {
    await cleanupUploadedFile(req.file)
    console.error('createDocumentRecord failed:', err)
    const status = typeof err?.status === 'number' ? err.status : 500
    const message = err?.message || 'Failed to save document'
    return { ok: false, status, payload: { error: message } }
  }
}

function normalizeDateInput(value?: string | null) {
  if (!value) return null
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return null
  return parsed.toISOString().slice(0, 10)
}

function normalizeOptionalString(value?: string | null): string | null {
  if (value === undefined || value === null) return null
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

const USER_SYNC_TTL_MS = 5 * 60 * 1000
let lastUserSyncAt = 0
let userSyncInFlight: Promise<void> | null = null

async function syncUsersIntoEmployees(options?: { force?: boolean }) {
  const force = options?.force ?? false
  const now = Date.now()
  if (!force) {
    if (now - lastUserSyncAt < USER_SYNC_TTL_MS) {
      return userSyncInFlight ?? Promise.resolve()
    }
    if (userSyncInFlight) {
      return userSyncInFlight
    }
  } else if (userSyncInFlight) {
    await userSyncInFlight
  }

  const db = getDb()
  const run = async () => {
    const [employeeRows] = await db.execute('SELECT id, employee_id, employee_name, email FROM employees')
    const existingEmails = new Set<string>()
    const existingEmployeeIds = new Set<string>()
    for (const row of employeeRows as any[]) {
      if (row.email) existingEmails.add(String(row.email).toLowerCase())
      if (row.employee_id) existingEmployeeIds.add(String(row.employee_id))
    }

    const [userRows] = await db.execute('SELECT id, email, name FROM users')
    for (const raw of userRows as any[]) {
      const email: string = (raw.email || '').toLowerCase()
      if (!email || existingEmails.has(email)) continue

      let employeeId = `USER-${raw.id}`
      if (existingEmployeeIds.has(employeeId)) {
        employeeId = `USER-${raw.id}`.slice(0, 63)
      }

      const id = uuid()
      const { sql: createdAt } = createTimestamps()
      const employeeName = raw.name || (raw.email ? String(raw.email).split('@')[0] : 'Account user')
      try {
        await db.execute(`INSERT INTO employees (
          id, employee_id, employee_name, designation, email, mobile, department, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)` , [
          id,
          employeeId,
          employeeName,
          'Account user',
          raw.email,
          null,
          'Users',
          createdAt
        ])
        existingEmails.add(email)
        existingEmployeeIds.add(employeeId)
      } catch (err: any) {
        if (err?.code !== 'ER_DUP_ENTRY') {
          console.error('Failed to sync user into employees:', err?.message || err)
        }
      }
    }
    lastUserSyncAt = Date.now()
  }

  if (force) {
    await run()
    return
  }

  userSyncInFlight = run().finally(() => {
    userSyncInFlight = null
  })
  await userSyncInFlight
}

async function findEmployeeRecord(identifier: string) {
  const db = getDb()
  const lookup = identifier.trim()
  if (!lookup) return null
  const query = 'SELECT id, employee_name, email, employee_id FROM employees WHERE id = ? OR employee_id = ? OR email = ? LIMIT 1'
  const lower = lookup.toLowerCase()
  const params: [string, string, string] = [lookup, lookup, lower]
  const [rows] = await db.execute(query, params)
  if ((rows as any[]).length > 0) return (rows as any[])[0]
  await syncUsersIntoEmployees({ force: true })
  const [rowsAfter] = await db.execute(query, params)
  return (rowsAfter as any[])[0] || null
}

function mapTaskRow(row: any, dependencyMap?: Map<string, string[]>) {
  const dependencies = dependencyMap?.get(row.id) ?? []
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    priority: row.priority,
    status: row.status,
    dueDate: row.due_date,
    employeeId: row.employee_id,
    employeeName: row.employee_name,
    employeeEmail: row.employee_email,
    team: row.team ?? undefined,
    remindBeforeMinutes: typeof row.remind_before_minutes === 'number' ? row.remind_before_minutes : undefined,
    notes: row.notes ?? undefined,
    dependencies,
    createdByUserId: row.created_by_user_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

async function loadDependenciesForTasks(taskIds: string[]): Promise<Map<string, string[]>> {
  const map = new Map<string, string[]>()
  if (taskIds.length === 0) return map
  const placeholders = taskIds.map(() => '?').join(',')
  const [rows] = await getDb().execute(
    `SELECT task_id, depends_on_task_id FROM task_dependencies WHERE task_id IN (${placeholders})`,
    taskIds
  )
  for (const row of rows as any[]) {
    const taskId = row.task_id as string
    const dependsOn = row.depends_on_task_id as string
    if (!map.has(taskId)) map.set(taskId, [])
    map.get(taskId)!.push(dependsOn)
  }
  return map
}

function sanitizeDependencyInput(raw: unknown, { exclude }: { exclude?: string } = {}) {
  if (!raw) return []
  const values = Array.isArray(raw) ? raw : String(raw).split(',')
  const unique: string[] = []
  const seen = new Set<string>()
  for (const value of values) {
    const token = String(value).trim()
    if (!token) continue
    if (exclude && token === exclude) continue
    if (seen.has(token)) continue
    seen.add(token)
    unique.push(token)
  }
  return unique
}

async function ensureDependenciesExist(taskIds: string[]): Promise<void> {
  if (taskIds.length === 0) return
  const placeholders = taskIds.map(() => '?').join(',')
  const [rows] = await getDb().execute(`SELECT id FROM tasks WHERE id IN (${placeholders})`, taskIds)
  const found = new Set((rows as any[]).map(r => r.id as string))
  const missing = taskIds.filter(id => !found.has(id))
  if (missing.length > 0) {
    throw new Error(`Unknown dependency id(s): ${missing.join(', ')}`)
  }
}

async function replaceTaskDependencies(taskId: string, dependencyIds: string[]) {
  const db = getDb()
  await db.execute('DELETE FROM task_dependencies WHERE task_id = ?', [taskId])
  if (dependencyIds.length === 0) return
  const tuples = dependencyIds.map(() => '(?, ?)').join(',')
  const params: string[] = []
  dependencyIds.forEach(dep => {
    params.push(taskId, dep)
  })
  await db.execute(`INSERT INTO task_dependencies (task_id, depends_on_task_id) VALUES ${tuples}`, params)
}

function mapActivityRow(row: any) {
  const createdAt = row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString()
  const occurredAt = row.occurred_at ? new Date(row.occurred_at).toISOString() : createdAt
  const sentimentScore = row.sentiment_score === null || row.sentiment_score === undefined
    ? null
    : Number.parseFloat(String(row.sentiment_score))
  return {
    id: row.id,
    entityType: row.entity_type,
    entityKey: row.entity_key,
    userEmail: row.user_email,
    userName: row.user_name,
    type: row.type,
    text: row.text,
    createdAt,
    channel: row.channel ?? null,
    direction: row.direction ?? null,
    subject: row.subject ?? null,
    occurredAt,
    sentimentScore,
    sentimentLabel: row.sentiment_label ?? null,
    metadata: parseJsonSafe<Record<string, unknown> | null>(row.metadata_json, null),
  }
}

type CreateActivityInput = {
  entityType: z.infer<typeof ActivityEntityEnum>
  entityKey: string
  text: string
  type?: z.infer<typeof ActivityTypeEnum>
  channel?: string | null
  direction?: z.infer<typeof CommunicationDirectionEnum> | null
  subject?: string | null
  occurredAt?: string | null
  metadata?: Record<string, unknown> | null
}

async function insertActivityRecord(input: CreateActivityInput, user: AuthUser) {
  const text = input.text.trim()
  if (!text) {
    throw new Error('Text is required')
  }

  const createdAtIso = new Date().toISOString()
  const createdAtDb = createdAtIso.slice(0, 19).replace('T', ' ')
  const occurredAtIso = input.occurredAt ? new Date(input.occurredAt).toISOString() : createdAtIso
  const occurredAtDb = occurredAtIso.slice(0, 19).replace('T', ' ')
  const type: z.infer<typeof ActivityTypeEnum> = input.type === 'system' && !isManager(user)
    ? 'comment'
    : (input.type ?? 'comment')

  const sentiment = analyzeSentimentText(text)
  const metadataJson = input.metadata ? JSON.stringify(input.metadata) : null
  const id = uuid()

  await getDb().execute(
    `INSERT INTO activities (
      id, entity_type, entity_key, user_email, user_name, type, text, created_at,
      channel, direction, subject, sentiment_score, sentiment_label, occurred_at, metadata_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      input.entityType,
      input.entityKey,
      user.email || null,
      user.name || null,
      type,
      text,
      createdAtDb,
      input.channel ?? null,
      input.direction ?? null,
      input.subject ?? null,
      sentiment.score,
      sentiment.label,
      occurredAtDb,
      metadataJson
    ]
  )

  return {
    id,
    entityType: input.entityType,
    entityKey: input.entityKey,
    userEmail: user.email || null,
    userName: user.name || null,
    type,
    text,
    createdAt: createdAtIso,
    channel: input.channel ?? null,
    direction: input.direction ?? null,
    subject: input.subject ?? null,
    occurredAt: occurredAtIso,
    sentimentScore: sentiment.score,
    sentimentLabel: sentiment.label,
    metadata: input.metadata ?? null
  }
}

async function recordAuditEvent(eventType: string, entityType: string | null, entityId: string | null, userId: string | null, meta: Record<string, unknown> | null) {
  try {
    await getDb().execute(
      'INSERT INTO audit_events (id, event_type, entity_type, entity_id, user_id, meta_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        uuid(),
        eventType,
        entityType,
        entityId,
        userId,
        meta ? JSON.stringify(meta) : null,
        new Date().toISOString().slice(0, 19).replace('T', ' ')
      ]
    )
  } catch (err) {
    console.error('Failed to record audit event:', err)
  }
}

type EmailTemplateDto = {
  id: string
  name: string
  description?: string | null
  subject: string
  bodyHtml?: string | null
  bodyText?: string | null
  tags: string[]
  isActive: boolean
  createdByUserId?: string | null
  updatedByUserId?: string | null
  createdAt: string
  updatedAt: string
}

function mapEmailTemplateRow(row: any): EmailTemplateDto {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? null,
    subject: row.subject,
    bodyHtml: row.body_html ?? null,
    bodyText: row.body_text ?? null,
    tags: parseJsonSafe<string[]>(row.tags, []),
    isActive: Boolean(row.is_active ?? 0),
    createdByUserId: row.created_by_user_id ?? null,
    updatedByUserId: row.updated_by_user_id ?? null,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString(),
    updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : new Date().toISOString()
  }
}

async function getEmailTemplateById(id: string) {
  const [rows] = await getDb().execute('SELECT * FROM email_templates WHERE id = ?', [id])
  if ((rows as any[]).length === 0) return null
  return mapEmailTemplateRow((rows as any[])[0])
}

async function listEmailTemplatesDb(filters: { search?: string; onlyActive?: boolean } = {}) {
  let sql = 'SELECT * FROM email_templates'
  const params: unknown[] = []
  const clauses: string[] = []
  if (filters.onlyActive !== undefined) {
    clauses.push('is_active = ?')
    params.push(filters.onlyActive ? 1 : 0)
  }
  if (filters.search) {
    clauses.push('(LOWER(name) LIKE ? OR LOWER(subject) LIKE ? OR LOWER(description) LIKE ?)')
    const like = `%${filters.search.toLowerCase()}%`
    params.push(like, like, like)
  }
  if (clauses.length > 0) {
    sql += ' WHERE ' + clauses.join(' AND ')
  }
  sql += ' ORDER BY created_at DESC'
  const [rows] = await getDb().execute(sql, params)
  return (rows as any[]).map(mapEmailTemplateRow)
}

async function insertEmailTemplateRecord(data: z.infer<typeof EmailTemplateSchema>, userId: string) {
  const id = uuid()
  await getDb().execute(
    `INSERT INTO email_templates (id, name, description, subject, body_html, body_text, tags, is_active, created_by_user_id, updated_by_user_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    , [
      id,
      data.name,
      data.description ?? null,
      data.subject,
      data.bodyHtml ?? null,
      data.bodyText ?? null,
      data.tags ? JSON.stringify(data.tags) : null,
      data.isActive === false ? 0 : 1,
      userId,
      userId
    ]
  )
  return await getEmailTemplateById(id)
}

async function updateEmailTemplateRecord(id: string, data: Partial<z.infer<typeof EmailTemplateSchema>>, userId: string) {
  const fields: string[] = []
  const params: unknown[] = []
  if (data.name !== undefined) { fields.push('name = ?'); params.push(data.name) }
  if (data.description !== undefined) { fields.push('description = ?'); params.push(data.description ?? null) }
  if (data.subject !== undefined) { fields.push('subject = ?'); params.push(data.subject) }
  if (data.bodyHtml !== undefined) { fields.push('body_html = ?'); params.push(data.bodyHtml ?? null) }
  if (data.bodyText !== undefined) { fields.push('body_text = ?'); params.push(data.bodyText ?? null) }
  if (data.tags !== undefined) { fields.push('tags = ?'); params.push(data.tags ? JSON.stringify(data.tags) : null) }
  if (data.isActive !== undefined) { fields.push('is_active = ?'); params.push(data.isActive ? 1 : 0) }
  fields.push('updated_by_user_id = ?')
  params.push(userId)
  params.push(id)
  const [result] = await getDb().execute(`UPDATE email_templates SET ${fields.join(', ')} WHERE id = ?`, params)
  if ((result as any).affectedRows === 0) return null
  return await getEmailTemplateById(id)
}

async function deactivateEmailTemplate(id: string, userId: string) {
  const [result] = await getDb().execute('UPDATE email_templates SET is_active = 0, updated_by_user_id = ? WHERE id = ?', [userId, id])
  return (result as any).affectedRows > 0
}

type TenderEmailMessageDto = {
  id: string
  tenderId: string
  templateId?: string | null
  direction: 'outbound' | 'inbound'
  subject: string
  body: string
  headers?: Record<string, unknown> | null
  status: string
  sentAt?: string | null
  createdByUserId?: string | null
  createdAt: string
}

async function insertTenderEmailMessageLog(entry: {
  tenderId: string
  templateId?: string | null
  direction: 'outbound' | 'inbound'
  subject: string
  body: string
  headers?: Record<string, unknown> | null
  status: string
  sentAt?: Date | null
  createdByUserId?: string | null
}): Promise<TenderEmailMessageDto> {
  const id = uuid()
  await getDb().execute(
    `INSERT INTO tender_email_messages (id, tender_id, template_id, direction, subject, body, headers, status, sent_at, created_by_user_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  , [
      id,
      entry.tenderId,
      entry.templateId ?? null,
      entry.direction,
      entry.subject,
      entry.body,
      entry.headers ? JSON.stringify(entry.headers) : null,
      entry.status,
      entry.sentAt ? entry.sentAt.toISOString().slice(0, 19).replace('T', ' ') : null,
      entry.createdByUserId ?? null
    ])

  return {
    id,
    tenderId: entry.tenderId,
    templateId: entry.templateId ?? null,
    direction: entry.direction,
    subject: entry.subject,
    body: entry.body,
    headers: entry.headers ?? null,
    status: entry.status,
    sentAt: entry.sentAt ? entry.sentAt.toISOString() : null,
    createdByUserId: entry.createdByUserId ?? null,
    createdAt: new Date().toISOString()
  }
}

async function getTenderById(tenderId: string) {
  const [rows] = await getDb().execute('SELECT * FROM tenders WHERE id = ?', [tenderId])
  if ((rows as any[]).length === 0) return null
  return (rows as any[])[0]
}

async function getCustomerById(customerId: string) {
  const [rows] = await getDb().execute('SELECT * FROM customers WHERE id = ?', [customerId])
  if ((rows as any[]).length === 0) return null
  return (rows as any[])[0]
}

type ChatConnectorDto = {
  id: string
  name: string
  type: string
  webhookUrl?: string | null
  metadata?: Record<string, unknown> | null
  isActive: boolean
  createdByUserId?: string | null
  createdAt: string
}

function mapChatConnectorRow(row: any): ChatConnectorDto {
  return {
    id: row.id,
    name: row.name,
    type: row.type,
    webhookUrl: row.webhook_url ?? null,
  metadata: parseJsonSafe<Record<string, unknown> | null>(row.metadata, null),
    isActive: Boolean(row.is_active ?? 0),
    createdByUserId: row.created_by_user_id ?? null,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString()
  }
}

async function getChatConnectorById(id: string) {
  const [rows] = await getDb().execute('SELECT * FROM chat_connectors WHERE id = ?', [id])
  if ((rows as any[]).length === 0) return null
  return mapChatConnectorRow((rows as any[])[0])
}

async function listChatConnectorsDb(filters: { onlyActive?: boolean } = {}) {
  let sql = 'SELECT * FROM chat_connectors'
  const params: unknown[] = []
  const clauses: string[] = []
  if (filters.onlyActive !== undefined) {
    clauses.push('is_active = ?')
    params.push(filters.onlyActive ? 1 : 0)
  }
  if (clauses.length > 0) {
    sql += ' WHERE ' + clauses.join(' AND ')
  }
  sql += ' ORDER BY created_at DESC'
  const [rows] = await getDb().execute(sql, params)
  return (rows as any[]).map(mapChatConnectorRow)
}

async function insertChatConnectorRecord(data: z.infer<typeof ChatConnectorSchema>, userId: string) {
  const id = uuid()
  await getDb().execute(
    `INSERT INTO chat_connectors (id, name, type, webhook_url, metadata, is_active, created_by_user_id)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
    , [
      id,
      data.name,
      data.type,
      data.webhookUrl ?? null,
      data.metadata ? JSON.stringify(data.metadata) : null,
      data.isActive === false ? 0 : 1,
      userId
    ]
  )
  return await getChatConnectorById(id)
}

async function updateChatConnectorRecord(id: string, data: Partial<z.infer<typeof ChatConnectorSchema>>) {
  const fields: string[] = []
  const params: unknown[] = []
  if (data.name !== undefined) { fields.push('name = ?'); params.push(data.name) }
  if (data.type !== undefined) { fields.push('type = ?'); params.push(data.type) }
  if (data.webhookUrl !== undefined) { fields.push('webhook_url = ?'); params.push(data.webhookUrl ?? null) }
  if (data.metadata !== undefined) { fields.push('metadata = ?'); params.push(data.metadata ? JSON.stringify(data.metadata) : null) }
  if (data.isActive !== undefined) { fields.push('is_active = ?'); params.push(data.isActive ? 1 : 0) }
  if (fields.length === 0) return await getChatConnectorById(id)
  params.push(id)
  const [result] = await getDb().execute(`UPDATE chat_connectors SET ${fields.join(', ')} WHERE id = ?`, params)
  if ((result as any).affectedRows === 0) return null
  return await getChatConnectorById(id)
}

async function deactivateChatConnector(id: string) {
  const [result] = await getDb().execute('UPDATE chat_connectors SET is_active = 0 WHERE id = ?', [id])
  return (result as any).affectedRows > 0
}

type ChatMessageDto = {
  id: string
  connectorId: string
  entityType: string
  entityId: string
  direction: 'outbound' | 'inbound'
  text: string
  status: string
  response?: Record<string, unknown> | null
  createdByUserId?: string | null
  createdAt: string
}

async function insertChatMessageRecord(entry: {
  connectorId: string
  entityType: string
  entityId: string
  direction: 'outbound' | 'inbound'
  text: string
  status: string
  response?: Record<string, unknown> | null
  createdByUserId?: string | null
}): Promise<ChatMessageDto> {
  const id = uuid()
  await getDb().execute(
    `INSERT INTO chat_messages (id, connector_id, entity_type, entity_id, direction, text, status, response, created_by_user_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    , [
      id,
      entry.connectorId,
      entry.entityType,
      entry.entityId,
      entry.direction,
      entry.text,
      entry.status,
      entry.response ? JSON.stringify(entry.response) : null,
      entry.createdByUserId ?? null
    ]
  )

  return {
    id,
    connectorId: entry.connectorId,
    entityType: entry.entityType,
    entityId: entry.entityId,
    direction: entry.direction,
    text: entry.text,
    status: entry.status,
    response: entry.response ?? null,
    createdByUserId: entry.createdByUserId ?? null,
    createdAt: new Date().toISOString()
  }
}

async function listChatMessages(connectorId: string, limit = 50) {
  const [rows] = await getDb().execute(
    'SELECT * FROM chat_messages WHERE connector_id = ? ORDER BY created_at DESC LIMIT ?',
    [connectorId, limit]
  )
  return (rows as any[]).map(row => ({
    id: row.id,
    connectorId: row.connector_id,
    entityType: row.entity_type,
    entityId: row.entity_id,
    direction: row.direction,
    text: row.text,
    status: row.status,
  response: parseJsonSafe<Record<string, unknown> | null>(row.response, null),
    createdByUserId: row.created_by_user_id ?? null,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString()
  }))
}

type VoiceCallDto = {
  id: string
  entityType: z.infer<typeof ActivityEntityEnum>
  entityId: string
  subject?: string | null
  participants: string[]
  status: string
  outcome?: string | null
  summary?: string | null
  recordingUrl?: string | null
  durationSeconds?: number | null
  createdByUserId?: string | null
  createdAt: string
}

function mapVoiceCallRow(row: any): VoiceCallDto {
  return {
    id: row.id,
    entityType: ActivityEntityEnum.safeParse(row.entity_type).success ? row.entity_type as z.infer<typeof ActivityEntityEnum> : 'tender',
    entityId: row.entity_id,
    subject: row.subject ?? null,
    participants: parseJsonSafe<string[]>(row.participants, []),
    status: row.status,
    outcome: row.outcome ?? null,
    summary: row.summary ?? null,
    recordingUrl: row.recording_url ?? null,
    durationSeconds: row.duration_seconds !== null && row.duration_seconds !== undefined ? Number(row.duration_seconds) : null,
    createdByUserId: row.created_by_user_id ?? null,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString()
  }
}

async function listVoiceCalls(filters: { entityType?: string; entityId?: string; limit?: number } = {}) {
  let sql = 'SELECT * FROM voice_calls'
  const params: unknown[] = []
  const clauses: string[] = []
  if (filters.entityType) { clauses.push('entity_type = ?'); params.push(filters.entityType) }
  if (filters.entityId) { clauses.push('entity_id = ?'); params.push(filters.entityId) }
  if (clauses.length > 0) {
    sql += ' WHERE ' + clauses.join(' AND ')
  }
  sql += ' ORDER BY created_at DESC'
  if (filters.limit) {
    sql += ' LIMIT ?'
    params.push(filters.limit)
  }
  const [rows] = await getDb().execute(sql, params)
  return (rows as any[]).map(mapVoiceCallRow)
}

async function insertVoiceCallRecord(data: z.infer<typeof VoiceCallCreateSchema>, userId: string) {
  const id = uuid()
  await getDb().execute(
    `INSERT INTO voice_calls (id, entity_type, entity_id, subject, participants, status, outcome, summary, recording_url, duration_seconds, created_by_user_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    , [
      id,
      data.entityType,
      data.entityId,
      data.subject ?? null,
      data.participants ? JSON.stringify(data.participants) : null,
      data.status ?? 'completed',
      data.outcome ?? null,
      data.summary ?? null,
      data.recordingUrl ?? null,
      data.durationSeconds ?? null,
      userId
    ]
  )
  const [rowData] = await getDb().execute('SELECT * FROM voice_calls WHERE id = ?', [id])
  return mapVoiceCallRow((rowData as any[])[0])
}

async function updateVoiceCallRecord(id: string, data: Partial<z.infer<typeof VoiceCallCreateSchema>>) {
  const fields: string[] = []
  const params: unknown[] = []
  if (data.entityType !== undefined) { fields.push('entity_type = ?'); params.push(data.entityType) }
  if (data.entityId !== undefined) { fields.push('entity_id = ?'); params.push(data.entityId) }
  if (data.subject !== undefined) { fields.push('subject = ?'); params.push(data.subject ?? null) }
  if (data.participants !== undefined) { fields.push('participants = ?'); params.push(data.participants ? JSON.stringify(data.participants) : null) }
  if (data.status !== undefined) { fields.push('status = ?'); params.push(data.status) }
  if (data.outcome !== undefined) { fields.push('outcome = ?'); params.push(data.outcome ?? null) }
  if (data.summary !== undefined) { fields.push('summary = ?'); params.push(data.summary ?? null) }
  if (data.recordingUrl !== undefined) { fields.push('recording_url = ?'); params.push(data.recordingUrl ?? null) }
  if (data.durationSeconds !== undefined) { fields.push('duration_seconds = ?'); params.push(data.durationSeconds ?? null) }
  if (fields.length === 0) return await getVoiceCallById(id)
  params.push(id)
  const [result] = await getDb().execute(`UPDATE voice_calls SET ${fields.join(', ')} WHERE id = ?`, params)
  if ((result as any).affectedRows === 0) return null
  return await getVoiceCallById(id)
}

async function getVoiceCallById(id: string) {
  const [rows] = await getDb().execute('SELECT * FROM voice_calls WHERE id = ?', [id])
  if ((rows as any[]).length === 0) return null
  return mapVoiceCallRow((rows as any[])[0])
}

type ApprovalPolicyDto = {
  id: string
  name: string
  description?: string | null
  criteria: Record<string, unknown> | null
  steps: Array<Record<string, unknown>> | null
  isActive: boolean
  createdByUserId?: string | null
  createdAt: string
}

function mapApprovalPolicyRow(row: any): ApprovalPolicyDto {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? null,
  criteria: parseJsonSafe<Record<string, unknown> | null>(row.criteria_json, null),
  steps: parseJsonSafe<Array<Record<string, unknown>> | null>(row.steps_json, null),
    isActive: Boolean(row.is_active ?? 0),
    createdByUserId: row.created_by_user_id ?? null,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString()
  }
}

async function listApprovalPolicies(filters: { includeInactive?: boolean } = {}) {
  let sql = 'SELECT * FROM approval_policies'
  const params: unknown[] = []
  if (!filters.includeInactive) {
    sql += ' WHERE is_active = 1'
  }
  sql += ' ORDER BY created_at DESC'
  const [rows] = await getDb().execute(sql, params)
  return (rows as any[]).map(mapApprovalPolicyRow)
}

async function insertApprovalPolicyRecord(data: z.infer<typeof ApprovalPolicySchema>, userId: string) {
  const id = uuid()
  await getDb().execute(
    `INSERT INTO approval_policies (id, name, description, criteria_json, steps_json, is_active, created_by_user_id)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
    , [
      id,
      data.name,
      data.description ?? null,
      data.criteria ? JSON.stringify(data.criteria) : null,
      data.steps ? JSON.stringify(data.steps) : null,
      data.isActive === false ? 0 : 1,
      userId
    ]
  )
  return await getApprovalPolicyById(id)
}

async function updateApprovalPolicyRecord(id: string, data: Partial<z.infer<typeof ApprovalPolicySchema>>) {
  const fields: string[] = []
  const params: unknown[] = []
  if (data.name !== undefined) { fields.push('name = ?'); params.push(data.name) }
  if (data.description !== undefined) { fields.push('description = ?'); params.push(data.description ?? null) }
  if (data.criteria !== undefined) { fields.push('criteria_json = ?'); params.push(data.criteria ? JSON.stringify(data.criteria) : null) }
  if (data.steps !== undefined) { fields.push('steps_json = ?'); params.push(data.steps ? JSON.stringify(data.steps) : null) }
  if (data.isActive !== undefined) { fields.push('is_active = ?'); params.push(data.isActive ? 1 : 0) }
  if (fields.length === 0) return await getApprovalPolicyById(id)
  params.push(id)
  const [result] = await getDb().execute(`UPDATE approval_policies SET ${fields.join(', ')} WHERE id = ?`, params)
  if ((result as any).affectedRows === 0) return null
  return await getApprovalPolicyById(id)
}

async function deactivateApprovalPolicy(id: string) {
  const [result] = await getDb().execute('UPDATE approval_policies SET is_active = 0 WHERE id = ?', [id])
  return (result as any).affectedRows > 0
}

async function getApprovalPolicyById(id: string) {
  const [rows] = await getDb().execute('SELECT * FROM approval_policies WHERE id = ?', [id])
  if ((rows as any[]).length === 0) return null
  return mapApprovalPolicyRow((rows as any[])[0])
}

type ApprovalRequestDto = {
  id: string
  policyId: string
  entityType: z.infer<typeof ActivityEntityEnum>
  entityId: string
  status: string
  submittedByUserId?: string | null
  submittedAt: string
  decidedAt?: string | null
  decisionNotes?: string | null
  context?: Record<string, unknown> | null
}

function mapApprovalRequestRow(row: any): ApprovalRequestDto {
  const entityTypeParsed = ActivityEntityEnum.safeParse(row.entity_type)
  return {
    id: row.id,
    policyId: row.policy_id,
    entityType: entityTypeParsed.success ? entityTypeParsed.data : 'tender',
    entityId: row.entity_id,
    status: row.status,
    submittedByUserId: row.submitted_by_user_id ?? null,
    submittedAt: row.submitted_at ? new Date(row.submitted_at).toISOString() : new Date().toISOString(),
    decidedAt: row.decided_at ? new Date(row.decided_at).toISOString() : null,
    decisionNotes: row.decision_notes ?? null,
    context: parseJsonSafe<Record<string, unknown> | null>(row.context_json, null)
  }
}

async function listApprovalRequests(filters: { entityType?: string; entityId?: string; status?: string } = {}) {
  let sql = 'SELECT * FROM approval_requests'
  const params: unknown[] = []
  const clauses: string[] = []
  if (filters.entityType) { clauses.push('entity_type = ?'); params.push(filters.entityType) }
  if (filters.entityId) { clauses.push('entity_id = ?'); params.push(filters.entityId) }
  if (filters.status) { clauses.push('status = ?'); params.push(filters.status) }
  if (clauses.length > 0) {
    sql += ' WHERE ' + clauses.join(' AND ')
  }
  sql += ' ORDER BY submitted_at DESC'
  const [rows] = await getDb().execute(sql, params)
  return (rows as any[]).map(mapApprovalRequestRow)
}

async function insertApprovalRequestRecord(data: z.infer<typeof ApprovalRequestSchema>, userId: string) {
  const id = uuid()
  const contextJson = data.context ? JSON.stringify(data.context) : null
  await getDb().execute(
    `INSERT INTO approval_requests (id, policy_id, entity_type, entity_id, status, submitted_by_user_id, context_json)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
    , [
      id,
      data.policyId,
      data.entityType,
      data.entityId,
      'pending',
      userId,
      contextJson
    ]
  )
  return await getApprovalRequestById(id)
}

async function updateApprovalRequestStatus(id: string, status: string, notes: string | null, userId: string) {
  const decidedAt = new Date()
  const [result] = await getDb().execute(
    `UPDATE approval_requests
     SET status = ?, decided_at = ?, decision_notes = ?, submitted_by_user_id = submitted_by_user_id
     WHERE id = ? AND status IN ('pending', 'in_review')`,
    [status, decidedAt.toISOString().slice(0, 19).replace('T', ' '), notes ?? null, id]
  )
  if ((result as any).affectedRows === 0) return null
  await recordAuditEvent('approval.decision', 'approval_request', id, userId, { status, notes })
  return await getApprovalRequestById(id)
}

async function markApprovalRequestInReview(id: string, notes: string | null, userId: string) {
  const [result] = await getDb().execute(
    `UPDATE approval_requests
     SET status = ?, decision_notes = ?, decided_at = NULL
     WHERE id = ? AND status = 'pending'`,
    ['in_review', notes ?? null, id]
  )
  if ((result as any).affectedRows === 0) return null
  await recordAuditEvent('approval.review', 'approval_request', id, userId, { status: 'in_review', notes })
  return await getApprovalRequestById(id)
}

async function getApprovalRequestById(id: string) {
  const [rows] = await getDb().execute('SELECT * FROM approval_requests WHERE id = ?', [id])
  if ((rows as any[]).length === 0) return null
  return mapApprovalRequestRow((rows as any[])[0])
}

app.get('/api/activities', requireAuth, async (req: Request, res: Response) => {
  const parsed = ActivityQuerySchema.safeParse({
    entityType: req.query.entityType,
    entityKey: req.query.entityKey,
  })
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() })
  }

  try {
    const { entityType, entityKey } = parsed.data
    const [rows] = await getDb().execute(
      'SELECT * FROM activities WHERE entity_type = ? AND entity_key = ? ORDER BY COALESCE(occurred_at, created_at) DESC, created_at DESC',
      [entityType, entityKey]
    )
    res.json((rows as any[]).map(mapActivityRow))
  } catch (err: any) {
    console.error('Failed to fetch activities:', err)
    if (res.headersSent) return
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/activities', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const parsed = ActivityCreateSchema.safeParse(req.body)
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() })
  }

  const data = parsed.data

  try {
    const created = await insertActivityRecord({
      entityType: data.entityType,
      entityKey: data.entityKey,
      text: data.text,
      type: data.type,
      channel: data.channel ?? null,
      direction: data.direction ?? null,
      subject: data.subject ?? null,
      occurredAt: data.occurredAt ?? null,
      metadata: data.metadata ?? null
    }, user)

    res.status(201).json(created)
  } catch (err: any) {
    console.error('Failed to create activity:', err)
    if (res.headersSent) return
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.get('/api/customers/:id/communications', requireAuth, async (req: Request, res: Response) => {
  try {
    const customerId = req.params.id
    const communications = await fetchCustomerCommunications(customerId, 100)
    res.json(communications)
  } catch (err: any) {
    console.error('Failed to load communications:', err)
    res.status(500).json({ error: 'Failed to load communications' })
  }
})

app.post('/api/customers/:id/communications', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const parsed = CommunicationCreateSchema.safeParse(req.body)
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() })
  }

  try {
    const customerId = req.params.id
    const created = await insertActivityRecord({
      entityType: 'customer',
      entityKey: customerId,
      text: parsed.data.text,
      type: 'communication',
      channel: parsed.data.channel,
      direction: parsed.data.direction,
      subject: parsed.data.subject ?? null,
      occurredAt: parsed.data.occurredAt ?? null,
      metadata: parsed.data.metadata ?? null
    }, user)
    if (parsed.data.channel?.toLowerCase() === 'email' && parsed.data.direction === 'outbound') {
      queueIntegrationEvent('communication.email.sent', {
        customerId,
        activityId: created.id,
        channel: parsed.data.channel,
        direction: parsed.data.direction,
        actorUserId: user.id
      })
    }
    res.status(201).json(created)
  } catch (err: any) {
    console.error('Failed to record communication:', err)
    if (res.headersSent) return
    res.status(500).json({ error: 'Failed to record communication' })
  }
})

app.get('/api/email/templates', requireAuth, async (req: Request, res: Response) => {
  try {
    const search = typeof req.query.search === 'string' ? req.query.search.trim() : undefined
    const activeParam = typeof req.query.active === 'string' ? req.query.active.toLowerCase() : undefined
    let onlyActive: boolean | undefined
    if (activeParam === 'true') onlyActive = true
    if (activeParam === 'false') onlyActive = false
    const templates = await listEmailTemplatesDb({ search, onlyActive })
    res.json(templates)
  } catch (err: any) {
    console.error('Failed to list email templates:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/email/templates', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (!isManager(user)) return res.status(403).json({ error: 'forbidden' })
  const parsed = EmailTemplateSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    const template = await insertEmailTemplateRecord(parsed.data, user.id)
    await recordAuditEvent('email_template.created', 'email_template', template?.id ?? null, user.id, { name: template?.name })
    res.status(201).json(template)
  } catch (err: any) {
    console.error('Failed to create email template:', err)
    res.status(500).json({ error: err?.message || 'Internal server error' })
  }
})

app.get('/api/email/templates/:id', requireAuth, async (req: Request, res: Response) => {
  try {
    const template = await getEmailTemplateById(req.params.id)
    if (!template) return res.status(404).json({ error: 'Not found' })
    res.json(template)
  } catch (err: any) {
    console.error('Failed to fetch email template:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.put('/api/email/templates/:id', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (!isManager(user)) return res.status(403).json({ error: 'forbidden' })
  const parsed = EmailTemplateSchema.partial().safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    const template = await updateEmailTemplateRecord(req.params.id, parsed.data, user.id)
    if (!template) return res.status(404).json({ error: 'Not found' })
    await recordAuditEvent('email_template.updated', 'email_template', template.id, user.id, { name: template.name })
    res.json(template)
  } catch (err: any) {
    console.error('Failed to update email template:', err)
    res.status(500).json({ error: err?.message || 'Internal server error' })
  }
})

app.delete('/api/email/templates/:id', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (!isManager(user)) return res.status(403).json({ error: 'forbidden' })
  try {
    const success = await deactivateEmailTemplate(req.params.id, user.id)
    if (!success) return res.status(404).json({ error: 'Not found' })
    await recordAuditEvent('email_template.deactivated', 'email_template', req.params.id, user.id, null)
    res.status(204).end()
  } catch (err: any) {
    console.error('Failed to delete email template:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/tenders/:id/email/send', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const tenderId = req.params.id
  const parsed = EmailSendSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  try {
    const tender = await getTenderById(tenderId)
    if (!tender) return res.status(404).json({ error: 'Tender not found' })
    if (!isManager(user)) {
      const ownerId = tender.owner_user_id ?? null
      const allottedTo = (tender.allotted_to || '').toLowerCase()
      const userEmail = (user.email || '').toLowerCase()
      if (ownerId && ownerId !== user.id && allottedTo !== userEmail) {
        return res.status(403).json({ error: 'forbidden' })
      }
    }

    const data = parsed.data
    let template: EmailTemplateDto | null = null
    if (data.templateId) {
      template = await getEmailTemplateById(data.templateId)
      if (!template || !template.isActive) {
        return res.status(404).json({ error: 'Template not found or inactive' })
      }
    }

    const to = data.to.map(email => email.trim()).filter(Boolean)
    if (to.length === 0) {
      return res.status(400).json({ error: 'At least one recipient is required' })
    }

    const subject = template?.subject ?? data.subject ?? ''
    const html = template?.bodyHtml ?? null
    const text = template?.bodyText ?? data.body ?? ''
    if (!subject || (!html && !text)) {
      return res.status(400).json({ error: 'Subject and body are required' })
    }

    const delivery = await deliverEmailMessage({ to, subject, html, text })
    const status = delivery.status === 'sent'
      ? 'sent'
      : delivery.status === 'queued'
        ? 'queued'
        : delivery.status === 'logged'
          ? 'logged'
          : 'failed'

    const messageBody = html ?? text
    const message = await insertTenderEmailMessageLog({
      tenderId,
      templateId: template?.id ?? null,
      direction: 'outbound',
      subject,
      body: messageBody,
      headers: { to },
      status,
      sentAt: delivery.status === 'sent' ? new Date() : null,
      createdByUserId: user.id
    })

    await insertActivityRecord({
      entityType: 'tender',
      entityKey: tenderId,
      text: `Email sent to ${to.join(', ')}`,
      type: 'communication',
      channel: 'email',
      direction: 'outbound',
      subject,
      metadata: {
        to,
        templateId: template?.id ?? null,
        deliveryStatus: status,
        notes: data.notes ?? null
      }
    }, user)

    await recordAuditEvent('email.sent', 'tender', tenderId, user.id, {
      templateId: template?.id ?? null,
      to,
      status: delivery.status,
      detail: delivery.detail
    })

    queueIntegrationEvent('communication.email.sent', {
      tenderId,
      to,
      status: delivery.status,
      actorUserId: user.id
    })

    res.status(201).json({ message, delivery })
  } catch (err: any) {
    console.error('Failed to send email:', err)
    if (res.headersSent) return
    res.status(500).json({ error: err?.message || 'Internal server error' })
  }
})

app.post('/api/email/inbound', async (req: Request, res: Response) => {
  try {
    if (EMAIL_SYNC_TOKEN) {
      const token = (req.header('x-sync-token') || req.query.token || '').toString()
      if (token !== EMAIL_SYNC_TOKEN) {
        return res.status(403).json({ error: 'forbidden' })
      }
    }
    const parsed = InboundEmailSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
    const data = parsed.data
    const tender = await getTenderById(data.tenderId)
    if (!tender) return res.status(404).json({ error: 'Tender not found' })

    const message = await insertTenderEmailMessageLog({
      tenderId: data.tenderId,
      direction: 'inbound',
      subject: data.subject,
      body: data.body,
      headers: data.headers ?? undefined,
      status: 'received',
      sentAt: null,
      createdByUserId: null
    })

    await insertActivityRecord({
      entityType: 'tender',
      entityKey: data.tenderId,
      text: `Inbound email from ${data.from}`,
      type: 'communication',
      channel: 'email',
      direction: 'inbound',
      subject: data.subject,
      metadata: {
        from: data.from,
        externalId: data.externalId ?? null,
        headers: data.headers ?? null
      }
    }, systemUser)

    await recordAuditEvent('email.inbound', 'tender', data.tenderId, null, {
      from: data.from,
      externalId: data.externalId ?? null,
      messageId: message.id
    })

    res.status(202).json({ ok: true })
  } catch (err: any) {
    console.error('Failed to ingest inbound email:', err)
    if (res.headersSent) return
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.get('/api/tenders', requireAuth, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user as AuthUser
    let sql = 'SELECT * FROM tenders'
    const params: unknown[] = []
    if (user.role === 'agent') {
      const conditions: string[] = []
      const seenValues = new Set<string>()

      conditions.push('owner_user_id = ?')
      params.push(user.id)

      if (user.email) {
        conditions.push('LOWER(allotted_to) = ?')
        params.push(user.email.toLowerCase())
      }

      if (user.email) {
        const employee = await findEmployeeRecord(user.email)
        if (employee) {
          const identifiers = new Set<string>()
          if (employee.id) identifiers.add(String(employee.id))
          if (employee.employee_id) identifiers.add(String(employee.employee_id))
          identifiers.forEach(identifier => {
            if (!seenValues.has(identifier)) {
              conditions.push('t.employee_id = ?')
              params.push(identifier)
              seenValues.add(identifier)
            }
          })
        }
      }

      if (conditions.length > 0) {
        sql += ` WHERE ${conditions.join(' OR ')}`
      }
    }
    sql += ' ORDER BY created_at DESC'
    const [rows] = await getDb().execute(sql, params)
    const mapped = (rows as any[]).map((r: any) => ({
      id: r.id,
      dateOfService: r.date_of_service,
      serialToken: r.serial_token,
      allottedTo: r.allotted_to,
      source: r.source,
      priority: r.priority,
      status: r.status,
      customerId: r.customer_id,
      customerName: r.customer_name,
      employeeId: r.employee_id,
      employeeName: r.employee_name,
      leadTitle: r.lead_title,
      leadDescription: r.lead_description,
      estimatedValue: r.estimated_value,
      followUpDate: r.follow_up_date,
      ownerUserId: r.owner_user_id,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    }))
    res.json(mapped)
  } catch (err: any) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/tenders', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const parsed = TenderSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  if (user.role === 'viewer') return res.status(403).json({ error: 'forbidden' })

  const data = parsed.data
  const { iso: nowIso, sql: nowSql } = createTimestamps()
  const id = uuid()
  let ownerUserId: string | null = data.ownerUserId ?? null

  if (user.role === 'agent') {
    ownerUserId = user.id
    if (!data.allottedTo || data.allottedTo.trim() === '') {
      data.allottedTo = user.email
    } else if (data.allottedTo.toLowerCase() !== user.email.toLowerCase()) {
      return res.status(403).json({ error: 'Agents may only create tickets for themselves' })
    }
  }

  const pool = getDb()
  const conn = await pool.getConnection()

  try {
    const serialToken = (data.serialToken || '').trim()
    if (!serialToken) {
      return res.status(400).json({ error: 'Serial token is required' })
    }

    const dateOfService = normalizeDateInput(data.dateOfService)
    if (data.dateOfService && !dateOfService) {
      return res.status(400).json({ error: 'dateOfService must be YYYY-MM-DD' })
    }

    const followUpDate = normalizeDateInput(data.followUpDate)
    if (data.followUpDate && !followUpDate) {
      return res.status(400).json({ error: 'followUpDate must be YYYY-MM-DD' })
    }

    const allottedTo = normalizeOptionalString(data.allottedTo)
    const source = normalizeOptionalString(data.source)
    const priority = normalizeOptionalString(data.priority)
    const statusValue = normalizeOptionalString(data.status)
    const customerId = normalizeOptionalString(data.customerId)
    const customerName = normalizeOptionalString(data.customerName)
    const employeeId = normalizeOptionalString(data.employeeId)
    const employeeName = normalizeOptionalString(data.employeeName)
    const leadTitle = normalizeOptionalString(data.leadTitle)
    const leadDescription = normalizeOptionalString(data.leadDescription)
    const estimatedValue = normalizeOptionalString(data.estimatedValue)

    data.serialToken = serialToken
    data.dateOfService = dateOfService ?? undefined
    data.allottedTo = allottedTo ?? undefined
    data.source = source ?? undefined
    data.priority = priority ?? undefined
    data.status = statusValue ?? undefined
    data.customerId = customerId ?? undefined
    data.customerName = customerName ?? undefined
    data.employeeId = employeeId ?? undefined
    data.employeeName = employeeName ?? undefined
    data.leadTitle = leadTitle ?? undefined
    data.leadDescription = leadDescription ?? undefined
    data.estimatedValue = estimatedValue ?? undefined
    data.followUpDate = followUpDate ?? undefined

    await conn.beginTransaction()

    await conn.execute(`INSERT INTO tenders (
      id, date_of_service, serial_token, allotted_to, source, priority, status,
      customer_id, customer_name, employee_id, employee_name, lead_title, lead_description,
      estimated_value, follow_up_date, owner_user_id, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      dateOfService ?? null,
      serialToken,
      allottedTo,
      source,
      priority,
      statusValue,
      customerId,
      customerName,
      employeeId,
      employeeName,
      leadTitle,
      leadDescription,
      estimatedValue,
      followUpDate,
      ownerUserId,
      nowSql,
      nowSql
    ])

    const snapshot = {
      tenderId: id,
      serialToken,
      dateOfService: dateOfService ?? null,
      allottedTo: allottedTo ?? null,
      source: source ?? null,
      priority: priority ?? null,
      status: statusValue ?? null,
      customerId: customerId ?? null,
      customerName: customerName ?? null,
      employeeId: employeeId ?? null,
      employeeName: employeeName ?? null,
      leadTitle: leadTitle ?? null,
      leadDescription: leadDescription ?? null,
      estimatedValue: estimatedValue ?? null,
      followUpDate: followUpDate ?? null,
      ownerUserId,
      createdAt: nowIso,
      createdBy: {
        userId: user.id,
        email: user.email,
        role: user.role
      }
    }
    const snapshotJson = JSON.stringify(snapshot)
    const snapshotHash = createHash('sha256').update(snapshotJson).digest('hex')

    await conn.execute(`INSERT INTO tender_backups (
      id, tender_id, serial_token, snapshot_json, snapshot_hash, created_by_user_id, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)` , [
      uuid(),
      id,
      data.serialToken,
      snapshotJson,
      snapshotHash,
      user.id,
      nowSql
    ])

    await conn.commit()

    const payload = { id, ...data, ownerUserId, createdAt: nowIso, updatedAt: nowIso }
    queueIntegrationEvent('tender.created', {
      id,
      serialToken,
      priority: priority ?? null,
      status: statusValue ?? null,
      ownerUserId
    })
    res.status(201).json(payload)
  } catch (err: any) {
    try {
      await conn.rollback()
    } catch (_) {}
    console.error('Failed to create tender:', err)
    if (res.headersSent) return
    res.status(400).json({ error: err?.message || 'Failed to create tender' })
  } finally {
    conn.release()
  }
})

app.put('/api/tenders/:id', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const parsed = TenderSchema.partial().safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const id = req.params.id

  try {
    const [rows] = await getDb().execute('SELECT owner_user_id FROM tenders WHERE id = ?', [id])
    if ((rows as any[]).length === 0) return res.status(404).json({ error: 'Not found' })
    let ownerUserId: string | null = (rows as any[])[0].owner_user_id ?? null

    if (!isManager(user)) {
      if (!ownerUserId || ownerUserId !== user.id) {
        return res.status(403).json({ error: 'forbidden' })
      }
    }

    const data = parsed.data

    if (isManager(user)) {
      if (data.ownerUserId !== undefined) {
        ownerUserId = data.ownerUserId || null
      }
    } else {
      ownerUserId = user.id
      if (data.allottedTo && data.allottedTo.toLowerCase() !== user.email.toLowerCase()) {
        return res.status(403).json({ error: 'Agents may not reassign tickets' })
      }
      if (!data.allottedTo) data.allottedTo = user.email
    }

    const [result] = await getDb().execute(`UPDATE tenders SET
      date_of_service = ?,
      serial_token = ?,
      allotted_to = ?,
      source = ?,
      priority = ?,
      status = ?,
      customer_id = ?,
      customer_name = ?,
      employee_id = ?,
      employee_name = ?,
      lead_title = ?,
      lead_description = ?,
      estimated_value = ?,
      follow_up_date = ?,
      owner_user_id = ?,
      updated_at = NOW()
      WHERE id = ?`, [
        data.dateOfService,
        data.serialToken,
        data.allottedTo,
        data.source,
        data.priority,
        data.status,
        data.customerId,
        data.customerName,
        data.employeeId,
        data.employeeName,
        data.leadTitle,
        data.leadDescription,
        data.estimatedValue,
        data.followUpDate,
        ownerUserId,
        id
      ])

    if ((result as any).affectedRows === 0) return res.status(404).json({ error: 'Not found' })

    const [updatedRows] = await getDb().execute('SELECT * FROM tenders WHERE id = ?', [id])
    const row = (updatedRows as any[])[0]
    if (!row) return res.status(404).json({ error: 'Not found' })
    const response = {
      id: row.id,
      dateOfService: row.date_of_service,
      serialToken: row.serial_token,
      allottedTo: row.allotted_to,
      source: row.source,
      priority: row.priority,
      status: row.status,
      customerId: row.customer_id,
      customerName: row.customer_name,
      employeeId: row.employee_id,
      employeeName: row.employee_name,
      leadTitle: row.lead_title,
      leadDescription: row.lead_description,
      estimatedValue: row.estimated_value,
      followUpDate: row.follow_up_date,
      ownerUserId: row.owner_user_id,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }
    queueIntegrationEvent('tender.updated', {
      id,
      serialToken: row.serial_token,
      priority: row.priority,
      status: row.status,
      ownerUserId: row.owner_user_id
    })
    res.json(response)
  } catch (err: any) {
    res.status(400).json({ error: err.message })
  }
})

app.delete('/api/tenders/:id', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const id = req.params.id
  try {
    if (!isManager(user)) {
      const [rows] = await getDb().execute('SELECT id FROM tenders WHERE id = ? AND owner_user_id = ?', [id, user.id])
      if ((rows as any[]).length === 0) return res.status(403).json({ error: 'forbidden' })
    }
    const [result] = await getDb().execute('DELETE FROM tenders WHERE id = ?', [id])
    if ((result as any).affectedRows === 0) return res.status(404).json({ error: 'Not found' })
    res.status(204).end()
  } catch (err: any) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/chat/connectors', requireAuth, async (_req: Request, res: Response) => {
  try {
    const connectors = await listChatConnectorsDb()
    res.json(connectors)
  } catch (err: any) {
    console.error('Failed to list chat connectors:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/chat/connectors', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (!isManager(user)) return res.status(403).json({ error: 'forbidden' })
  const parsed = ChatConnectorSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    const connector = await insertChatConnectorRecord(parsed.data, user.id)
    await recordAuditEvent('chat.connector.created', 'chat_connector', connector?.id ?? null, user.id, { type: connector?.type })
    res.status(201).json(connector)
  } catch (err: any) {
    console.error('Failed to create chat connector:', err)
    res.status(500).json({ error: err?.message || 'Internal server error' })
  }
})

app.put('/api/chat/connectors/:id', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (!isManager(user)) return res.status(403).json({ error: 'forbidden' })
  const parsed = ChatConnectorSchema.partial().safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    const connector = await updateChatConnectorRecord(req.params.id, parsed.data)
    if (!connector) return res.status(404).json({ error: 'Not found' })
    await recordAuditEvent('chat.connector.updated', 'chat_connector', connector.id, user.id, { type: connector.type })
    res.json(connector)
  } catch (err: any) {
    console.error('Failed to update chat connector:', err)
    res.status(500).json({ error: err?.message || 'Internal server error' })
  }
})

app.delete('/api/chat/connectors/:id', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (!isManager(user)) return res.status(403).json({ error: 'forbidden' })
  try {
    const success = await deactivateChatConnector(req.params.id)
    if (!success) return res.status(404).json({ error: 'Not found' })
    await recordAuditEvent('chat.connector.deactivated', 'chat_connector', req.params.id, user.id, null)
    res.status(204).end()
  } catch (err: any) {
    console.error('Failed to deactivate chat connector:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.get('/api/chat/connectors/:id/messages', requireAuth, async (req: Request, res: Response) => {
  try {
    const connector = await getChatConnectorById(req.params.id)
    if (!connector) return res.status(404).json({ error: 'Not found' })
    const limitRaw = typeof req.query.limit === 'string' ? Number.parseInt(req.query.limit, 10) : undefined
    const limit = Number.isFinite(limitRaw) && limitRaw! > 0 ? Math.min(limitRaw!, 200) : 50
    const messages = await listChatMessages(connector.id, limit)
    res.json({ connector, messages })
  } catch (err: any) {
    console.error('Failed to list chat messages:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/chat/connectors/:id/messages', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  try {
    const connector = await getChatConnectorById(req.params.id)
    if (!connector || !connector.isActive) {
      return res.status(404).json({ error: 'Connector not found' })
    }
    const parsed = ChatMessageSendSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
    const data = parsed.data
    const payload = { text: data.text, entityType: data.entityType, entityId: data.entityId }
    const delivery = await postChatWebhook(connector, payload)
  const status = delivery.status
    const message = await insertChatMessageRecord({
      connectorId: connector.id,
      entityType: data.entityType,
      entityId: data.entityId,
      direction: 'outbound',
      text: data.text,
      status,
      response: { detail: delivery.detail },
      createdByUserId: user.id
    })

    await insertActivityRecord({
      entityType: data.entityType,
      entityKey: data.entityId,
      text: data.text,
      type: 'communication',
      channel: 'chat',
      direction: 'outbound',
      metadata: {
        connectorId: connector.id,
        status,
        response: delivery.detail ?? null
      }
    }, user)

    await recordAuditEvent('chat.message.outbound', data.entityType, data.entityId, user.id, {
      connectorId: connector.id,
      status,
      detail: delivery.detail
    })

    res.status(201).json({ message, delivery })
  } catch (err: any) {
    console.error('Failed to send chat message:', err)
    if (res.headersSent) return
    res.status(500).json({ error: err?.message || 'Internal server error' })
  }
})

app.post('/api/chat/webhooks/:id', async (req: Request, res: Response) => {
  try {
    if (CHAT_WEBHOOK_TOKEN) {
      const token = (req.header('x-chat-token') || req.query.token || '').toString()
      if (token !== CHAT_WEBHOOK_TOKEN) {
        return res.status(403).json({ error: 'forbidden' })
      }
    }
    const connector = await getChatConnectorById(req.params.id)
    if (!connector || !connector.isActive) {
      return res.status(404).json({ error: 'Connector not found' })
    }
    const parsed = ChatMessageSendSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
    const data = parsed.data
    const message = await insertChatMessageRecord({
      connectorId: connector.id,
      entityType: data.entityType,
      entityId: data.entityId,
      direction: 'inbound',
      text: data.text,
      status: 'received',
      response: null,
      createdByUserId: null
    })

    await insertActivityRecord({
      entityType: data.entityType,
      entityKey: data.entityId,
      text: data.text,
      type: 'communication',
      channel: 'chat',
      direction: 'inbound',
      metadata: {
        connectorId: connector.id,
        messageId: message.id
      }
    }, systemUser)

    await recordAuditEvent('chat.message.inbound', data.entityType, data.entityId, null, {
      connectorId: connector.id,
      messageId: message.id
    })

    res.status(202).json({ ok: true })
  } catch (err: any) {
    console.error('Failed to process chat webhook:', err)
    if (res.headersSent) return
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.get('/api/voice-calls', requireAuth, async (req: Request, res: Response) => {
  try {
    const entityTypeRaw = typeof req.query.entityType === 'string' ? req.query.entityType : undefined
    const entityTypeParsed = entityTypeRaw ? ActivityEntityEnum.safeParse(entityTypeRaw) : null
    const entityType = entityTypeParsed?.success ? entityTypeParsed.data : undefined
    const entityId = typeof req.query.entityId === 'string' ? req.query.entityId : undefined
    const limitRaw = typeof req.query.limit === 'string' ? Number.parseInt(req.query.limit, 10) : undefined
    const limit = Number.isFinite(limitRaw) && limitRaw! > 0 ? Math.min(limitRaw!, 200) : 100
  const calls = await listVoiceCalls({ entityType, entityId, limit })
    res.json(calls)
  } catch (err: any) {
    console.error('Failed to list voice calls:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/voice-calls', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const parsed = VoiceCallCreateSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    const call = await insertVoiceCallRecord(parsed.data, user.id)
    await insertActivityRecord({
      entityType: parsed.data.entityType,
      entityKey: parsed.data.entityId,
      text: parsed.data.summary || parsed.data.subject || 'Voice call logged',
      type: 'communication',
      channel: 'voice',
      direction: 'outbound',
      metadata: {
        status: call.status,
        outcome: call.outcome ?? null,
        durationSeconds: call.durationSeconds ?? null
      }
    }, user)

    await recordAuditEvent('voice_call.logged', parsed.data.entityType, parsed.data.entityId, user.id, {
      voiceCallId: call.id,
      status: call.status
    })

    res.status(201).json(call)
  } catch (err: any) {
    console.error('Failed to create voice call:', err)
    res.status(500).json({ error: err?.message || 'Internal server error' })
  }
})

app.put('/api/voice-calls/:id', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const parsed = VoiceCallUpdateSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    const call = await updateVoiceCallRecord(req.params.id, parsed.data)
    if (!call) return res.status(404).json({ error: 'Not found' })
    await insertActivityRecord({
      entityType: call.entityType,
      entityKey: call.entityId,
      text: `Voice call updated: status ${call.status}`,
      type: 'system',
      channel: 'voice',
      direction: null,
      metadata: {
        outcome: call.outcome ?? null,
        durationSeconds: call.durationSeconds ?? null
      }
    }, user)

    await recordAuditEvent('voice_call.updated', call.entityType, call.entityId, user.id, {
      voiceCallId: call.id,
      status: call.status
    })

    res.json(call)
  } catch (err: any) {
    console.error('Failed to update voice call:', err)
    res.status(500).json({ error: err?.message || 'Internal server error' })
  }
})

app.get('/api/approvals/policies', requireAuth, async (req: Request, res: Response) => {
  try {
    const includeInactive = req.query.includeInactive === 'true'
    const policies = await listApprovalPolicies({ includeInactive })
    res.json(policies)
  } catch (err: any) {
    console.error('Failed to list approval policies:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/approvals/policies', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (!isManager(user)) return res.status(403).json({ error: 'forbidden' })
  const parsed = ApprovalPolicySchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    const policy = await insertApprovalPolicyRecord(parsed.data, user.id)
    await recordAuditEvent('approval.policy.created', 'approval_policy', policy?.id ?? null, user.id, { name: policy?.name })
    res.status(201).json(policy)
  } catch (err: any) {
    console.error('Failed to create approval policy:', err)
    res.status(500).json({ error: err?.message || 'Internal server error' })
  }
})

app.put('/api/approvals/policies/:id', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (!isManager(user)) return res.status(403).json({ error: 'forbidden' })
  const parsed = ApprovalPolicySchema.partial().safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    const policy = await updateApprovalPolicyRecord(req.params.id, parsed.data)
    if (!policy) return res.status(404).json({ error: 'Not found' })
    await recordAuditEvent('approval.policy.updated', 'approval_policy', policy.id, user.id, { name: policy.name })
    res.json(policy)
  } catch (err: any) {
    console.error('Failed to update approval policy:', err)
    res.status(500).json({ error: err?.message || 'Internal server error' })
  }
})

app.delete('/api/approvals/policies/:id', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (!isManager(user)) return res.status(403).json({ error: 'forbidden' })
  try {
    const success = await deactivateApprovalPolicy(req.params.id)
    if (!success) return res.status(404).json({ error: 'Not found' })
    await recordAuditEvent('approval.policy.deactivated', 'approval_policy', req.params.id, user.id, null)
    res.status(204).end()
  } catch (err: any) {
    console.error('Failed to deactivate approval policy:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.get('/api/approvals/requests', requireAuth, async (req: Request, res: Response) => {
  try {
    const entityTypeRaw = typeof req.query.entityType === 'string' ? req.query.entityType : undefined
    const entityTypeParsed = entityTypeRaw ? ActivityEntityEnum.safeParse(entityTypeRaw) : null
    const entityType = entityTypeParsed?.success ? entityTypeParsed.data : undefined
    const entityId = typeof req.query.entityId === 'string' ? req.query.entityId : undefined
    const status = typeof req.query.status === 'string' ? req.query.status : undefined
    const requests = await listApprovalRequests({ entityType, entityId, status })
    res.json(requests)
  } catch (err: any) {
    console.error('Failed to list approval requests:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/approvals/requests', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const parsed = ApprovalRequestSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    const policy = await getApprovalPolicyById(parsed.data.policyId)
    if (!policy || !policy.isActive) return res.status(404).json({ error: 'Policy not found' })
    const requestRecord = await insertApprovalRequestRecord(parsed.data, user.id)
    await insertActivityRecord({
      entityType: parsed.data.entityType,
      entityKey: parsed.data.entityId,
      text: `Approval requested for policy ${policy.name}`,
      type: 'system',
      channel: 'approval',
      direction: null,
      metadata: {
        policyId: policy.id,
        requestId: requestRecord?.id ?? null,
        context: parsed.data.context ?? null
      }
    }, user)
    await recordAuditEvent('approval.requested', parsed.data.entityType, parsed.data.entityId, user.id, {
      policyId: policy.id,
      requestId: requestRecord?.id ?? null,
      context: parsed.data.context ?? null
    })
    res.status(201).json(requestRecord)
  } catch (err: any) {
    console.error('Failed to submit approval request:', err)
    res.status(500).json({ error: err?.message || 'Internal server error' })
  }
})

app.get('/api/approvals/requests/:id', requireAuth, async (req: Request, res: Response) => {
  try {
    const requestRecord = await getApprovalRequestById(req.params.id)
    if (!requestRecord) return res.status(404).json({ error: 'Not found' })
    res.json(requestRecord)
  } catch (err: any) {
    console.error('Failed to fetch approval request:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/approvals/requests/:id/decision', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (!isManager(user)) return res.status(403).json({ error: 'forbidden' })
  const parsed = ApprovalDecisionSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    const existing = await getApprovalRequestById(req.params.id)
    if (!existing) return res.status(404).json({ error: 'Not found' })
    const notes = parsed.data.notes ?? null
    if (parsed.data.status === 'in_review') {
      if (existing.status !== 'pending') {
        return res.status(400).json({ error: 'Only pending requests can move to in-review' })
      }
      const updated = await markApprovalRequestInReview(req.params.id, notes, user.id)
      if (!updated) return res.status(500).json({ error: 'Failed to update approval request' })
      await insertActivityRecord({
        entityType: existing.entityType,
        entityKey: existing.entityId,
        text: `Approval review started by ${user.name || user.email}`,
        type: 'system',
        channel: 'approval',
        direction: null,
        metadata: {
          requestId: existing.id,
          notes,
          status: 'in_review'
        }
      }, user)
      res.json(updated)
      return
    }
    if (!['pending', 'in_review'].includes(existing.status)) {
      return res.status(400).json({ error: 'Request already decided' })
    }
    const updated = await updateApprovalRequestStatus(req.params.id, parsed.data.status, notes, user.id)
    if (!updated) return res.status(500).json({ error: 'Failed to update approval request' })
    await insertActivityRecord({
      entityType: existing.entityType,
      entityKey: existing.entityId,
      text: `Approval ${parsed.data.status} by ${user.name || user.email}`,
      type: 'system',
      channel: 'approval',
      direction: null,
      metadata: {
        requestId: existing.id,
        notes,
        previousStatus: existing.status,
        status: parsed.data.status
      }
    }, user)
    queueIntegrationEvent('approval.decision', {
      requestId: existing.id,
      entityType: existing.entityType,
      entityId: existing.entityId,
      status: parsed.data.status,
      decidedByUserId: user.id
    })
    res.json(updated)
  } catch (err: any) {
    console.error('Failed to decide approval request:', err)
    res.status(500).json({ error: err?.message || 'Internal server error' })
  }
})

// Task assignments
const TaskUpdateSchema = TaskSchema.partial()

app.get('/api/tasks', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  try {
    let sql = `SELECT t.*, e.employee_name, e.email AS employee_email
               FROM tasks t
               LEFT JOIN employees e ON t.employee_id = e.id`
    const params: unknown[] = []
    if (user.role === 'agent' || user.role === 'viewer') {
      sql += ' WHERE e.email = ?'
      params.push(user.email)
    }
    sql += ' ORDER BY COALESCE(t.due_date, "9999-12-31"), t.created_at DESC'
    const [rows] = await getDb().execute(sql, params)
    const records = rows as any[]
    const dependencyMap = await loadDependenciesForTasks(records.map(row => row.id as string))
    res.json(records.map(row => mapTaskRow(row, dependencyMap)))
  } catch (err: any) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/tasks', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (!isManager(user)) return res.status(403).json({ error: 'forbidden' })
  const raw = req.body ?? {}
  const dependenciesProvided = raw.dependencies !== undefined && raw.dependencies !== null && raw.dependencies !== ''
  const parsed = TaskSchema.safeParse({
    ...raw,
    team: normalizeString(raw.team),
    notes: raw.notes !== undefined ? normalizeString(raw.notes) : undefined,
    dependencies: dependenciesProvided ? sanitizeDependencyInput(raw.dependencies) : undefined
  })
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const data = parsed.data
  try {
    const employee = await findEmployeeRecord(data.employeeId)
    if (!employee) return res.status(400).json({ error: 'Employee not found' })
    const id = uuid()
    const status = data.status ?? 'Pending'
    const dueDate = normalizeDateInput(data.dueDate)
    const team = data.team ? data.team.trim() : null
    const remindBefore = data.remindBeforeMinutes ?? null
    const notes = data.notes ? data.notes.trim() : null
    const dependencies = sanitizeDependencyInput(data.dependencies ?? [], { exclude: id })
    await ensureDependenciesExist(dependencies)
    await getDb().execute(`INSERT INTO tasks (
      id, title, description, priority, status, due_date, employee_id, team, remind_before_minutes, notes, created_by_user_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
      id,
      data.title,
      data.description ?? null,
      data.priority,
      status,
      dueDate,
      employee.id,
      team,
      remindBefore,
      notes,
      user.id,
    ])
    await replaceTaskDependencies(id, dependencies)
    const [rows] = await getDb().execute(`
      SELECT t.*, e.employee_name, e.email AS employee_email
      FROM tasks t
      LEFT JOIN employees e ON t.employee_id = e.id
      WHERE t.id = ?
    `, [id])
    const dependencyMap = await loadDependenciesForTasks([id])
    const task = mapTaskRow((rows as any[])[0], dependencyMap)
    queueIntegrationEvent('task.created', {
      id: task.id,
      status: task.status,
      priority: task.priority,
      employeeId: task.employeeId
    })
    res.status(201).json(task)
  } catch (err: any) {
    res.status(400).json({ error: err.message })
  }
})

app.put('/api/tasks/:id', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const id = req.params.id
  const raw = req.body ?? {}
  const dependenciesProvided = raw.dependencies !== undefined && raw.dependencies !== null && raw.dependencies !== ''
  if (!isManager(user) && dependenciesProvided) {
    return res.status(403).json({ error: 'forbidden' })
  }
  const parsed = TaskUpdateSchema.safeParse({
    ...raw,
    team: raw.team !== undefined ? normalizeString(raw.team) : undefined,
    notes: raw.notes !== undefined ? normalizeString(raw.notes) : undefined,
    dependencies: dependenciesProvided ? sanitizeDependencyInput(raw.dependencies) : undefined
  })
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    const [existingRows] = await getDb().execute(`
      SELECT t.*, e.employee_name, e.email AS employee_email
      FROM tasks t
      LEFT JOIN employees e ON t.employee_id = e.id
      WHERE t.id = ?
    `, [id])
    const existing = (existingRows as any[])[0]
    if (!existing) return res.status(404).json({ error: 'Not found' })

    const isAssignee = existing.employee_email && existing.employee_email.toLowerCase() === user.email.toLowerCase()
    const manager = isManager(user)

    const data = parsed.data
    const setClauses: string[] = []
    const params: unknown[] = []

    if (manager) {
      if (data.title !== undefined) { setClauses.push('title = ?'); params.push(data.title) }
      if (data.description !== undefined) { setClauses.push('description = ?'); params.push(data.description ?? null) }
      if (data.priority !== undefined) { setClauses.push('priority = ?'); params.push(data.priority) }
      if (data.status !== undefined) { setClauses.push('status = ?'); params.push(data.status) }
      if (data.dueDate !== undefined) { setClauses.push('due_date = ?'); params.push(normalizeDateInput(data.dueDate)) }
      if (data.employeeId !== undefined) {
        const employee = await findEmployeeRecord(data.employeeId)
        if (!employee) return res.status(400).json({ error: 'Employee not found' })
        setClauses.push('employee_id = ?')
        params.push(employee.id)
      }
      if (data.team !== undefined) { setClauses.push('team = ?'); params.push(data.team ? data.team.trim() : null) }
      if (data.remindBeforeMinutes !== undefined) { setClauses.push('remind_before_minutes = ?'); params.push(data.remindBeforeMinutes ?? null) }
      if (data.notes !== undefined) { setClauses.push('notes = ?'); params.push(data.notes ? data.notes.trim() : null) }
    } else {
      if (!isAssignee) return res.status(403).json({ error: 'forbidden' })
      if (data.status === undefined) return res.status(400).json({ error: 'Status is required' })
      setClauses.push('status = ?')
      params.push(data.status)
    }

    if (setClauses.length === 0) return res.status(400).json({ error: 'No changes provided' })

    setClauses.push('updated_at = NOW()')
    await getDb().execute(`UPDATE tasks SET ${setClauses.join(', ')} WHERE id = ?`, [...params, id])

    if (manager && data.dependencies !== undefined) {
      const dependencies = sanitizeDependencyInput(data.dependencies, { exclude: id })
      await ensureDependenciesExist(dependencies)
      await replaceTaskDependencies(id, dependencies)
    }

    const [rows] = await getDb().execute(`
      SELECT t.*, e.employee_name, e.email AS employee_email
      FROM tasks t
      LEFT JOIN employees e ON t.employee_id = e.id
      WHERE t.id = ?
    `, [id])
    const dependencyMap = await loadDependenciesForTasks([id])
    const task = mapTaskRow((rows as any[])[0], dependencyMap)
    queueIntegrationEvent('task.updated', {
      id: task.id,
      status: task.status,
      priority: task.priority,
      employeeId: task.employeeId
    })
    res.json(task)
  } catch (err: any) {
    res.status(400).json({ error: err.message })
  }
})

app.delete('/api/tasks/:id', requireAuth, requireRole('admin','manager'), async (req: Request, res: Response) => {
  const id = req.params.id
  try {
    const [result] = await getDb().execute('DELETE FROM tasks WHERE id = ?', [id])
    if ((result as any).affectedRows === 0) return res.status(404).json({ error: 'Not found' })
    res.status(204).end()
  } catch (err: any) {
    res.status(500).json({ error: err.message })
  }
})

// Custom fields & layouts
app.get('/api/custom-fields', requireAuth, async (req: Request, res: Response) => {
  try {
    const raw = (req.query as any).entityType
    const entityTypeRaw = Array.isArray(raw) ? raw[0] : raw
    const entityType = typeof entityTypeRaw === 'string' && entityTypeRaw.trim().length > 0 ? entityTypeRaw.trim() : undefined
    const fields = await listCustomFields(entityType)
    res.json(fields)
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to load custom fields' })
  }
})

app.post('/api/custom-fields', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const parsed = CustomFieldCreateSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const data = parsed.data
  try {
    const id = uuid()
    await getDb().execute(`
      INSERT INTO custom_fields (id, entity_type, field_key, label, description, field_type, required, config, default_value, order_index, created_by_user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      id,
      data.entityType,
      data.fieldKey,
      data.label,
      data.description ?? null,
      data.fieldType,
      data.required ? 1 : 0,
      data.config ? JSON.stringify(data.config) : null,
      data.defaultValue !== undefined ? JSON.stringify(data.defaultValue) : null,
      data.orderIndex ?? 0,
      user?.id ?? null
    ])
    const [rows] = await getDb().execute('SELECT * FROM custom_fields WHERE id = ?', [id])
    const record = mapCustomFieldRow((rows as any[])[0])
    queueIntegrationEvent('custom_field.updated', { entityType: record.entityType, fieldKey: record.fieldKey, action: 'created' })
    res.status(201).json(record)
  } catch (err: any) {
    if (err?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Field key already exists for this entity type' })
    }
    res.status(500).json({ error: err.message || 'Failed to create custom field' })
  }
})

app.put('/api/custom-fields/:id', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const parsed = CustomFieldUpdateSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const id = req.params.id
  const data = parsed.data
  try {
    const setClauses: string[] = []
    const params: unknown[] = []
    if (data.entityType !== undefined) { setClauses.push('entity_type = ?'); params.push(data.entityType) }
    if (data.fieldKey !== undefined) { setClauses.push('field_key = ?'); params.push(data.fieldKey) }
    if (data.label !== undefined) { setClauses.push('label = ?'); params.push(data.label) }
    if (data.description !== undefined) { setClauses.push('description = ?'); params.push(data.description ?? null) }
    if (data.fieldType !== undefined) { setClauses.push('field_type = ?'); params.push(data.fieldType) }
    if (data.required !== undefined) { setClauses.push('required = ?'); params.push(data.required ? 1 : 0) }
    if (data.config !== undefined) { setClauses.push('config = ?'); params.push(data.config ? JSON.stringify(data.config) : null) }
    if (data.defaultValue !== undefined) { setClauses.push('default_value = ?'); params.push(data.defaultValue !== undefined ? JSON.stringify(data.defaultValue) : null) }
    if (data.orderIndex !== undefined) { setClauses.push('order_index = ?'); params.push(data.orderIndex) }
    if (!setClauses.length) return res.status(400).json({ error: 'No changes provided' })
    setClauses.push('updated_at = CURRENT_TIMESTAMP')
    const [result] = await getDb().execute(`UPDATE custom_fields SET ${setClauses.join(', ')} WHERE id = ?`, [...params, id])
    if ((result as any).affectedRows === 0) return res.status(404).json({ error: 'Not found' })
    const [rows] = await getDb().execute('SELECT * FROM custom_fields WHERE id = ?', [id])
    const record = mapCustomFieldRow((rows as any[])[0])
    queueIntegrationEvent('custom_field.updated', { entityType: record.entityType, fieldKey: record.fieldKey, action: 'updated' })
    res.json(record)
  } catch (err: any) {
    if (err?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Field key already exists for this entity type' })
    }
    res.status(500).json({ error: err.message || 'Failed to update custom field' })
  }
})

app.delete('/api/custom-fields/:id', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const id = req.params.id
  try {
    const [rows] = await getDb().execute('SELECT entity_type, field_key FROM custom_fields WHERE id = ?', [id])
    const record = (rows as any[])[0]
    if (!record) return res.status(404).json({ error: 'Not found' })
    await getDb().execute('DELETE FROM custom_fields WHERE id = ?', [id])
    queueIntegrationEvent('custom_field.updated', { entityType: record.entity_type, fieldKey: record.field_key, action: 'deleted' })
    res.status(204).end()
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to delete custom field' })
  }
})

app.get('/api/custom-field-values/:entityType/:entityId', requireAuth, async (req: Request, res: Response) => {
  const entityType = req.params.entityType?.trim()
  const entityId = req.params.entityId?.trim()
  if (!entityType || !entityId) return res.status(400).json({ error: 'entityType and entityId are required' })
  try {
    const data = await loadCustomFieldValues(entityType, entityId)
    res.json(data)
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to load custom field values' })
  }
})

app.put('/api/custom-field-values/:entityType/:entityId', requireAuth, async (req: Request, res: Response) => {
  const entityType = req.params.entityType?.trim()
  const entityId = req.params.entityId?.trim()
  if (!entityType || !entityId) return res.status(400).json({ error: 'entityType and entityId are required' })
  const parsed = CustomFieldValuesUpsertSchema.safeParse(req.body ?? {})
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    const { updatedKeys } = await saveCustomFieldValues(entityType, entityId, parsed.data.values)
    if (updatedKeys.length) {
      queueIntegrationEvent('custom_field.updated', { entityType, entityId, keys: updatedKeys })
    }
    const data = await loadCustomFieldValues(entityType, entityId)
    res.json({ ...data, updatedKeys })
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to upsert custom field values' })
  }
})

app.get('/api/entity-layouts/:entityType', requireAuth, async (req: Request, res: Response) => {
  const entityType = req.params.entityType?.trim()
  if (!entityType) return res.status(400).json({ error: 'entityType is required' })
  try {
    const layout = await getEntityLayoutConfig(entityType)
    const fields = await listCustomFields(entityType)
    res.json({ layout, fields })
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to load entity layout' })
  }
})

app.put('/api/entity-layouts/:entityType', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const entityType = req.params.entityType?.trim()
  if (!entityType) return res.status(400).json({ error: 'entityType is required' })
  const parsed = EntityLayoutSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    await saveEntityLayoutConfig(entityType, parsed.data)
    const fields = await listCustomFields(entityType)
    res.json({ layout: parsed.data, fields })
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to save entity layout' })
  }
})

app.get('/api/branding', requireAuth, async (_req: Request, res: Response) => {
  try {
    const branding = await getBrandingSettings()
    res.json(branding)
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to load branding settings' })
  }
})

app.put('/api/branding', requireRole('admin'), async (req: Request, res: Response) => {
  const parsed = BrandingUpdateSchema.safeParse(req.body ?? {})
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    await saveBrandingSettings(parsed.data)
    const branding = await getBrandingSettings()
    res.json(branding)
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to update branding settings' })
  }
})

app.get('/api/webhooks', requireRole('admin','manager'), async (_req: Request, res: Response) => {
  try {
    const [rows] = await getDb().execute('SELECT * FROM webhook_subscriptions ORDER BY created_at DESC')
    res.json((rows as any[]).map(mapWebhookRow))
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to load webhooks' })
  }
})

app.post('/api/webhooks', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const parsed = WebhookCreateSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const data = parsed.data
  try {
    const id = uuid()
    await getDb().execute(`
      INSERT INTO webhook_subscriptions (id, name, event_type, target_url, shared_secret, headers, is_active, created_by_user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      id,
      data.name,
      data.eventType,
      data.targetUrl,
      data.sharedSecret ?? null,
      data.headers ? JSON.stringify(data.headers) : null,
      data.isActive === false ? 0 : 1,
      user?.id ?? null
    ])
    const [rows] = await getDb().execute('SELECT * FROM webhook_subscriptions WHERE id = ?', [id])
    res.status(201).json(mapWebhookRow((rows as any[])[0]))
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to create webhook' })
  }
})

app.put('/api/webhooks/:id', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const id = req.params.id
  const parsed = WebhookUpdateSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const data = parsed.data
  try {
    const setClauses: string[] = []
    const params: unknown[] = []
    if (data.name !== undefined) { setClauses.push('name = ?'); params.push(data.name) }
    if (data.eventType !== undefined) { setClauses.push('event_type = ?'); params.push(data.eventType) }
    if (data.targetUrl !== undefined) { setClauses.push('target_url = ?'); params.push(data.targetUrl) }
    if (data.sharedSecret !== undefined) { setClauses.push('shared_secret = ?'); params.push(data.sharedSecret ?? null) }
    if (data.headers !== undefined) { setClauses.push('headers = ?'); params.push(data.headers ? JSON.stringify(data.headers) : null) }
    if (data.isActive !== undefined) { setClauses.push('is_active = ?'); params.push(data.isActive ? 1 : 0) }
    if (!setClauses.length) return res.status(400).json({ error: 'No changes provided' })
    setClauses.push('updated_at = CURRENT_TIMESTAMP')
    const [result] = await getDb().execute(`UPDATE webhook_subscriptions SET ${setClauses.join(', ')} WHERE id = ?`, [...params, id])
    if ((result as any).affectedRows === 0) return res.status(404).json({ error: 'Not found' })
    const [rows] = await getDb().execute('SELECT * FROM webhook_subscriptions WHERE id = ?', [id])
    res.json(mapWebhookRow((rows as any[])[0]))
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to update webhook' })
  }
})

app.delete('/api/webhooks/:id', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const id = req.params.id
  try {
    const [result] = await getDb().execute('DELETE FROM webhook_subscriptions WHERE id = ?', [id])
    if ((result as any).affectedRows === 0) return res.status(404).json({ error: 'Not found' })
    res.status(204).end()
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to delete webhook' })
  }
})

app.post('/api/webhooks/:id/test', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const id = req.params.id
  try {
    const [rows] = await getDb().execute('SELECT * FROM webhook_subscriptions WHERE id = ?', [id])
    const record = (rows as any[])[0]
    if (!record) return res.status(404).json({ error: 'Not found' })
    const bodyPayload = {
      event: record.event_type,
      payload: {
        message: 'Webhook test event',
        requestedAt: new Date().toISOString()
      },
      emittedAt: new Date().toISOString(),
      test: true
    }
    const body = JSON.stringify(bodyPayload)
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-CRM-Event': record.event_type,
      'X-CRM-Hook-Id': record.id
    }
    if (record.shared_secret) {
      const sig = computeWebhookSignature(record.shared_secret, body)
      if (sig) headers[WEBHOOK_SIGNATURE_HEADER] = sig
    }
    const extraHeaders = parseJsonSafe<Record<string, string> | undefined>(record.headers, undefined)
    if (extraHeaders) {
      Object.entries(extraHeaders).forEach(([key, value]) => {
        if (typeof value === 'string') headers[key] = value
      })
    }
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS)
    try {
      const response = await fetch(record.target_url, {
        method: 'POST',
        headers,
        body,
        signal: controller.signal
      })
      const text = await response.text().catch(() => '')
      res.json({ status: response.status, ok: response.ok, body: text.slice(0, 2000) })
    } finally {
      clearTimeout(timeout)
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to test webhook' })
  }
})

app.post('/api/assistant/ask', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const parsed = AssistantAskSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  try {
    const result = await generateAssistantResponse(parsed.data.prompt, user)
    res.json(result)
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Assistant request failed' })
  }
})

app.get('/api/assistant/timeline', requireAuth, async (req: Request, res: Response) => {
  try {
    const entityType = String(req.query.entityType || '').toLowerCase() as TimelineEntityType
    const entityId = String(req.query.entityId || '')
    if (!['tender', 'customer'].includes(entityType)) {
      return res.status(400).json({ error: 'entityType must be tender or customer' })
    }
    if (!entityId.trim()) {
      return res.status(400).json({ error: 'entityId required' })
    }
    const insights = await fetchTimelineInsights(entityType, entityId.trim())
    if (!insights) {
      return res.status(404).json({ error: 'Entity not found or no insights available' })
    }
    res.json(insights)
  } catch (err: any) {
    console.error('Timeline insights error:', err)
    res.status(500).json({ error: 'Failed to compute timeline insights' })
  }
})

app.get('/api/analytics/overview', requireAuth, async (_req: Request, res: Response) => {
  try {
    const overview = await fetchAnalyticsOverview()
    res.json(overview)
  } catch (err: any) {
    console.error('Analytics overview error:', err)
    res.status(500).json({ error: 'Failed to load analytics overview' })
  }
})

app.use('/api/enterprise', createEnterpriseRouter())

// Document workspace
app.get('/api/documents', requireAuth, async (req: Request, res: Response) => {
  try {
    const queryInput = {
      q: Array.isArray((req.query as any).q) ? (req.query as any).q[0] : (req.query as any).q,
      category: Array.isArray((req.query as any).category) ? (req.query as any).category[0] : (req.query as any).category,
      tag: Array.isArray((req.query as any).tag) ? (req.query as any).tag[0] : (req.query as any).tag
    }
    const parsed = DocumentQuerySchema.safeParse(queryInput)
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
    const { q, category, tag } = parsed.data
    const conditions: string[] = []
    const params: unknown[] = []

    if (category) {
      conditions.push('category = ?')
      params.push(category)
    }

    if (q) {
      const like = `%${q.toLowerCase()}%`
      conditions.push(`(
        LOWER(name) LIKE ? OR
        LOWER(owner) LIKE ? OR
        LOWER(related_to) LIKE ? OR
        LOWER(summary) LIKE ? OR
        LOWER(file_name) LIKE ? OR
        LOWER(link) LIKE ?
      )`)
      params.push(like, like, like, like, like, like)
    }

    if (tag) {
      conditions.push('JSON_SEARCH(tags, "one", ?) IS NOT NULL')
      params.push(tag)
    }

    let sql = `
      SELECT d.*, ra.entity_type, ra.entity_id
      FROM documents d
      LEFT JOIN record_attachments ra ON ra.document_id = d.id
    `
    if (conditions.length > 0) {
      sql += ' WHERE ' + conditions.map(c => `(${c})`).join(' AND ')
    }
    sql += ' ORDER BY d.uploaded_at DESC'
    const [rows] = await getDb().execute(sql, params)
    res.json(groupDocumentRows(rows as any[]))
  } catch (err: any) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/documents', requireAuth, documentUploadMiddleware, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (user.role === 'viewer') return res.status(403).json({ error: 'forbidden' })
  const uploadReq = req as Request & { file?: Express.Multer.File }
  const result = await createDocumentRecord(uploadReq, user)
  if (!result.ok) {
    return res.status(result.status).json(result.payload)
  }
  res.status(201).json(result.document)
})

app.delete('/api/documents/:id', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (user.role === 'viewer') return res.status(403).json({ error: 'forbidden' })
  const id = req.params.id
  try {
    const [rows] = await getDb().execute('SELECT storage_key FROM documents WHERE id = ?', [id])
    const record = (rows as any[])[0]
    if (!record) return res.status(404).json({ error: 'Not found' })
    await getDb().execute('DELETE FROM documents WHERE id = ?', [id])
    await removeStoredFile(record.storage_key as string | undefined)
    res.status(204).end()
  } catch (err: any) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/customers/:id/documents', requireAuth, async (req: Request, res: Response) => {
  try {
    const documents = await listEntityDocuments('customer', req.params.id)
    res.json(documents)
  } catch (err: any) {
    res.status(500).json({ error: err?.message || 'Failed to load customer documents' })
  }
})

app.post('/api/customers/:id/documents', requireAuth, documentUploadMiddleware, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (user.role === 'viewer') return res.status(403).json({ error: 'forbidden' })
  const uploadReq = req as Request & { file?: Express.Multer.File }
  const result = await createDocumentRecord(uploadReq, user, { entityType: 'customer', entityId: req.params.id })
  if (!result.ok) {
    return res.status(result.status).json(result.payload)
  }
  res.status(201).json(result.document)
})

app.delete('/api/customers/:id/documents/:documentId', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (user.role === 'viewer') return res.status(403).json({ error: 'forbidden' })
  try {
    await detachDocumentFromEntity('customer', req.params.id, req.params.documentId)
    res.status(204).end()
  } catch (err: any) {
    res.status(500).json({ error: err?.message || 'Failed to detach document' })
  }
})

app.get('/api/tenders/:id/documents', requireAuth, async (req: Request, res: Response) => {
  try {
    const documents = await listEntityDocuments('tender', req.params.id)
    res.json(documents)
  } catch (err: any) {
    res.status(500).json({ error: err?.message || 'Failed to load tender documents' })
  }
})

app.post('/api/tenders/:id/documents', requireAuth, documentUploadMiddleware, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (user.role === 'viewer') return res.status(403).json({ error: 'forbidden' })
  const uploadReq = req as Request & { file?: Express.Multer.File }
  const result = await createDocumentRecord(uploadReq, user, { entityType: 'tender', entityId: req.params.id })
  if (!result.ok) {
    return res.status(result.status).json(result.payload)
  }
  res.status(201).json(result.document)
})

app.delete('/api/tenders/:id/documents/:documentId', requireAuth, async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  if (user.role === 'viewer') return res.status(403).json({ error: 'forbidden' })
  try {
    await detachDocumentFromEntity('tender', req.params.id, req.params.documentId)
    res.status(204).end()
  } catch (err: any) {
    res.status(500).json({ error: err?.message || 'Failed to detach document' })
  }
})

app.get('/api/search', requireAuth, async (req: Request, res: Response) => {
  try {
    const rawQuery = Array.isArray((req.query as any).q) ? (req.query as any).q[0] : (req.query as any).q
    const q = typeof rawQuery === 'string' ? rawQuery.trim() : ''
    if (!q) {
      return res.status(400).json({ error: 'Query parameter q is required' })
    }

    const entityTypeRaw = Array.isArray((req.query as any).entityType) ? (req.query as any).entityType[0] : (req.query as any).entityType
    const entityIdRaw = Array.isArray((req.query as any).entityId) ? (req.query as any).entityId[0] : (req.query as any).entityId
    const entityType = typeof entityTypeRaw === 'string' ? entityTypeRaw.trim().toLowerCase() : undefined
    const entityId = typeof entityIdRaw === 'string' ? entityIdRaw.trim() : undefined

    if ((entityType && !entityId) || (!entityType && entityId)) {
      return res.status(400).json({ error: 'entityType and entityId must be provided together' })
    }
    if (entityType && !['customer', 'tender'].includes(entityType)) {
      return res.status(400).json({ error: 'Unsupported entityType' })
    }

    const likeTerm = `%${q.toLowerCase()}%`

    // Documents search
    const documentParams: unknown[] = [likeTerm, likeTerm, likeTerm]
    let documentSql = `
      SELECT d.id, d.name, d.summary, d.text_content, d.updated_at, d.category, d.owner, d.file_name, d.storage_key,
             ra.entity_type, ra.entity_id
      FROM documents d
      LEFT JOIN record_attachments ra ON ra.document_id = d.id
      WHERE (
        LOWER(d.name) LIKE ? OR
        LOWER(COALESCE(d.summary, '')) LIKE ? OR
        LOWER(COALESCE(d.text_content, '')) LIKE ?
      )
    `
    if (entityType && entityId) {
      documentSql += ' AND ra.entity_type = ? AND ra.entity_id = ?'
      documentParams.push(entityType, entityId)
    }
    documentSql += ' ORDER BY d.updated_at DESC LIMIT ?'
    documentParams.push(SEARCH_RESULT_LIMIT)
    const [documentRowsRaw] = await getDb().execute(documentSql, documentParams)
    const documentRows = documentRowsRaw as any[]
    const documentAggregated = new Map<string, { row: any; entities: DocumentEntityLink[] }>()
    for (const row of documentRows) {
      if (!documentAggregated.has(row.id)) {
        documentAggregated.set(row.id, { row, entities: [] })
      }
      const bucket = documentAggregated.get(row.id)!
      if (row.entity_type && row.entity_id) {
        bucket.entities.push({ entityType: row.entity_type, entityId: row.entity_id })
      }
    }
    const documentResults = Array.from(documentAggregated.values()).map(({ row, entities }) => {
      const contentSource = row.text_content || row.summary || row.name || ''
      const snippet = buildSnippet(contentSource, q)
      const uniqueEntities: DocumentEntityLink[] = []
      const seen = new Set<string>()
      for (const link of entities) {
        const key = `${link.entityType}:${link.entityId}`
        if (seen.has(key)) continue
        seen.add(key)
        uniqueEntities.push(link)
      }
      return {
        id: row.id,
        type: 'document' as const,
        title: row.name,
        snippet,
        entityType: uniqueEntities[0]?.entityType ?? null,
        entityId: uniqueEntities[0]?.entityId ?? null,
        updatedAt: row.updated_at,
        metadata: {
          category: row.category,
          owner: row.owner,
          fileName: row.file_name,
          downloadUrl: row.storage_key ? `/api/documents/${row.id}/download` : null,
          entities: uniqueEntities,
          summary: row.summary ?? null,
          textSnippet: snippet
        }
      }
    })

    // Activities (notes/comments)
    const activityParams: unknown[] = [likeTerm]
    let activitySql = `
      SELECT id, entity_type, entity_key, text, created_at
      FROM activities
      WHERE LOWER(text) LIKE ?
    `
    if (entityType && entityId) {
      activitySql += ' AND entity_type = ? AND entity_key = ?'
      activityParams.push(entityType, entityId)
    }
    activitySql += ' ORDER BY created_at DESC LIMIT ?'
    activityParams.push(SEARCH_RESULT_LIMIT)
    const [activityRows] = await getDb().execute(activitySql, activityParams)
    const activityResults = (activityRows as any[]).map(row => ({
      id: row.id,
      type: 'activity' as const,
      title: `Comment on ${row.entity_type} ${row.entity_key}`,
      snippet: buildSnippet(row.text || '', q),
      entityType: row.entity_type,
      entityId: row.entity_key,
      updatedAt: row.created_at,
      metadata: {}
    }))

    // Tender fields (acts like email/note log)
    const tenderParams: unknown[] = [likeTerm, likeTerm, likeTerm]
    let tenderSql = `
      SELECT id, serial_token, customer_id, lead_title, lead_description, status, updated_at
      FROM tenders
      WHERE (
        LOWER(COALESCE(lead_title, '')) LIKE ? OR
        LOWER(COALESCE(lead_description, '')) LIKE ? OR
        LOWER(serial_token) LIKE ?
      )
    `
    if (entityType === 'customer' && entityId) {
      tenderSql += ' AND customer_id = ?'
      tenderParams.push(entityId)
    }
    if (entityType === 'tender' && entityId) {
      tenderSql += ' AND id = ?'
      tenderParams.push(entityId)
    }
    tenderSql += ' ORDER BY updated_at DESC LIMIT ?'
    tenderParams.push(SEARCH_RESULT_LIMIT)
    const [tenderRows] = await getDb().execute(tenderSql, tenderParams)
    const tenderResults = (tenderRows as any[]).map(row => ({
      id: row.id,
      type: 'tender' as const,
      title: row.lead_title || `Tender ${row.serial_token}`,
      snippet: buildSnippet(row.lead_description || row.serial_token || '', q),
      entityType: 'tender',
      entityId: row.id,
      updatedAt: row.updated_at,
      metadata: {
        status: row.status,
        customerId: row.customer_id,
        serialToken: row.serial_token
      }
    }))

    const results = [...documentResults, ...activityResults, ...tenderResults]
      .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime())
      .slice(0, SEARCH_RESULT_LIMIT)

    res.json({ query: q, results })
  } catch (err: any) {
    res.status(500).json({ error: err?.message || 'Search failed' })
  }
})

app.get('/api/customers/:id/intelligence', requireAuth, async (req: Request, res: Response) => {
  try {
    const customerId = req.params.id
    const [customerRows] = await getDb().execute('SELECT * FROM customers WHERE id = ?', [customerId])
    const customer = (customerRows as any[])[0]
    if (!customer) {
      return res.status(404).json({ error: 'Customer not found' })
    }

    const [tenderStatsRows] = await getDb().execute(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status IN ('Won', 'Closed', 'Completed') THEN 1 ELSE 0 END) AS succeeded,
        SUM(CASE WHEN status IN ('Lost', 'Cancelled') THEN 1 ELSE 0 END) AS lost,
        SUM(CASE WHEN status IS NULL OR status NOT IN ('Won', 'Closed', 'Completed', 'Lost', 'Cancelled') THEN 1 ELSE 0 END) AS active,
        SUM(CASE WHEN estimated_value REGEXP '^[0-9]+(\\.[0-9]+)?$' THEN CAST(estimated_value AS DECIMAL(18,2)) ELSE 0 END) AS pipeline_value,
        SUM(CASE WHEN status IN ('Won', 'Completed') AND estimated_value REGEXP '^[0-9]+(\\.[0-9]+)?$' THEN CAST(estimated_value AS DECIMAL(18,2)) ELSE 0 END) AS won_value,
        MAX(updated_at) AS last_updated
      FROM tenders
      WHERE customer_id = ?
    `, [customerId])
    const tenderStats = (tenderStatsRows as any[])[0] ?? {}

    const [recentTenderRows] = await getDb().execute(`
      SELECT id, serial_token, lead_title, status, estimated_value, follow_up_date, updated_at
      FROM tenders
      WHERE customer_id = ?
      ORDER BY updated_at DESC
      LIMIT 5
    `, [customerId])

    const [upcomingFollowUpsRows] = await getDb().execute(`
      SELECT id, lead_title, follow_up_date, status
      FROM tenders
      WHERE customer_id = ? AND follow_up_date IS NOT NULL AND follow_up_date >= CURDATE()
      ORDER BY follow_up_date ASC
      LIMIT 5
    `, [customerId])

    const [documentStatsRows] = await getDb().execute(`
      SELECT COUNT(*) AS total, MAX(d.updated_at) AS last_updated
      FROM record_attachments ra
      JOIN documents d ON d.id = ra.document_id
      WHERE ra.entity_type = 'customer' AND ra.entity_id = ?
    `, [customerId])
    const documentStats = (documentStatsRows as any[])[0] ?? {}
    const recentDocumentsFull = await listEntityDocuments('customer', customerId)
    const recentDocuments = recentDocumentsFull.slice(0, 3).map(doc => ({
      id: doc.id,
      name: doc.name,
      category: doc.category,
      updatedAt: doc.updatedAt,
      summary: doc.summary,
      tags: doc.tags,
      fileName: doc.fileName
    }))

    const [activityStatsRows] = await getDb().execute(`
      SELECT COUNT(*) AS total, MAX(created_at) AS last_created
      FROM activities
      WHERE entity_type = 'customer' AND entity_key = ?
    `, [customerId])
    const activityStats = (activityStatsRows as any[])[0] ?? {}

    const [recentActivitiesRows] = await getDb().execute(`
      SELECT id, type, text, created_at
      FROM activities
      WHERE entity_type = 'customer' AND entity_key = ?
      ORDER BY created_at DESC
      LIMIT 5
    `, [customerId])

    const parseDate = (value: any): Date | null => {
      if (!value) return null
      const date = new Date(value)
      if (Number.isNaN(date.getTime())) return null
      return date
    }

    const lastTenderUpdate = parseDate(tenderStats.last_updated)
    const lastDocumentUpdate = parseDate(documentStats.last_updated)
    const lastActivityDate = parseDate(activityStats.last_created)
    const lastInteraction = [lastTenderUpdate, lastDocumentUpdate, lastActivityDate]
      .filter((d): d is Date => Boolean(d))
      .sort((a, b) => b.getTime() - a.getTime())[0] ?? null

    const daysSinceInteraction = lastInteraction ? Math.floor((Date.now() - lastInteraction.getTime()) / (1000 * 60 * 60 * 24)) : null

    const totalTenders = Number(tenderStats.total ?? 0)
    const activeTenders = Number(tenderStats.active ?? 0)
    const documentCount = Number(documentStats.total ?? 0)
    const activityCount = Number(activityStats.total ?? 0)
    const engagementScore = computeEngagementScore({
      totalTenders,
      activeTenders,
      documentCount,
      activityCount,
      lastInteractionAt: lastInteraction ? lastInteraction.toISOString() : undefined
    })
    const engagementStage = classifyEngagementStage(engagementScore)
    const engagementTrend = await recordEngagementSnapshot(customerId, engagementScore, engagementStage, {
      totalTenders,
      activeTenders,
      documentCount,
      activityCount,
      daysSinceInteraction
    })

    const manualSegments = await fetchCustomerSegments(customerId)
    const communicationsRecent = await fetchCustomerCommunications(customerId, 12)

    const [communicationStatsRows] = await getDb().execute(`
      SELECT COUNT(*) AS total, MAX(COALESCE(occurred_at, created_at)) AS last_interaction
      FROM activities
      WHERE entity_type = 'customer' AND entity_key = ? AND type = 'communication'
    `, [customerId])
    const communicationStats = (communicationStatsRows as any[])[0] ?? {}

    const [communicationChannelRows] = await getDb().execute(`
      SELECT channel, COUNT(*) AS total
      FROM activities
      WHERE entity_type = 'customer' AND entity_key = ? AND type = 'communication'
      GROUP BY channel
    `, [customerId])
    const communicationByChannel = (communicationChannelRows as any[]).reduce<Record<string, number>>((acc, row) => {
      const channel = row.channel || 'Unspecified'
      acc[channel] = Number(row.total ?? 0)
      return acc
    }, {})

    const [sentimentRows] = await getDb().execute(`
      SELECT id, text, sentiment_label, sentiment_score, type, channel, occurred_at, created_at
      FROM activities
      WHERE entity_type = 'customer' AND entity_key = ? AND sentiment_score IS NOT NULL
      ORDER BY COALESCE(occurred_at, created_at) DESC
      LIMIT 30
    `, [customerId])

    const sentimentRecords = (sentimentRows as any[]).map(row => {
      const occurredAt = row.occurred_at ? new Date(row.occurred_at).toISOString() : (row.created_at ? new Date(row.created_at).toISOString() : null)
      const score = row.sentiment_score === null || row.sentiment_score === undefined ? 0 : Number(row.sentiment_score)
      const label: SentimentLabel = row.sentiment_label
        ? row.sentiment_label
        : score > 0.1 ? 'positive' : score < -0.1 ? 'negative' : 'neutral'
      return {
        id: row.id,
        text: row.text,
        label,
        score,
        channel: row.channel ?? null,
        source: row.type,
        occurredAt
      }
    })

    const sentimentSampleSize = sentimentRecords.length
    const averageSentiment = sentimentSampleSize
      ? sentimentRecords.reduce((sum, item) => sum + item.score, 0) / sentimentSampleSize
      : 0
    const sentimentLabel: SentimentLabel = averageSentiment > 0.1 ? 'positive' : averageSentiment < -0.1 ? 'negative' : 'neutral'
    const sentimentLast = sentimentRecords[0]
    const sentimentSummary = {
      averageScore: Number(averageSentiment.toFixed(3)),
      label: sentimentLabel,
      lastUpdated: sentimentLast?.occurredAt ?? null,
      sampleSize: sentimentSampleSize,
      recent: sentimentRecords.slice(0, 5)
    }

    const nowIso = new Date().toISOString()
    const autoSegments: CustomerSegmentRecord[] = []
    const pushAutoSegment = (key: string, segment: string, description: string, color: string) => {
      autoSegments.push({
        id: `auto-${customerId}-${key}`,
        customerId,
        segment,
        description,
        color,
        source: 'system',
        createdByUserId: null,
        createdAt: nowIso
      })
    }

    if (engagementStage === 'Champion') {
      pushAutoSegment('champion', 'Champion', 'High engagement across all touchpoints — nurture advocacy opportunities.', '#16a34a')
    } else if (engagementStage === 'Healthy') {
      pushAutoSegment('healthy', 'Healthy', 'Solid relationship momentum — maintain regular value updates.', '#0ea5e9')
    } else if (engagementStage === 'At Risk') {
      pushAutoSegment('atrisk', 'At Risk', 'Engagement is softening — re-establish contact and reinforce value.', '#f97316')
    } else {
      pushAutoSegment('dormant', 'Dormant', 'Minimal activity observed — plan a reactivation campaign.', '#dc2626')
    }

    if (sentimentSummary.label === 'positive' && sentimentSummary.averageScore > 0.25) {
      pushAutoSegment('promoter', 'Promoter', 'Recent communications trend positive — request testimonials or referrals.', '#22c55e')
    }
    if (sentimentSummary.label === 'negative') {
      pushAutoSegment('needs-attention', 'Needs Attention', 'Sentiment trending negative — craft a recovery plan.', '#f87171')
    }
    if ((daysSinceInteraction ?? 0) > 30) {
      pushAutoSegment('stalled', 'Stalled Pipeline', 'No meaningful touchpoints in over a month — prioritize outreach.', '#f59e0b')
    }

    const segmentsMap = new Map<string, CustomerSegmentRecord>()
    manualSegments.forEach(seg => segmentsMap.set(seg.segment.toLowerCase(), seg))
    autoSegments.forEach(seg => {
      const key = seg.segment.toLowerCase()
      if (!segmentsMap.has(key)) {
        segmentsMap.set(key, seg)
      }
    })
    const segments = Array.from(segmentsMap.values())

    const recommendations: string[] = []
    if (daysSinceInteraction !== null && daysSinceInteraction > 14) {
      recommendations.push(`No recent touchpoints in ${daysSinceInteraction} days — schedule a follow-up call.`)
    }
    if (totalTenders === 0) {
      recommendations.push('No tenders linked to this customer — consider qualifying a new opportunity.')
    }
    if (activeTenders > 0 && Number(tenderStats.pipeline_value ?? 0) === 0) {
      recommendations.push('Update tender value estimates to quantify pipeline impact.')
    }
    if (documentCount === 0) {
      recommendations.push('Attach discovery notes or proposals to keep the customer workspace complete.')
    }
    if (activityCount === 0) {
      recommendations.push('Log the next customer conversation to build an interaction history.')
    }
    if (sentimentSummary.label === 'negative' && sentimentSummary.sampleSize > 0) {
      recommendations.push('Sentiment is trending negative — plan a corrective conversation with a trusted stakeholder.')
    }
    if (Number(communicationStats.total ?? 0) === 0) {
      recommendations.push('No communications recorded yet — capture the next call or email to build a timeline.')
    }
    if (segments.some(seg => seg.segment.toLowerCase() === 'champion')) {
      recommendations.push('Consider a value-add touch or referral request — this customer is highly engaged.')
    }
    if (segments.some(seg => seg.segment.toLowerCase().includes('dormant'))) {
      recommendations.push('Customer appears dormant — coordinate a reactivation play with marketing.')
    }

    const uniqueRecommendations = Array.from(new Set(recommendations))

    const customerName = [customer.first_name, customer.last_name].filter(Boolean).join(' ') || customer.organization_name

    res.json({
      customer: {
        id: customer.id,
        name: customerName,
        organization: customer.organization_name,
        email: customer.email,
        mobile: customer.mobile
      },
      engagementScore,
      engagement: {
        score: engagementScore,
        stage: engagementStage,
        trend: engagementTrend,
        lastComputedAt: engagementTrend[0]?.computedAt ?? new Date().toISOString()
      },
      sentiment: sentimentSummary,
      segments,
      communications: {
        summary: {
          total: Number(communicationStats.total ?? 0),
          lastInteractionAt: communicationStats.last_interaction ? new Date(communicationStats.last_interaction).toISOString() : null,
          byChannel: communicationByChannel
        },
        recent: communicationsRecent
      },
      metrics: {
        tenders: {
          total: totalTenders,
          active: activeTenders,
          succeeded: Number(tenderStats.succeeded ?? 0),
          lost: Number(tenderStats.lost ?? 0),
          pipelineValue: Number(tenderStats.pipeline_value ?? 0),
          wonValue: Number(tenderStats.won_value ?? 0),
          lastUpdated: lastTenderUpdate ? lastTenderUpdate.toISOString() : null
        },
        documents: {
          total: documentCount,
          lastUpdated: lastDocumentUpdate ? lastDocumentUpdate.toISOString() : null
        },
        activities: {
          total: activityCount,
          lastCreated: lastActivityDate ? lastActivityDate.toISOString() : null
        }
      },
      recent: {
        tenders: (recentTenderRows as any[]).map(row => ({
          id: row.id,
          title: row.lead_title || `Tender ${row.serial_token}`,
          status: row.status,
          estimatedValue: row.estimated_value,
          followUpDate: row.follow_up_date,
          updatedAt: row.updated_at
        })),
        documents: recentDocuments,
        activities: (recentActivitiesRows as any[]).map(row => ({
          id: row.id,
          type: row.type,
          text: row.text,
          createdAt: row.created_at
        })),
        upcomingFollowUps: (upcomingFollowUpsRows as any[]).map(row => ({
          id: row.id,
          title: row.lead_title,
          followUpDate: row.follow_up_date,
          status: row.status
        }))
      },
      recommendations: uniqueRecommendations
    })
  } catch (err: any) {
    console.error('Failed to build customer intelligence snapshot:', err)
    if (res.headersSent) return
    res.status(500).json({ error: err?.message || 'Failed to load customer intelligence' })
  }
})

app.get('/api/documents/:id/download', requireAuth, async (req: Request, res: Response) => {
  const id = req.params.id
  try {
    const [rows] = await getDb().execute('SELECT file_name, storage_key FROM documents WHERE id = ?', [id])
    const record = (rows as any[])[0]
    if (!record) return res.status(404).json({ error: 'Not found' })
    if (!record.storage_key) return res.status(404).json({ error: 'No file available for this document' })
    const filePath = path.join(DOCUMENT_UPLOAD_DIR, record.storage_key)
    try {
      await fs.access(filePath)
    } catch {
      return res.status(404).json({ error: 'File not found' })
    }
    res.download(filePath, record.file_name || 'document')
  } catch (err: any) {
    res.status(500).json({ error: err.message })
  }
})

// Employees CRUD
const EmployeeSchema = z.object({
  employeeId: z.string(),
  employeeName: z.string(),
  designation: z.string().optional(),
  email: z.string().email(),
  mobile: z.string(),
  department: z.string().optional(),
})

app.get('/api/employees', requireAuth, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user as AuthUser
    if (!isManager(user)) {
      return res.status(403).json({ error: 'forbidden' })
    }
    await syncUsersIntoEmployees()
    const [rows] = await getDb().execute('SELECT * FROM employees ORDER BY created_at DESC')
    const mapped = (rows as any[]).map((r: any) => ({
      id: r.id,
      employeeId: r.employee_id,
      employeeName: r.employee_name,
      designation: r.designation,
      email: r.email,
      mobile: r.mobile,
      department: r.department,
      createdAt: r.created_at,
    }))
    res.json(mapped)
  } catch (err: any) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/employees', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const parse = EmployeeSchema.safeParse(req.body)
  if (!parse.success) return res.status(400).json({ error: parse.error.flatten() })
  const now = new Date().toISOString()
  const id = uuid()
  const e = parse.data
  try {
    await getDb().execute(`INSERT INTO employees (
      id, employee_id, employee_name, designation, email, mobile, department, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, 
    [id, e.employeeId, e.employeeName, e.designation, e.email, e.mobile, e.department, now])
    res.status(201).json({ id, ...e, createdAt: now })
  } catch (err: any) {
    res.status(400).json({ error: err.message })
  }
})

app.put('/api/employees/:id', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const parse = EmployeeSchema.partial().safeParse(req.body)
  if (!parse.success) return res.status(400).json({ error: parse.error.flatten() })
  const id = req.params.id
  const e = parse.data
  try {
    const [result] = await getDb().execute(`UPDATE employees SET
      employee_id=?, employee_name=?, designation=?,
      email=?, mobile=?, department=?
      WHERE id=?`, 
      [e.employeeId, e.employeeName, e.designation, e.email, e.mobile, e.department, id])
    if ((result as any).affectedRows === 0) return res.status(404).json({ error: 'Not found' })
    res.json({ id, ...e })
  } catch (err: any) {
    res.status(400).json({ error: err.message })
  }
})

app.delete('/api/employees/:id', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const id = req.params.id
  try {
    const [result] = await getDb().execute('DELETE FROM employees WHERE id = ?', [id])
    if ((result as any).affectedRows === 0) return res.status(404).json({ error: 'Not found' })
    res.status(204).end()
  } catch (err: any) {
    res.status(500).json({ error: err.message })
  }
})

// Customers CRUD
const CustomerSchema = z.object({
  firstName: z.string(),
  lastName: z.string(),
  organizationName: z.string(),
  address: z.string(),
  city: z.string(),
  pinCode: z.string(),
  state: z.string(),
  country: z.string(),
  email: z.string().email(),
  mobile: z.string(),
  contactPerson: z.string().optional().default(''),
  contactPersonName: z.string().optional().default(''),
  contactPersonEmail: z.string().email().optional().default(''),
  businessType: z.string().optional().default(''),
})

app.get('/api/customers', requireAuth, async (req: Request, res: Response) => {
  try {
    const searchRaw = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase() : ''
    const limitRaw = Number.parseInt(typeof req.query.limit === 'string' ? req.query.limit : '', 10)
    const offsetRaw = Number.parseInt(typeof req.query.offset === 'string' ? req.query.offset : '', 10)
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 200) : 50
    const offset = Number.isFinite(offsetRaw) && offsetRaw >= 0 ? offsetRaw : 0

    const conditions: string[] = []
    const params: unknown[] = []

    if (searchRaw) {
      const like = `%${searchRaw}%`
      conditions.push(`(
        LOWER(first_name) LIKE ? OR
        LOWER(last_name) LIKE ? OR
        LOWER(organization_name) LIKE ? OR
        LOWER(email) LIKE ? OR
        LOWER(mobile) LIKE ?
      )`)
      params.push(like, like, like, like, like)
    }

    let sql = 'SELECT * FROM customers'
    if (conditions.length > 0) {
      sql += ' WHERE ' + conditions.join(' AND ')
    }
    sql += ` ORDER BY created_at DESC LIMIT ${limit + 1} OFFSET ${offset}`

    const [rows] = await getDb().execute(sql, params)
    const list = rows as any[]
    const hasMore = list.length > limit
    const trimmed = hasMore ? list.slice(0, limit) : list
    const mapped = trimmed.map((r: any) => ({
      id: r.id,
      firstName: r.first_name,
      lastName: r.last_name,
      organizationName: r.organization_name,
      address: r.address,
      city: r.city,
      pinCode: r.pin_code,
      state: r.state,
      country: r.country,
      email: r.email,
      mobile: r.mobile,
      contactPerson: r.contact_person,
      contactPersonName: r.contact_person_name,
      contactPersonEmail: r.contact_person_email,
      businessType: r.business_type,
      createdAt: r.created_at,
    }))
    const nextCursor = hasMore ? String(offset + mapped.length) : null
    res.json({ data: mapped, nextCursor })
  } catch (err: any) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/customers', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const parse = CustomerSchema.safeParse(req.body)
  if (!parse.success) return res.status(400).json({ error: parse.error.flatten() })

  const { iso: createdAtIso, sql: createdAtSql } = createTimestamps()
  const id = uuid()
  const c = parse.data

  const normalized = {
    firstName: c.firstName.trim(),
    lastName: c.lastName.trim(),
    organizationName: c.organizationName.trim(),
    address: c.address.trim(),
    city: c.city.trim(),
    pinCode: c.pinCode.trim(),
    state: c.state.trim(),
    country: c.country.trim(),
    email: c.email.trim(),
    mobile: c.mobile.trim(),
    contactPerson: normalizeOptionalString(c.contactPerson),
    contactPersonName: normalizeOptionalString(c.contactPersonName),
    contactPersonEmail: normalizeOptionalString(c.contactPersonEmail),
    businessType: normalizeOptionalString(c.businessType)
  }

  const requiredFields: Array<[keyof typeof normalized, string]> = [
    ['firstName', 'First name'],
    ['lastName', 'Last name'],
    ['organizationName', 'Organisation name'],
    ['address', 'Address'],
    ['city', 'City'],
    ['pinCode', 'PIN code'],
    ['state', 'State'],
    ['country', 'Country'],
    ['email', 'Email'],
    ['mobile', 'Mobile']
  ]

  for (const [key, label] of requiredFields) {
    const value = normalized[key]
    if (typeof value !== 'string' || value.length === 0) {
      return res.status(400).json({ error: `${label} is required` })
    }
  }

  normalized.email = normalized.email.toLowerCase()
  if (normalized.contactPersonEmail) {
    normalized.contactPersonEmail = normalized.contactPersonEmail.toLowerCase()
  }

  try {
    await getDb().execute(`INSERT INTO customers (
      id, first_name, last_name, organization_name, address, city, pin_code, state, country,
      email, mobile, contact_person, contact_person_name, contact_person_email, business_type, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
      id,
      normalized.firstName,
      normalized.lastName,
      normalized.organizationName,
      normalized.address,
      normalized.city,
      normalized.pinCode,
      normalized.state,
      normalized.country,
      normalized.email,
      normalized.mobile,
      normalized.contactPerson,
      normalized.contactPersonName,
      normalized.contactPersonEmail,
      normalized.businessType,
      createdAtSql
    ])

    res.status(201).json({ id, ...normalized, createdAt: createdAtIso })
  } catch (err: any) {
    res.status(400).json({ error: err.message })
  }
})

app.put('/api/customers/:id', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const parse = CustomerSchema.partial().safeParse(req.body)
  if (!parse.success) return res.status(400).json({ error: parse.error.flatten() })
  const id = req.params.id
  const c = parse.data
  try {
    const [result] = await getDb().execute(`UPDATE customers SET
      first_name=?, last_name=?, organization_name=?, address=?, city=?,
      pin_code=?, state=?, country=?, email=?, mobile=?, contact_person=?,
      contact_person_name=?, contact_person_email=?, business_type=?
      WHERE id=?`, 
      [c.firstName, c.lastName, c.organizationName, c.address, c.city, c.pinCode, 
       c.state, c.country, c.email, c.mobile, c.contactPerson, c.contactPersonName, 
       c.contactPersonEmail, c.businessType, id])
    if ((result as any).affectedRows === 0) return res.status(404).json({ error: 'Not found' })
    res.json({ id, ...c })
  } catch (err: any) {
    res.status(400).json({ error: err.message })
  }
})

app.get('/api/customers/:id/segments', requireAuth, async (req: Request, res: Response) => {
  try {
    const customerId = req.params.id
    const segments = await fetchCustomerSegments(customerId)
    res.json(segments)
  } catch (err: any) {
    console.error('Failed to load segments:', err)
    res.status(500).json({ error: 'Failed to load segments' })
  }
})

app.post('/api/customers/:id/segments', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const user = (req as any).user as AuthUser
  const parsed = SegmentCreateSchema.safeParse(req.body)
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() })
  }

  try {
    const customerId = req.params.id
    const id = uuid()
    const createdAtIso = new Date().toISOString()
    const createdAtDb = createdAtIso.slice(0, 19).replace('T', ' ')
    await getDb().execute(
      'INSERT INTO customer_segments (id, customer_id, segment, description, color, source, created_by_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [id, customerId, parsed.data.segment, parsed.data.description ?? null, parsed.data.color ?? null, 'manual', user.id ?? null, createdAtDb]
    )
    res.status(201).json({
      id,
      customerId,
      segment: parsed.data.segment,
      description: parsed.data.description ?? null,
      color: parsed.data.color ?? null,
      source: 'manual',
      createdByUserId: user.id ?? null,
      createdAt: createdAtIso
    })
  } catch (err: any) {
    if (err?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Segment already assigned to customer' })
    }
    console.error('Failed to create segment:', err)
    res.status(500).json({ error: 'Failed to create segment' })
  }
})

app.delete('/api/customers/:id/segments/:segmentId', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const customerId = req.params.id
  const segmentId = req.params.segmentId
  try {
    const [result] = await getDb().execute('DELETE FROM customer_segments WHERE id = ? AND customer_id = ?', [segmentId, customerId])
    if ((result as any).affectedRows === 0) {
      return res.status(404).json({ error: 'Segment not found' })
    }
    res.status(204).end()
  } catch (err: any) {
    console.error('Failed to delete segment:', err)
    res.status(500).json({ error: 'Failed to delete segment' })
  }
})

app.delete('/api/customers/:id', requireRole('admin','manager'), async (req: Request, res: Response) => {
  const id = req.params.id
  try {
    const [result] = await getDb().execute('DELETE FROM customers WHERE id = ?', [id])
    if ((result as any).affectedRows === 0) return res.status(404).json({ error: 'Not found' })
    res.status(204).end()
  } catch (err: any) {
    res.status(500).json({ error: err.message })
  }
})

// User administration
const UpdateUserRoleSchema = z.object({
  role: z.enum(['admin', 'manager', 'agent', 'viewer'])
})

app.get('/api/users', requireRole('admin'), async (_req: Request, res: Response) => {
  try {
    const [rows] = await getDb().execute('SELECT id, email, name, role, created_at FROM users ORDER BY created_at DESC')
    const users = (rows as any[]).map(r => ({
      id: r.id,
      email: r.email,
      name: r.name,
      role: r.role,
      createdAt: r.created_at
    }))
    res.json(users)
  } catch (err: any) {
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/users/:id/role', requireRole('admin'), async (req: Request, res: Response) => {
  const { role } = UpdateUserRoleSchema.parse(req.body)
  const targetId = req.params.id
  const admin = (req as any).user as AuthUser

  if (admin.id === targetId && role !== 'admin') {
    return res.status(400).json({ error: 'Admins cannot demote themselves' })
  }

  try {
    const [result] = await getDb().execute('UPDATE users SET role = ? WHERE id = ?', [role, targetId])
    if ((result as any).affectedRows === 0) return res.status(404).json({ error: 'Not found' })
    res.json({ id: targetId, role })
  } catch (err: any) {
    res.status(400).json({ error: err.message })
  }
})

app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (res.headersSent) {
    return next(err)
  }
  const requestId = uuid()
  const status = typeof err?.status === 'number' && err.status >= 400 && err.status < 600 ? err.status : 500
  const message = status >= 500 ? 'Internal server error' : err?.message || 'Request failed'
  console.error('Unhandled request error', {
    requestId,
    method: req.method,
    path: req.path,
    status,
    error: err?.message,
    stack: process.env.NODE_ENV === 'development' ? err?.stack : undefined
  })
  res.status(status).json({ error: message, requestId })
})
