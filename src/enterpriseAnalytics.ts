import { Router, type Request, type Response } from 'express'
import { randomUUID as uuid } from 'node:crypto'
import { z } from 'zod'
import { getDb } from './db.js'
import { requireAuth, requireRole, type AuthUser } from './rbac.js'

const CLOSED_STATUSES = new Set(['Closed', 'Closed Won', 'Closed Lost', 'Won', 'Lost', 'Closed - Lost'])
const HIGH_PRIORITY = new Set(['High', 'Urgent'])

const ReportScheduleSchema = z.object({
  name: z.string().min(3).max(120),
  cadence: z.enum(['daily', 'weekly', 'monthly']),
  recipients: z.array(z.string().email()).min(1),
  format: z.enum(['pdf', 'xlsx', 'json']).default('pdf'),
  timezone: z.string().min(2).max(64).default('UTC'),
  filters: z.record(z.any()).optional()
})

export async function createEnterpriseSchema() {
  const sql = `
    CREATE TABLE IF NOT EXISTS report_subscriptions (
      id            VARCHAR(36) PRIMARY KEY,
      name          VARCHAR(255) NOT NULL,
      cadence       VARCHAR(32) NOT NULL,
      recipients    TEXT NOT NULL,
      format        VARCHAR(16) NOT NULL DEFAULT 'pdf',
      timezone      VARCHAR(64) NOT NULL DEFAULT 'UTC',
      filters       JSON NULL,
      last_run_at   DATETIME NULL,
      next_run_at   DATETIME NULL,
      created_by_user_id VARCHAR(36) NOT NULL,
      created_at    DATETIME NOT NULL,
      updated_at    DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `
  try {
    await getDb().execute(sql)
  } catch (err) {
    console.error('[enterprise] failed to ensure report_subscriptions table', err)
    throw err
  }
}

let ensureSchemaPromise: Promise<void> | null = null

async function ensureSchema() {
  if (!ensureSchemaPromise) {
    ensureSchemaPromise = createEnterpriseSchema().catch(err => {
      ensureSchemaPromise = null
      throw err
    })
  }
  return ensureSchemaPromise
}

function computeNextRun(cadence: 'daily' | 'weekly' | 'monthly', from: Date = new Date()): string {
  const next = new Date(from.getTime())
  next.setSeconds(0, 0)
  switch (cadence) {
    case 'daily':
      next.setDate(next.getDate() + 1)
      break
    case 'weekly':
      next.setDate(next.getDate() + (7 - next.getDay() || 7))
      break
    case 'monthly':
      next.setMonth(next.getMonth() + 1, 1)
      break
  }
  next.setHours(9, 0, 0, 0)
  return next.toISOString()
}

function parseNumeric(value: unknown): number | null {
  if (value == null) return null
  if (typeof value === 'number' && Number.isFinite(value)) return value
  const numeric = Number(String(value).replace(/[^0-9.-]/g, ''))
  return Number.isFinite(numeric) ? numeric : null
}

function average(values: number[]): number | null {
  if (!values.length) return null
  return Number((values.reduce((sum, value) => sum + value, 0) / values.length).toFixed(2))
}

function median(values: number[]): number | null {
  if (!values.length) return null
  const sorted = [...values].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 0 ? Number(((sorted[mid - 1] + sorted[mid]) / 2).toFixed(2)) : sorted[mid]
}

async function computeRealtimeDashboardMetrics() {
  const db = getDb()
  const now = new Date()

  const [openRows] = await db.query(`
    SELECT
      id,
      serial_token,
      customer_name,
      allotted_to,
      status,
      priority,
      estimated_value,
      follow_up_date,
      created_at,
      updated_at,
      TIMESTAMPDIFF(HOUR, created_at, COALESCE(updated_at, NOW())) AS ageHours
    FROM tenders
    WHERE status NOT IN ('Closed', 'Closed Won', 'Closed Lost', 'Won', 'Lost', 'Closed - Lost')
  `) as any

  const openItems = (openRows as any[]).map(row => {
    const estimatedValue = parseNumeric(row.estimated_value)
    const followUpDate = row.follow_up_date ? new Date(row.follow_up_date) : null
    const ageHours = Number(row.ageHours ?? 0)
    return {
      id: row.id,
      serialToken: row.serial_token,
      customerName: row.customer_name ?? null,
      owner: row.allotted_to ?? null,
      status: row.status ?? null,
      priority: row.priority ?? null,
      estimatedValue,
      followUpDate,
      ageHours
    }
  })

  const openCount = openItems.length
  const highPriorityCount = openItems.filter(item => HIGH_PRIORITY.has((item.priority || '').trim())).length
  const openValues = openItems.map(item => item.estimatedValue).filter((value): value is number => value != null)
  const totalPipelineValue = Number(openValues.reduce((sum, value) => sum + value, 0).toFixed(2))
  const averageDealSize = openValues.length ? Number((totalPipelineValue / openValues.length).toFixed(2)) : 0
  const avgAgeDays = average(openItems.map(item => item.ageHours / 24))

  const ageBuckets = [
    { label: '0-2 days', count: 0 },
    { label: '3-7 days', count: 0 },
    { label: '8-14 days', count: 0 },
    { label: '15+ days', count: 0 }
  ]
  openItems.forEach(item => {
    const ageDays = item.ageHours / 24
    if (ageDays <= 2) ageBuckets[0].count += 1
    else if (ageDays <= 7) ageBuckets[1].count += 1
    else if (ageDays <= 14) ageBuckets[2].count += 1
    else ageBuckets[3].count += 1
  })

  const ownersMap = new Map<string | null, { openCount: number; highPriority: number; ages: number[] }>()
  openItems.forEach(item => {
    const key = item.owner ?? 'Unassigned'
    const info = ownersMap.get(key) ?? { openCount: 0, highPriority: 0, ages: [] }
    info.openCount += 1
  if (HIGH_PRIORITY.has((item.priority || '').trim())) info.highPriority += 1
    info.ages.push(item.ageHours / 24)
    ownersMap.set(key, info)
  })

  const ownerLeaders = Array.from(ownersMap.entries())
    .map(([owner, info]) => ({
      owner,
      openCount: info.openCount,
      highPriority: info.highPriority,
      avgAgeDays: average(info.ages)
    }))
    .sort((a, b) => b.openCount - a.openCount)
    .slice(0, 6)

  let slaOnTrack = 0
  let slaAtRisk = 0
  let slaBreached = 0
  const followUpLagHours: number[] = []

  openItems.forEach(item => {
    if (!item.followUpDate) return
    const diffMs = item.followUpDate.getTime() - now.getTime()
    const diffHours = diffMs / (1000 * 60 * 60)
    if (diffHours < 0) slaBreached += 1
    else if (diffHours <= 48) slaAtRisk += 1
    else slaOnTrack += 1

    const lagHours = (now.getTime() - item.followUpDate.getTime()) / (1000 * 60 * 60)
    followUpLagHours.push(lagHours)
  })

  const [[conversion]] = await db.query(`
    SELECT
      SUM(status IN ('Closed Won','Won')) AS won,
      SUM(status IN ('Closed Lost','Lost')) AS lost,
      SUM(status IN ('Closed', 'Closed Won','Closed Lost','Won','Lost','Closed - Lost')) AS closed,
      SUM(status IN ('Closed Won','Won') AND updated_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS wonLast30,
      SUM(status IN ('Closed','Closed Won','Closed Lost','Won','Lost','Closed - Lost') AND updated_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS closedLast30
    FROM tenders
  `) as any

  const won = Number(conversion?.won ?? 0)
  const lost = Number(conversion?.lost ?? 0)
  const closed = Number(conversion?.closed ?? 0)
  const wonLast30 = Number(conversion?.wonLast30 ?? 0)
  const closedLast30 = Number(conversion?.closedLast30 ?? 0)

  const conversionRate = closed ? Number(((won / closed) * 100).toFixed(1)) : 0
  const trailing30Rate = closedLast30 ? Number(((wonLast30 / closedLast30) * 100).toFixed(1)) : 0

  const [[resolution]] = await db.query(`
    SELECT
      AVG(TIMESTAMPDIFF(HOUR, created_at, COALESCE(updated_at, NOW()))) AS avgResolutionHours
    FROM tenders
    WHERE status IN ('Closed','Closed Won','Closed Lost','Won','Lost','Closed - Lost')
  `) as any

  const recommendations: string[] = []
  if (conversionRate < 40 && closed > 5) {
    recommendations.push('Boost conversion by reviewing disqualified deals from the last quarter and refining qualification criteria.')
  }
  if (slaBreached > 0) {
    recommendations.push('Resolve the breached follow-ups now and create escalations for owners lagging behind SLA.')
  }
  if (avgAgeDays != null && avgAgeDays > 14) {
    recommendations.push('Average age of open deals exceeds two weeks. Consider accelerating review cadences or reallocating workloads.')
  }

  return {
    generatedAt: now.toISOString(),
    workInProgress: {
      openCount,
      highPriorityCount,
      avgAgeDays,
      ageBuckets,
      ownerLeaders,
      totalPipelineValue,
      averageDealSize,
      currency: 'INR'
    },
    conversion: {
      won,
      lost,
      closed,
      conversionRate,
      trailing30Rate
    },
    sla: {
      onTrack: slaOnTrack,
      atRisk: slaAtRisk,
      breached: slaBreached,
      avgResolutionHours: resolution?.avgResolutionHours != null ? Number(Number(resolution.avgResolutionHours).toFixed(1)) : null,
      medianFollowUpLagHours: median(followUpLagHours.filter(value => Number.isFinite(value) && value >= 0))
    },
    recommendations
  }
}

async function detectOutliersAndRisks() {
  const db = getDb()
  const now = new Date()
  const [rows] = await db.query(`
    SELECT id, serial_token, customer_name, status, priority, estimated_value, follow_up_date, created_at, updated_at
    FROM tenders
    WHERE estimated_value IS NOT NULL AND estimated_value <> ''
  `) as any

  const items = (rows as any[]).map(row => {
    const value = parseNumeric(row.estimated_value)
    const followUpDate = row.follow_up_date ? new Date(row.follow_up_date) : null
    const updatedAt = row.updated_at ? new Date(row.updated_at) : null
    const createdAt = row.created_at ? new Date(row.created_at) : null
    const ageMs = (updatedAt ?? now).getTime() - (createdAt ?? now).getTime()
    const ageDays = ageMs / (1000 * 60 * 60 * 24)
    const overdueHours = followUpDate ? (now.getTime() - followUpDate.getTime()) / (1000 * 60 * 60) : null
    return {
      id: row.id,
      serialToken: row.serial_token,
      customerName: row.customer_name ?? null,
      status: row.status ?? null,
      priority: row.priority ?? null,
      estimatedValue: value,
      followUpDate: followUpDate ? followUpDate.toISOString() : null,
      ageDays,
      overdueHours
    }
  }).filter(item => item.estimatedValue != null) as Array<{
    id: string
    serialToken: string
    customerName: string | null
    status: string | null
    priority: string | null
    estimatedValue: number
    followUpDate: string | null
    ageDays: number
    overdueHours: number | null
  }>

  const values = items.map(item => item.estimatedValue)
  const mean = average(values)
  const variance = values.length ? values.reduce((sum, value) => sum + Math.pow(value - (mean ?? 0), 2), 0) / values.length : 0
  const stdDeviation = Math.sqrt(variance)
  const zThreshold = 2.25

  const flagged = items.map(item => {
    const zScore = stdDeviation > 0 ? (item.estimatedValue - (mean ?? 0)) / stdDeviation : 0
  const normalizedPriority = (item.priority || '').trim()
  const normalizedStatus = (item.status || '').trim()
  const valueRisk = Math.min(40, Math.abs(zScore) * 10)
  const overdueRisk = item.overdueHours != null && item.overdueHours > 0 ? Math.min(30, item.overdueHours / 12) : 0
  const ageRisk = item.ageDays > 30 ? Math.min(20, (item.ageDays - 30) * 1.5) : Math.max(0, item.ageDays - 14)
  const priorityRisk = HIGH_PRIORITY.has(normalizedPriority) ? 10 : 0
    const rawScore = valueRisk + overdueRisk + ageRisk + priorityRisk
    const riskScore = Math.min(100, Math.round(rawScore))
    const riskBand = riskScore >= 75 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 30 ? 'moderate' : 'low'
    const reasons: string[] = []
  if (Math.abs(zScore) >= zThreshold) reasons.push('Deal value is a statistical outlier')
  if (item.overdueHours != null && item.overdueHours > 0) reasons.push(`Follow-up overdue by ${Math.round(item.overdueHours)}h`)
  if (!CLOSED_STATUSES.has(normalizedStatus) && item.ageDays > 45) reasons.push(`Open for ${Math.round(item.ageDays)} days without closure`)
  else if (item.ageDays > 30) reasons.push(`Active for ${Math.round(item.ageDays)} days`)
  if (HIGH_PRIORITY.has(normalizedPriority)) reasons.push('High or urgent priority')
    return {
      ...item,
      zScore: Number(zScore.toFixed(2)),
      riskScore,
      riskBand,
      reasons
    }
  }).filter(item => item.reasons.length > 0)
    .sort((a, b) => b.riskScore - a.riskScore)

  return {
    generatedAt: now.toISOString(),
    summary: {
      analyzed: items.length,
      flagged: flagged.length,
      meanValue: mean,
      stdDeviation: Number(stdDeviation.toFixed(2)),
      threshold: zThreshold
    },
    items: flagged.slice(0, 25)
  }
}

async function listReportSubscriptions(user: AuthUser) {
  await ensureSchema()
  const [rows] = await getDb().query(`
    SELECT id, name, cadence, recipients, format, timezone, filters, last_run_at, next_run_at, created_by_user_id, created_at, updated_at
    FROM report_subscriptions
    ORDER BY created_at DESC
  `)
  return (rows as any[]).map(row => ({
    id: row.id,
    name: row.name,
    cadence: row.cadence,
    recipients: String(row.recipients || '')
      .split(',')
      .map((value: string) => value.trim())
      .filter((value: string) => value.length > 0),
    format: row.format,
    timezone: row.timezone,
    filters: row.filters ? JSON.parse(row.filters) : undefined,
    lastRunAt: row.last_run_at ? new Date(row.last_run_at).toISOString() : null,
    nextRunAt: row.next_run_at ? new Date(row.next_run_at).toISOString() : null,
    createdByUserId: row.created_by_user_id,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
    updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : null,
    canManage: user.role === 'admin' || user.role === 'manager'
  }))
}

async function createReportSubscription(user: AuthUser, payload: z.infer<typeof ReportScheduleSchema>) {
  await ensureSchema()
  const nowIso = new Date().toISOString()
  const id = uuid()
  const nextRunAt = computeNextRun(payload.cadence)
  await getDb().execute(`
    INSERT INTO report_subscriptions (id, name, cadence, recipients, format, timezone, filters, last_run_at, next_run_at, created_by_user_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    id,
    payload.name,
    payload.cadence,
    payload.recipients.join(','),
    payload.format,
    payload.timezone,
    payload.filters ? JSON.stringify(payload.filters) : null,
    null,
    nextRunAt.slice(0, 19).replace('T', ' '),
    user.id,
    nowIso.slice(0, 19).replace('T', ' '),
    nowIso.slice(0, 19).replace('T', ' ')
  ])

  return {
    id,
    ...payload,
    recipients: payload.recipients,
    lastRunAt: null,
    nextRunAt,
    createdByUserId: user.id,
    createdAt: nowIso,
    updatedAt: nowIso
  }
}

async function deleteReportSubscription(id: string) {
  await ensureSchema()
  await getDb().execute('DELETE FROM report_subscriptions WHERE id = ?', [id])
}

async function markReportRun(id: string) {
  await ensureSchema()
  const nowIso = new Date().toISOString()
  const [rows] = await getDb().query('SELECT cadence FROM report_subscriptions WHERE id = ? LIMIT 1', [id])
  const cadenceValue = ((rows as any[])[0]?.cadence || 'weekly') as 'daily' | 'weekly' | 'monthly'
  const nextRun = computeNextRun(cadenceValue)
  await getDb().execute(`
    UPDATE report_subscriptions
    SET last_run_at = ?, next_run_at = ?, updated_at = ?
    WHERE id = ?
  `, [
    nowIso.slice(0, 19).replace('T', ' '),
    nextRun.slice(0, 19).replace('T', ' '),
    nowIso.slice(0, 19).replace('T', ' '),
    id
  ])
}

async function getSecurityPosture(): Promise<any> {
  const db = getDb()
  const [secretRows] = await db.query(`
    SELECT CASE WHEN LENGTH(?) < 32 THEN 1 ELSE 0 END AS weakSecret
  `, [process.env.JWT_SECRET || ''])

  const weakSecret = Boolean((secretRows as any[])[0]?.weakSecret)

  const [distributionRows] = await db.query(`
    SELECT LOWER(role) AS role, COUNT(*) AS count
    FROM users
    GROUP BY LOWER(role)
  `)

  const userDistribution = (distributionRows as any[]).map(row => ({
    role: row.role,
    count: Number(row.count || 0)
  }))

  const alerts: Array<{ level: 'info' | 'warning' | 'critical'; message: string }> = []
  if (weakSecret) {
    alerts.push({ level: 'critical', message: 'JWT secret length is below 32 characters. Rotate to a stronger secret immediately.' })
  }
  if (process.env.COOKIES_AUTH !== 'true') {
    alerts.push({ level: 'warning', message: 'HTTP-only session cookies are disabled. Consider enabling COOKIES_AUTH for stronger session security.' })
  }

  const mfaRoles = (process.env.MFA_ENFORCED_ROLES || 'admin,manager').split(',').map(part => part.trim()).filter(Boolean)
  const providers = (process.env.SSO_ALLOWED_PROVIDERS || 'AzureAD,Okta,Google').split(',').map(part => part.trim()).filter(Boolean)
  const tokenExpiry = process.env.JWT_EXPIRES ? Number(String(process.env.JWT_EXPIRES).replace(/[^0-9]/g, '')) : null
  const idleTimeout = process.env.IDLE_TIMEOUT_MINUTES ? Number(process.env.IDLE_TIMEOUT_MINUTES) : null
  const passwordMinLength = process.env.PASSWORD_MIN_LENGTH ? Number(process.env.PASSWORD_MIN_LENGTH) : 12
  const rotationDays = process.env.PASSWORD_ROTATION_DAYS ? Number(process.env.PASSWORD_ROTATION_DAYS) : 90

  return {
    generatedAt: new Date().toISOString(),
    userDistribution,
    sso: {
      enabled: process.env.SSO_ENABLED === 'true',
      providers,
      enforcement: process.env.SSO_ENFORCEMENT ?? 'optional'
    },
    mfa: {
      enforced: mfaRoles.length > 0,
      enforcedFor: mfaRoles,
      backupCodesEnabled: process.env.MFA_BACKUP_CODES === 'true'
    },
    passwordPolicy: {
      minLength: passwordMinLength,
      complexity: ['upper-case', 'lower-case', 'numeric', 'symbol'],
      rotationDays
    },
    sessionSecurity: {
      tokenExpiryMinutes: tokenExpiry,
      idleTimeoutMinutes: idleTimeout,
      refreshTokenEnabled: process.env.REFRESH_TOKENS === 'true'
    },
    alerts,
    recommendations: alerts.length === 0 ? [
      'Review security posture quarterly and validate MFA coverage for privileged roles.',
      'Document incident response runbooks and practice at least twice a year.'
    ] : [
      'Address outstanding alerts before onboarding new admins.',
      'Re-run penetration testing once the critical findings are remediated.'
    ]
  }
}

export function createEnterpriseRouter() {
  const router = Router()

  router.get('/realtime', requireAuth, requireRole('admin', 'manager'), async (_req: Request, res: Response) => {
    try {
      const metrics = await computeRealtimeDashboardMetrics()
      res.json(metrics)
    } catch (err: any) {
      console.error('[enterprise] failed to compute realtime metrics', err)
      res.status(500).json({ error: 'Failed to compute real-time metrics' })
    }
  })

  router.get('/outliers', requireAuth, requireRole('admin', 'manager'), async (_req: Request, res: Response) => {
    try {
      const insights = await detectOutliersAndRisks()
      res.json(insights)
    } catch (err: any) {
      console.error('[enterprise] failed to detect outliers', err)
      res.status(500).json({ error: 'Failed to detect outliers' })
    }
  })

  router.get('/security/posture', requireAuth, requireRole('admin'), async (_req: Request, res: Response) => {
    try {
      const posture = await getSecurityPosture()
      res.json(posture)
    } catch (err: any) {
      console.error('[enterprise] failed to load security posture', err)
      res.status(500).json({ error: 'Failed to load security posture' })
    }
  })

  router.get('/report-subscriptions', requireAuth, requireRole('admin', 'manager'), async (req: Request, res: Response) => {
    try {
      const user = (req as any).user as AuthUser
      const records = await listReportSubscriptions(user)
      res.json(records)
    } catch (err: any) {
      console.error('[enterprise] failed to list report subscriptions', err)
      res.status(500).json({ error: 'Failed to list report subscriptions' })
    }
  })

  router.post('/report-subscriptions', requireAuth, requireRole('admin', 'manager'), async (req: Request, res: Response) => {
    try {
      const user = (req as any).user as AuthUser
      const parsed = ReportScheduleSchema.safeParse(req.body)
      if (!parsed.success) {
        return res.status(400).json({ error: parsed.error.flatten() })
      }
      const payload = await createReportSubscription(user, parsed.data)
      res.status(201).json(payload)
    } catch (err: any) {
      console.error('[enterprise] failed to create report subscription', err)
      res.status(500).json({ error: 'Failed to create subscription' })
    }
  })

  router.delete('/report-subscriptions/:id', requireAuth, requireRole('admin', 'manager'), async (req: Request, res: Response) => {
    try {
      await deleteReportSubscription(req.params.id)
      res.status(204).end()
    } catch (err: any) {
      console.error('[enterprise] failed to delete report subscription', err)
      res.status(500).json({ error: 'Failed to delete subscription' })
    }
  })

  router.post('/report-subscriptions/:id/dispatch', requireAuth, requireRole('admin', 'manager'), async (req: Request, res: Response) => {
    try {
      const user = (req as any).user as AuthUser
      const metrics = await computeRealtimeDashboardMetrics()
      await markReportRun(req.params.id)
      res.json({
        generatedAt: new Date().toISOString(),
        requestedBy: { id: user.id, email: user.email },
        metrics
      })
    } catch (err: any) {
      console.error('[enterprise] failed to dispatch report', err)
      res.status(500).json({ error: 'Failed to dispatch report' })
    }
  })

  return router
}
