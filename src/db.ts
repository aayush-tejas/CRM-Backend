import mysql from 'mysql2/promise'

let pool: mysql.Pool

export function getDb() {
  if (!pool) {
    pool = mysql.createPool({
      host: process.env.DB_HOST || 'localhost',
      port: Number(process.env.DB_PORT || 3306),
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'crm',
      charset: 'utf8mb4',
      connectionLimit: 10
    })
  }
  return pool
}

// Create database without specifying it in connection
async function createDatabase() {
  const tempPool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    charset: 'utf8mb4'
  })
  
  await tempPool.execute(`CREATE DATABASE IF NOT EXISTS \`${process.env.DB_NAME || 'crm'}\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci`)
  await tempPool.end()
}

export async function migrate() {
  // First create the database
  await createDatabase()
  
  // Then connect to it and create tables
  const db = getDb()

  // Create tables
  await db.execute(`
  CREATE TABLE IF NOT EXISTS users (
    id CHAR(36) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255),
    password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      role VARCHAR(32) NOT NULL DEFAULT 'agent',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`)

  // Add role column if it does not exist (idempotent). MySQL before 8.0 doesn't support IF NOT EXISTS on ADD COLUMN, so catch duplicate errors.
  try {
      await db.execute('ALTER TABLE users ADD COLUMN role VARCHAR(32) NOT NULL DEFAULT "agent"')
  } catch (err: any) {
    // ER_DUP_FIELDNAME = 1060 indicates column already exists – safe to ignore
    if (err?.code !== 'ER_DUP_FIELDNAME') {
      console.error('Role column migration warning:', err.message)
    }
  }

    // Normalize legacy role values (employee -> agent)
    await db.execute('UPDATE users SET role = "agent" WHERE role IS NULL OR role = "" OR role = "employee"')

  await db.execute(`
  CREATE TABLE IF NOT EXISTS employees (
    id CHAR(36) PRIMARY KEY,
    employee_id VARCHAR(64) NOT NULL UNIQUE,
    employee_name VARCHAR(255) NOT NULL,
    designation VARCHAR(255),
    email VARCHAR(255),
    mobile VARCHAR(32),
    department VARCHAR(255),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`)

  await db.execute(`
  CREATE TABLE IF NOT EXISTS customers (
    id CHAR(36) PRIMARY KEY,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    organization_name VARCHAR(255),
    address TEXT,
    city VARCHAR(255),
    pin_code VARCHAR(20),
    state VARCHAR(255),
    country VARCHAR(255),
    email VARCHAR(255),
    mobile VARCHAR(32),
    contact_person VARCHAR(255),
    contact_person_name VARCHAR(255),
    contact_person_email VARCHAR(255),
    business_type VARCHAR(255),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`)

  await db.execute(`
  CREATE TABLE IF NOT EXISTS tenders (
    id CHAR(36) PRIMARY KEY,
    date_of_service DATE,
    serial_token VARCHAR(128) NOT NULL UNIQUE,
    allotted_to VARCHAR(255),
    source VARCHAR(255),
    priority VARCHAR(32),
    status VARCHAR(32),
    customer_id VARCHAR(255),
    customer_name VARCHAR(255),
    employee_id VARCHAR(255),
    employee_name VARCHAR(255),
    lead_title VARCHAR(255),
    lead_description TEXT,
    estimated_value VARCHAR(64),
    follow_up_date DATE,
      owner_user_id CHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  )`)

    try {
      await db.execute('ALTER TABLE tenders ADD COLUMN owner_user_id CHAR(36) NULL')
    } catch (err: any) {
      if (err?.code !== 'ER_DUP_FIELDNAME') {
        console.error('owner_user_id migration warning:', err.message)
      }
    }

  await db.execute(`
  CREATE TABLE IF NOT EXISTS tender_backups (
    id CHAR(36) PRIMARY KEY,
    tender_id CHAR(36) NOT NULL,
    serial_token VARCHAR(128) NOT NULL,
    snapshot_json JSON NOT NULL,
    snapshot_hash CHAR(64) NOT NULL,
    created_by_user_id CHAR(36) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_tender_backups_tender (tender_id),
    INDEX idx_tender_backups_serial (serial_token)
  )`)

  await db.execute(`
  CREATE TABLE IF NOT EXISTS tasks (
    id CHAR(36) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    priority VARCHAR(32) NOT NULL DEFAULT 'Medium',
    status VARCHAR(32) NOT NULL DEFAULT 'Pending',
    due_date DATE,
    employee_id CHAR(36) NOT NULL,
    team VARCHAR(128),
    remind_before_minutes INT,
    notes TEXT,
    created_by_user_id CHAR(36) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  )`)

  try {
    await db.execute('ALTER TABLE tasks ADD INDEX idx_tasks_employee (employee_id)')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_KEYNAME') {
      console.error('tasks employee index warning:', err.message)
    }
  }

  try {
    await db.execute('ALTER TABLE tasks ADD COLUMN team VARCHAR(128) NULL')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_FIELDNAME') {
      console.error('tasks team column warning:', err.message)
    }
  }

  try {
    await db.execute('ALTER TABLE tasks ADD COLUMN remind_before_minutes INT NULL')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_FIELDNAME') {
      console.error('tasks remind column warning:', err.message)
    }
  }

  try {
    await db.execute('ALTER TABLE tasks ADD COLUMN notes TEXT NULL')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_FIELDNAME') {
      console.error('tasks notes column warning:', err.message)
    }
  }

  await db.execute(`
  CREATE TABLE IF NOT EXISTS task_dependencies (
    task_id CHAR(36) NOT NULL,
    depends_on_task_id CHAR(36) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (task_id, depends_on_task_id),
    CONSTRAINT fk_task_dep_task FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    CONSTRAINT fk_task_dep_depends FOREIGN KEY (depends_on_task_id) REFERENCES tasks(id) ON DELETE CASCADE
  )`)

  try {
    await db.execute('ALTER TABLE task_dependencies ADD INDEX idx_task_dependencies_task (task_id)')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_KEYNAME') {
      console.error('task_dependencies index warning:', err.message)
    }
  }

    await db.execute(`
    CREATE TABLE IF NOT EXISTS custom_fields (
      id CHAR(36) PRIMARY KEY,
      entity_type VARCHAR(64) NOT NULL,
      field_key VARCHAR(64) NOT NULL,
      label VARCHAR(255) NOT NULL,
      description TEXT,
      field_type VARCHAR(32) NOT NULL,
      required TINYINT(1) NOT NULL DEFAULT 0,
      config JSON,
      default_value JSON,
      order_index INT NOT NULL DEFAULT 0,
      created_by_user_id CHAR(36),
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_custom_fields (entity_type, field_key),
      INDEX idx_custom_fields_entity (entity_type)
    )`)

    await db.execute(`
    CREATE TABLE IF NOT EXISTS custom_field_values (
      id CHAR(36) PRIMARY KEY,
      field_id CHAR(36) NOT NULL,
      entity_type VARCHAR(64) NOT NULL,
      entity_id CHAR(36) NOT NULL,
      value_text TEXT,
      value_number DECIMAL(18,4),
      value_date DATE,
      value_json JSON,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_field_entity (field_id, entity_id),
      INDEX idx_field_values_entity (entity_type, entity_id),
      CONSTRAINT fk_custom_field_values_field FOREIGN KEY (field_id) REFERENCES custom_fields(id) ON DELETE CASCADE
    )`)

    await db.execute(`
    CREATE TABLE IF NOT EXISTS entity_layouts (
      id CHAR(36) PRIMARY KEY,
      entity_type VARCHAR(64) NOT NULL UNIQUE,
      layout JSON NOT NULL,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`)

    await db.execute(`
    CREATE TABLE IF NOT EXISTS branding_settings (
      id CHAR(36) PRIMARY KEY,
      tenant_key VARCHAR(64) NOT NULL UNIQUE,
      brand_name VARCHAR(255),
      logo_url TEXT,
      favicon_url TEXT,
      primary_color VARCHAR(16),
      accent_color VARCHAR(16),
      background_color VARCHAR(16),
      text_color VARCHAR(16),
      default_locale VARCHAR(16) NOT NULL DEFAULT 'en',
      available_locales JSON,
      white_label JSON,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`)

    await db.execute(`
    CREATE TABLE IF NOT EXISTS webhook_subscriptions (
      id CHAR(36) PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      event_type VARCHAR(64) NOT NULL,
      target_url TEXT NOT NULL,
      shared_secret VARCHAR(255),
      headers JSON,
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      created_by_user_id CHAR(36),
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_webhooks_event (event_type),
      INDEX idx_webhooks_active (is_active)
    )`)

  try {
    await db.execute('ALTER TABLE task_dependencies ADD INDEX idx_task_dependencies_depends (depends_on_task_id)')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_KEYNAME') {
      console.error('task_dependencies depends index warning:', err.message)
    }
  }

  await db.execute(`
  CREATE TABLE IF NOT EXISTS documents (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner VARCHAR(255),
    related_to VARCHAR(255),
    category VARCHAR(64),
    tags JSON,
    summary TEXT,
    link TEXT,
    file_name VARCHAR(255),
    file_size BIGINT,
    mime_type VARCHAR(128),
    storage_key VARCHAR(255),
    uploaded_by_user_id CHAR(36),
    text_content LONGTEXT,
    uploaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  )`)

  try {
    await db.execute('ALTER TABLE documents ADD INDEX idx_documents_category (category)')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_KEYNAME') {
      console.error('documents category index warning:', err.message)
    }
  }

  try {
    await db.execute('ALTER TABLE documents ADD INDEX idx_documents_uploaded_by (uploaded_by_user_id)')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_KEYNAME') {
      console.error('documents uploaded_by index warning:', err.message)
    }
  }

  try {
    await db.execute('ALTER TABLE documents ADD COLUMN text_content LONGTEXT NULL')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_FIELDNAME') {
      console.error('documents text_content column warning:', err.message)
    }
  }

  try {
    await db.execute('ALTER TABLE documents ADD FULLTEXT INDEX idx_documents_fulltext (name, summary, text_content)')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_KEYNAME') {
      console.error('documents fulltext index warning:', err.message)
    }
  }

  await db.execute(`
  CREATE TABLE IF NOT EXISTS record_attachments (
    id CHAR(36) PRIMARY KEY,
    entity_type VARCHAR(32) NOT NULL,
    entity_id CHAR(36) NOT NULL,
    document_id CHAR(36) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by_user_id CHAR(36),
    UNIQUE KEY uniq_record_attachment (entity_type, entity_id, document_id),
    INDEX idx_record_attachments_entity (entity_type, entity_id),
    CONSTRAINT fk_record_attachment_document FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
  )`)

  await db.execute(`
  CREATE TABLE IF NOT EXISTS activities (
    id CHAR(36) PRIMARY KEY,
    entity_type VARCHAR(64) NOT NULL,
    entity_key VARCHAR(255) NOT NULL,
    user_email VARCHAR(255),
    user_name VARCHAR(255),
    type VARCHAR(32) NOT NULL DEFAULT 'comment',
    text TEXT NOT NULL,
    channel VARCHAR(32),
    direction VARCHAR(16),
    subject VARCHAR(255),
    sentiment_score DECIMAL(10,5),
    sentiment_label VARCHAR(16),
    occurred_at DATETIME,
    metadata_json JSON,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`)

  try {
    await db.execute('ALTER TABLE activities ADD INDEX idx_activities_entity (entity_type, entity_key)')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_KEYNAME') {
      console.error('activities entity index warning:', err.message)
    }
  }

  const activityColumnMigrations: Array<{ sql: string; code: string }> = [
    { sql: 'ALTER TABLE activities ADD COLUMN channel VARCHAR(32) NULL', code: 'ER_DUP_FIELDNAME' },
    { sql: 'ALTER TABLE activities ADD COLUMN direction VARCHAR(16) NULL', code: 'ER_DUP_FIELDNAME' },
    { sql: 'ALTER TABLE activities ADD COLUMN subject VARCHAR(255) NULL', code: 'ER_DUP_FIELDNAME' },
    { sql: 'ALTER TABLE activities ADD COLUMN sentiment_score DECIMAL(10,5) NULL', code: 'ER_DUP_FIELDNAME' },
    { sql: 'ALTER TABLE activities ADD COLUMN sentiment_label VARCHAR(16) NULL', code: 'ER_DUP_FIELDNAME' },
    { sql: 'ALTER TABLE activities ADD COLUMN occurred_at DATETIME NULL', code: 'ER_DUP_FIELDNAME' },
    { sql: 'ALTER TABLE activities ADD COLUMN metadata_json JSON NULL', code: 'ER_DUP_FIELDNAME' }
  ]

  for (const migration of activityColumnMigrations) {
    try {
      await db.execute(migration.sql)
    } catch (err: any) {
      if (err?.code !== migration.code) {
        console.error('activities column migration warning:', err?.message)
      }
    }
  }

  try {
    await db.execute('ALTER TABLE activities ADD INDEX idx_activities_occurred (occurred_at)')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_KEYNAME') {
      console.error('activities occurred index warning:', err.message)
    }
  }

  await db.execute(`
  CREATE TABLE IF NOT EXISTS customer_segments (
    id CHAR(36) PRIMARY KEY,
    customer_id CHAR(36) NOT NULL,
    segment VARCHAR(64) NOT NULL,
    description VARCHAR(500),
    color VARCHAR(16),
    source VARCHAR(16) NOT NULL DEFAULT 'manual',
    created_by_user_id CHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_customer_segment (customer_id, segment),
    INDEX idx_customer_segments_customer (customer_id)
  )`)

  await db.execute(`
  CREATE TABLE IF NOT EXISTS engagement_scores (
    id CHAR(36) PRIMARY KEY,
    customer_id CHAR(36) NOT NULL,
    score INT NOT NULL,
    stage VARCHAR(32) NOT NULL,
    drivers JSON,
    computed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_engagement_scores_customer (customer_id, computed_at)
  )`)

  await db.execute(`
  CREATE TABLE IF NOT EXISTS email_templates (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description VARCHAR(255),
    subject VARCHAR(255) NOT NULL,
    body_html LONGTEXT,
    body_text LONGTEXT,
    tags JSON,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_by_user_id CHAR(36),
    updated_by_user_id CHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_email_template_name (name)
  )`)

  await db.execute(`
  CREATE TABLE IF NOT EXISTS tender_email_messages (
    id CHAR(36) PRIMARY KEY,
    tender_id CHAR(36) NOT NULL,
    template_id CHAR(36),
    direction ENUM('outbound','inbound') NOT NULL DEFAULT 'outbound',
    subject VARCHAR(255) NOT NULL,
    body LONGTEXT NOT NULL,
    headers JSON,
    status VARCHAR(32) NOT NULL DEFAULT 'queued',
    sent_at DATETIME,
    created_by_user_id CHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_tender_email_messages_tender (tender_id),
    INDEX idx_tender_email_messages_direction (direction),
    CONSTRAINT fk_tender_email_messages_template FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE SET NULL
  )`)

  await db.execute(`
  CREATE TABLE IF NOT EXISTS chat_connectors (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    type VARCHAR(32) NOT NULL,
    webhook_url TEXT,
    metadata JSON,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_by_user_id CHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`)

  await db.execute(`
  CREATE TABLE IF NOT EXISTS chat_messages (
    id CHAR(36) PRIMARY KEY,
    connector_id CHAR(36) NOT NULL,
    entity_type VARCHAR(32) NOT NULL,
    entity_id CHAR(36) NOT NULL,
    direction ENUM('outbound','inbound') NOT NULL,
    text TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    response JSON,
    created_by_user_id CHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_chat_messages_connector (connector_id),
    INDEX idx_chat_messages_entity (entity_type, entity_id),
    CONSTRAINT fk_chat_messages_connector FOREIGN KEY (connector_id) REFERENCES chat_connectors(id) ON DELETE CASCADE
  )`)

  await db.execute(`
  CREATE TABLE IF NOT EXISTS voice_calls (
    id CHAR(36) PRIMARY KEY,
    entity_type VARCHAR(32) NOT NULL,
    entity_id CHAR(36) NOT NULL,
    subject VARCHAR(255),
    participants JSON,
    status VARCHAR(32) NOT NULL,
    outcome VARCHAR(64),
    summary TEXT,
    recording_url TEXT,
    duration_seconds INT,
    created_by_user_id CHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_voice_calls_entity (entity_type, entity_id)
  )`)

  await db.execute(`
  CREATE TABLE IF NOT EXISTS approval_policies (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    criteria_json JSON,
    steps_json JSON,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_by_user_id CHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_approval_policies_active (is_active)
  )`)

  await db.execute(`
  CREATE TABLE IF NOT EXISTS approval_requests (
    id CHAR(36) PRIMARY KEY,
    policy_id CHAR(36) NOT NULL,
    entity_type VARCHAR(32) NOT NULL,
    entity_id CHAR(36) NOT NULL,
    status VARCHAR(32) NOT NULL,
    submitted_by_user_id CHAR(36),
    submitted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decided_at DATETIME,
    decision_notes TEXT,
    context_json JSON,
    INDEX idx_approval_requests_entity (entity_type, entity_id),
    INDEX idx_approval_requests_policy (policy_id),
    CONSTRAINT fk_approval_requests_policy FOREIGN KEY (policy_id) REFERENCES approval_policies(id) ON DELETE CASCADE
  )`)

  try {
    await db.execute('ALTER TABLE approval_requests ADD COLUMN context_json JSON NULL')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_FIELDNAME') {
      console.error('approval_requests context column warning:', err.message)
    }
  }

  await db.execute(`
  CREATE TABLE IF NOT EXISTS audit_events (
    id CHAR(36) PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    entity_type VARCHAR(32),
    entity_id CHAR(36),
    user_id CHAR(36),
    meta_json JSON,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_events_entity (entity_type, entity_id),
    INDEX idx_audit_events_type (event_type)
  )`)

  try {
    await db.execute('ALTER TABLE activities ADD COLUMN channel VARCHAR(32) NULL')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_FIELDNAME') {
      console.error('activities channel column warning:', err.message)
    }
  }

  try {
    await db.execute('ALTER TABLE activities ADD COLUMN direction VARCHAR(16) NULL')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_FIELDNAME') {
      console.error('activities direction column warning:', err.message)
    }
  }

  try {
    await db.execute('ALTER TABLE activities ADD COLUMN subject VARCHAR(255) NULL')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_FIELDNAME') {
      console.error('activities subject column warning:', err.message)
    }
  }

  try {
    await db.execute('ALTER TABLE activities ADD COLUMN sentiment_score DECIMAL(6,3) NULL')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_FIELDNAME') {
      console.error('activities sentiment_score column warning:', err.message)
    }
  }

  try {
    await db.execute('ALTER TABLE activities ADD COLUMN sentiment_label VARCHAR(24) NULL')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_FIELDNAME') {
      console.error('activities sentiment_label column warning:', err.message)
    }
  }

  try {
    await db.execute('ALTER TABLE activities ADD COLUMN occurred_at DATETIME NULL')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_FIELDNAME') {
      console.error('activities occurred_at column warning:', err.message)
    }
  }

  try {
    await db.execute('ALTER TABLE activities ADD COLUMN metadata_json JSON NULL')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_FIELDNAME') {
      console.error('activities metadata_json column warning:', err.message)
    }
  }

  try {
    await db.execute('ALTER TABLE activities ADD INDEX idx_activities_entity_occurred (entity_type, entity_key, occurred_at)')
  } catch (err: any) {
    if (err?.code !== 'ER_DUP_KEYNAME') {
      console.error('activities occurred_at index warning:', err.message)
    }
  }

  await db.execute(`
  CREATE TABLE IF NOT EXISTS customer_segments (
    id CHAR(36) PRIMARY KEY,
    customer_id CHAR(36) NOT NULL,
    segment VARCHAR(64) NOT NULL,
    description TEXT,
    color VARCHAR(16),
    source VARCHAR(16) NOT NULL DEFAULT 'manual',
    created_by_user_id CHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_customer_segments (customer_id, segment),
    INDEX idx_customer_segments_customer (customer_id),
    CONSTRAINT fk_customer_segments_customer FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
  )`)

  await db.execute(`
  CREATE TABLE IF NOT EXISTS engagement_scores (
    id CHAR(36) PRIMARY KEY,
    customer_id CHAR(36) NOT NULL,
    score INT NOT NULL,
    stage VARCHAR(32) NOT NULL,
    drivers JSON,
    computed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_engagement_scores_customer (customer_id, computed_at),
    CONSTRAINT fk_engagement_scores_customer FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
  )`)
}
