import { getDb } from './src/db.js'

async function checkUsers() {
  const db = getDb()
  try {
    console.log('Checking users table...')
    
    // First, let's see all tables
    const [tables] = await db.execute('SHOW TABLES')
    console.log('\nTables in CRM database:')
    tables.forEach(table => {
      const tableName = Object.values(table)[0]
      console.log(`- ${tableName}`)
    })
    
    // Check users table structure
    console.log('\nUsers table structure:')
    const [columns] = await db.execute('DESCRIBE users')
    console.table(columns)
    
    // Check users data
    console.log('\nUsers in database:')
    const [users] = await db.execute('SELECT id, email, name, created_at FROM users ORDER BY created_at DESC')
    
    if (users.length === 0) {
      console.log('No users found in database yet.')
    } else {
      console.table(users)
    }
    
    console.log(`\nTotal users: ${users.length}`)
    
  } catch (error) {
    console.error('Error checking users:', error)
  } finally {
    await db.end()
  }
}

checkUsers()