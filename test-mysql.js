import { getDb, migrate } from './src/db.js'

async function test() {
  try {
    console.log('Testing MySQL connection...')
    await migrate()
    console.log('Migration completed successfully')
    
    const db = getDb()
    const [rows] = await db.execute('SELECT 1 as test')
    console.log('MySQL connection OK:', rows)
    
    // Test creating a dummy employee
    const [result] = await db.execute('INSERT INTO employees (id, employee_id, employee_name, email, mobile) VALUES (?, ?, ?, ?, ?)', 
      ['test-id', 'EMP001', 'Test Employee', 'test@example.com', '1234567890'])
    console.log('Insert test:', result)
    
    // Clean up
    await db.execute('DELETE FROM employees WHERE id = ?', ['test-id'])
    console.log('Test completed successfully!')
    
    process.exit(0)
  } catch (error) {
    console.error('Test failed:', error)
    process.exit(1)
  }
}

test()