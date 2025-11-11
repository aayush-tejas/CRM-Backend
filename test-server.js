import express from 'express'
import { migrate, getDb } from './src/db.js'

const app = express()
app.use(express.json())

app.get('/health', (req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString() })
})

app.get('/test-db', async (req, res) => {
  try {
    const [rows] = await getDb().execute('SELECT 1 as test')
    res.json({ database: 'connected', result: rows })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

async function startServer() {
  try {
    console.log('Starting migration...')
    await migrate()
    console.log('Migration completed')
    
    const port = 4000
    const server = app.listen(port, '0.0.0.0', () => {
      console.log(`Test server listening on http://localhost:${port}`)
      console.log('Server is ready to accept connections')
    })
    
    server.on('error', (err) => {
      console.error('Server error:', err)
    })
    
    // Keep the process alive
    process.on('SIGINT', () => {
      console.log('Shutting down gracefully...')
      server.close(() => {
        console.log('Server closed')
        process.exit(0)
      })
    })
    
  } catch (error) {
    console.error('Failed to start server:', error)
    process.exit(1)
  }
}

startServer()