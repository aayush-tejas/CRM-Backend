import { getDb } from './src/db.js'

async function testAuth() {
  console.log('Testing authentication endpoints...')
  
  try {
    // Test signup
    const signupResponse = await fetch('http://localhost:4000/api/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Test User',
        email: 'test@example.com',
        password: 'testpass123'
      })
    })
    
    console.log('Signup response status:', signupResponse.status)
    
    if (signupResponse.ok) {
      const signupData = await signupResponse.json()
      console.log('✅ Signup successful:', signupData)
      
      // Check database
      const db = getDb()
      const [users] = await db.execute('SELECT id, email, name, created_at FROM users')
      console.log('Users in database:', users)
      
      // Test login
      const loginResponse = await fetch('http://localhost:4000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'test@example.com',
          password: 'testpass123'
        })
      })
      
      console.log('Login response status:', loginResponse.status)
      
      if (loginResponse.ok) {
        const loginData = await loginResponse.json()
        console.log('✅ Login successful:', loginData)
      } else {
        const loginError = await loginResponse.text()
        console.log('❌ Login failed:', loginError)
      }
      
      await db.end()
    } else {
      const signupError = await signupResponse.text()
      console.log('❌ Signup failed:', signupError)
    }
    
  } catch (error) {
    console.error('Test error:', error.message)
  }
}

testAuth()