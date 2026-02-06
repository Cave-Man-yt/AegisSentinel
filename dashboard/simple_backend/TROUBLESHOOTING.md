# GenAI Sentinel - Login Troubleshooting Guide

## 🔍 Debug Steps

### Step 1: Check if Backend is Running
```bash
cd d:\HACKARTHON_UI\simple_backend
python main.py
```

Look for:
```
✅ Default users created: admin, welcome@123
🚀 GenAI Sentinel Login System Started
```

### Step 2: Test Credentials
```bash
python test_credentials.py
```

This will show you:
- All users in the database
- Which passwords work
- What the correct credentials are

### Step 3: Test Backend API Directly

Open browser and go to: `http://localhost:8000`

You should see:
```json
{
  "message": "GenAI Sentinel Login API",
  "status": "online"
}
```

### Step 4: Test Login Endpoint

Using curl or Postman:
```bash
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"Admin@123\"}"
```

Expected response:
```json
{
  "success": true,
  "message": "Login successful"
}
```

### Step 5: Check Browser Console

1. Open `index.html` in browser
2. Press F12 to open Developer Tools
3. Go to Console tab
4. Try to login
5. Look for error messages

Common issues:
- `Failed to fetch` → Backend not running
- `CORS error` → CORS misconfiguration
- `404 Not Found` → Wrong API URL

### Step 6: Verify API URL in login.js

Check file: `d:\HACKARTHON_UI\login.js`

Line should be:
```javascript
const API_URL = 'http://localhost:8000';
```

---

## ✅ CONFIRMED WORKING CREDENTIALS

```
Username: admin
Password: Admin@123
```

```
Username: welcome@123
Password: helloworld@123
```

**COPY THESE EXACTLY** (case-sensitive!)

---

## 🐛 Common Issues

### Issue: "Invalid username or password"
**Cause:** Typo in username or password
**Solution:** Copy-paste credentials exactly as shown above

### Issue: "Connection error"
**Cause:** Backend not running
**Solution:** Run `python main.py` in simple_backend folder

### Issue: Nothing happens when clicking login
**Cause:** JavaScript not loaded
**Solution:** Check browser console for errors

### Issue: Error popup doesn't show
**Cause:** CSS not loaded
**Solution:** Verify `login-errors.css` is in same folder as `index.html`

---

## 🔧 Quick Reset

If nothing works, try this:

```bash
# 1. Delete the database
cd d:\HACKARTHON_UI\simple_backend
del users.db

# 2. Run backend (creates fresh database)
python main.py

# 3. Test credentials
python test_credentials.py
```

---

## 📞 Need Help?

Run the test script and share the output:
```bash
python test_credentials.py
```
