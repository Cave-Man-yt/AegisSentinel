# GenAI Sentinel - Simple Login System

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd simple_backend
pip install -r requirements.txt
```

### 2. Run Backend Server
```bash
python main.py
```
Server will start at: `http://localhost:8000`

### 3. Update Frontend
Add to your `index.html` before closing `</body>`:
```html
<link rel="stylesheet" href="login-errors.css">
<script src="login.js"></script>
```

### 4. Test Login
Open `index.html` in browser and use:
- **Username:** `admin` | **Password:** `Admin@123`
- **Username:** `welcome@123` | **Password:** `helloworld@123`

---

## 📁 File Structure

```
d:\HACKARTHON_UI\
├── simple_backend\
│   ├── main.py              # FastAPI backend
│   ├── requirements.txt     # Python dependencies
│   ├── database.sql         # SQLite schema (reference)
│   └── users.db             # SQLite database (auto-created)
├── login.js                 # Frontend login handler
├── login-errors.css         # Error styling
└── index.html               # Your existing HTML
```

---

## 🔒 Security Features

✅ **bcrypt password hashing** - Passwords never stored in plain text  
✅ **Generic error messages** - Prevents username enumeration  
✅ **CORS protection** - Configure allowed origins in production  
✅ **Input validation** - Both frontend and backend  
✅ **No session tokens** - Simple stateless authentication

---

## 🛠️ API Documentation

### POST `/login`

**Request:**
```json
{
  "username": "admin",
  "password": "Admin@123"
}
```

**Response (Success):**
```json
{
  "success": true,
  "message": "Login successful"
}
```

**Response (Failure):**
```json
{
  "success": false,
  "message": "Invalid username or password"
}
```

---

## 🎨 Features

- **SQLite Database** - Lightweight, no setup required
- **Auto-initialization** - Database and users created on first run
- **Error Popup** - Cyberpunk-styled with glow and shake effects
- **No Page Refresh** - Smooth single-page experience
- **LocalStorage Auth** - Remembers login state

---

## 🔑 Default Users

| Username | Password | 
|----------|----------|
| admin | Admin@123 |
| welcome@123 | helloworld@123 |

⚠️ **Change passwords in production!**

---

## 🧪 Testing

1. **Start backend:** `python simple_backend/main.py`
2. **Open browser:** Open `index.html`
3. **Try incorrect password:** See red error popup
4. **Try correct credentials:** Modal closes, dashboard loads

---

## 📝 Notes

- Backend runs on port **8000**
- Frontend can be served from any port (CORS enabled)
- Database file `users.db` created automatically
- Error messages auto-hide after 5 seconds
