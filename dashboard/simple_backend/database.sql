-- Simple SQLite Schema for GenAI Sentinel Login
-- No PostgreSQL extensions needed

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

-- Insert default users with bcrypt hashed passwords
-- Username: admin | Password: Admin@123
INSERT INTO users (username, password_hash) VALUES 
('admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5ysLZLdP.rJaa');

-- Username: welcome@123 | Password: helloworld@123
INSERT INTO users (username, password_hash) VALUES 
('welcome@123', '$2b$12$qZXJVVJ5x8LzKF8xqVrJ0.YHxE5mK5yPJ8nK9qxJ0.5K9qxJ0.5K9O');
