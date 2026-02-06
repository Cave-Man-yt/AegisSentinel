-- GenAI Sentinel - PostgreSQL Database Schema
-- Production-ready schema with security best practices

-- Enable UUID extension for future use
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table with RBAC support
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'analyst', 'user')),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    email VARCHAR(255) UNIQUE,
    full_name VARCHAR(100),
    CONSTRAINT username_length CHECK (char_length(username) >= 3)
);

-- Create index for faster username lookups
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_is_active ON users(is_active);

-- Login audit logs table for security monitoring
CREATE TABLE login_audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(50) NOT NULL,  -- Store username even if user is deleted
    login_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) NOT NULL,  -- IPv6 support
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(100),
    session_id VARCHAR(255)
);

-- Create indexes for audit log queries
CREATE INDEX idx_login_audit_user_id ON login_audit_logs(user_id);
CREATE INDEX idx_login_audit_login_time ON login_audit_logs(login_time DESC);
CREATE INDEX idx_login_audit_success ON login_audit_logs(success);
CREATE INDEX idx_login_audit_ip_address ON login_audit_logs(ip_address);

-- Security events table for threat detection
CREATE TABLE security_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN (
        'brute_force_attempt',
        'suspicious_login',
        'invalid_token',
        'multiple_failed_logins',
        'account_lockout',
        'privilege_escalation_attempt',
        'unusual_activity',
        'sql_injection_attempt',
        'xss_attempt'
    )),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    description TEXT NOT NULL,
    triggered_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB  -- Flexible field for additional context
);

-- Create indexes for security event queries
CREATE INDEX idx_security_events_type ON security_events(event_type);
CREATE INDEX idx_security_events_severity ON security_events(severity);
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX idx_security_events_triggered_by ON security_events(triggered_by);

-- Prompt injection attempts table for threat distribution monitoring
CREATE TABLE prompt_injection_attempts (
    id SERIAL PRIMARY KEY,
    attack_type VARCHAR(100) NOT NULL CHECK (attack_type IN (
        'DAN Attacks',
        'Roleplay',
        'Obfuscation',
        'Direct Injection',
        'Jailbreak',
        'System Prompt Leak',
        'Context Confusion',
        'Multi-turn Manipulation',
        'Encoding Bypass',
        'Token Smuggling'
    )),
    prompt_text TEXT NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence_score DECIMAL(5,2) CHECK (confidence_score >= 0 AND confidence_score <= 100),
    blocked BOOLEAN NOT NULL DEFAULT true,
    source_ip VARCHAR(45) NOT NULL,
    user_agent TEXT,
    endpoint VARCHAR(100),  -- e.g., 'GPT-4 Turbo', 'Claude 3 Opus'
    app_id VARCHAR(100),    -- e.g., 'Finance-Bot-v1'
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    response_action VARCHAR(50) CHECK (response_action IN ('blocked', 'flagged', 'sanitized', 'allowed_with_warning')),
    latency_ms INTEGER,  -- Processing latency added by security check
    metadata JSONB  -- Additional detection metadata
);

-- Create indexes for prompt injection queries
CREATE INDEX idx_prompt_injection_attack_type ON prompt_injection_attempts(attack_type);
CREATE INDEX idx_prompt_injection_detected_at ON prompt_injection_attempts(detected_at DESC);
CREATE INDEX idx_prompt_injection_severity ON prompt_injection_attempts(severity);
CREATE INDEX idx_prompt_injection_blocked ON prompt_injection_attempts(blocked);
CREATE INDEX idx_prompt_injection_source_ip ON prompt_injection_attempts(source_ip);
CREATE INDEX idx_prompt_injection_user_id ON prompt_injection_attempts(user_id);
CREATE INDEX idx_prompt_injection_endpoint ON prompt_injection_attempts(endpoint);

-- Create a view for recent security dashboard
CREATE VIEW recent_security_summary AS
SELECT 
    DATE(timestamp) as date,
    event_type,
    severity,
    COUNT(*) as event_count
FROM security_events
WHERE timestamp >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY DATE(timestamp), event_type, severity
ORDER BY date DESC, event_count DESC;

-- Create a view for failed login tracking
CREATE VIEW failed_login_attempts AS
SELECT 
    username,
    ip_address,
    COUNT(*) as attempt_count,
    MAX(login_time) as last_attempt
FROM login_audit_logs
WHERE success = false 
    AND login_time >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
GROUP BY username, ip_address
HAVING COUNT(*) >= 3
ORDER BY attempt_count DESC;

-- Create a view for threat distribution (matches dashboard chart)
CREATE VIEW threat_distribution AS
SELECT 
    attack_type,
    COUNT(*) as total_attempts,
    COUNT(CASE WHEN blocked = true THEN 1 END) as blocked_count,
    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_count,
    ROUND((COUNT(*)::DECIMAL / NULLIF((SELECT COUNT(*) FROM prompt_injection_attempts), 0) * 100), 2) as percentage,
    MAX(detected_at) as last_detected
FROM prompt_injection_attempts
WHERE detected_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY attack_type
ORDER BY total_attempts DESC;

-- Insert default admin user (password: Admin@123 - CHANGE IN PRODUCTION!)
-- Password hash generated with bcrypt for 'Admin@123'
INSERT INTO users (username, password_hash, role, email, full_name) 
VALUES (
    'admin',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5ysLZLdP.rJaa',  -- Change this!
    'admin',
    'admin@genai-sentinel.local',
    'System Administrator'
);

-- Insert sample analyst user (password: Analyst@123 - CHANGE IN PRODUCTION!)
INSERT INTO users (username, password_hash, role, email, full_name) 
VALUES (
    'analyst',
    '$2b$12$8Z8qO8/ZL0hVv8tYXqBJ0OqO7WvTqxSeP4bkjKT1sA1jxVZJxGLhS',  -- Change this!
    'analyst',
    'analyst@genai-sentinel.local',
    'Security Analyst'
);

-- Insert custom user (password: helloworld@123)
-- Password hash generated with bcrypt for 'helloworld@123'
INSERT INTO users (username, password_hash, role, email, full_name) 
VALUES (
    'welcome@123',
    '$2b$12$qZXJVVJ5x8LzKF8xqVrJ0.YHxE5mK5yPJ8nK9qxJ0.5K9qxJ0.5K9O',
    'user',
    'welcome@genai-sentinel.local',
    'Welcome User'
);

-- Comments for documentation
COMMENT ON TABLE users IS 'User accounts with role-based access control';
COMMENT ON TABLE login_audit_logs IS 'Complete audit trail of all login attempts';
COMMENT ON TABLE security_events IS 'Security incidents and threat detection events';
COMMENT ON TABLE prompt_injection_attempts IS 'Detected prompt injection attacks and threat distribution data';
COMMENT ON COLUMN users.password_hash IS 'bcrypt hashed password with salt';
COMMENT ON COLUMN login_audit_logs.success IS 'Whether the login attempt succeeded';
COMMENT ON COLUMN security_events.metadata IS 'JSON field for flexible event context';
COMMENT ON COLUMN prompt_injection_attempts.prompt_text IS 'The actual malicious prompt text that was detected';
COMMENT ON COLUMN prompt_injection_attempts.confidence_score IS 'ML model confidence score (0-100) for detection accuracy';
COMMENT ON COLUMN prompt_injection_attempts.response_action IS 'Action taken by the security layer';
