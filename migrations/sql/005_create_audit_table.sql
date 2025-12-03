-- 创建审计日志表
CREATE TABLE {{SCHEMA}}."audit_log" (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES {{SCHEMA}}."user"(id) ON DELETE CASCADE,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    ip_address INET,
    user_agent TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 创建索引
CREATE INDEX {{SCHEMA}}.idx_audit_log_user ON {{SCHEMA}}."audit_log"(user_id);
CREATE INDEX {{SCHEMA}}.idx_audit_log_action ON {{SCHEMA}}."audit_log"(action);
CREATE INDEX {{SCHEMA}}.idx_audit_log_resource ON {{SCHEMA}}."audit_log"(resource_type, resource_id);
CREATE INDEX {{SCHEMA}}.idx_audit_log_created_at ON {{SCHEMA}}."audit_log"(created_at);