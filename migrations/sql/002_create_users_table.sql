-- 创建用户表
CREATE TABLE {{SCHEMA}}."user" (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    personal_info JSONB DEFAULT '{}',
    settings JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 创建索引
CREATE INDEX {{SCHEMA}}.idx_user_email ON {{SCHEMA}}."user"(email);
CREATE INDEX {{SCHEMA}}.idx_user_is_active ON {{SCHEMA}}."user"(is_active);
CREATE INDEX {{SCHEMA}}.idx_user_created_at ON {{SCHEMA}}."user"(created_at);