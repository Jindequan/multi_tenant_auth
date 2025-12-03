-- 创建团队表
CREATE TABLE {{SCHEMA}}."team" (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    owner_id UUID NOT NULL REFERENCES {{SCHEMA}}."user"(id) ON DELETE CASCADE,
    billing_tier VARCHAR(50),
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 创建团队成员表
CREATE TABLE {{SCHEMA}}."team_member" (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id UUID NOT NULL REFERENCES {{SCHEMA}}."team"(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES {{SCHEMA}}."user"(id) ON DELETE CASCADE,
    role_name VARCHAR(50) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    invited_by UUID REFERENCES {{SCHEMA}}."user"(id) ON DELETE SET NULL,
    invited_at TIMESTAMP WITH TIME ZONE,
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(team_id, user_id)
);

-- 创建索引
CREATE INDEX {{SCHEMA}}.idx_team_slug ON {{SCHEMA}}."team"(slug);
CREATE INDEX {{SCHEMA}}.idx_team_owner ON {{SCHEMA}}."team"(owner_id);
CREATE INDEX {{SCHEMA}}.idx_team_created_at ON {{SCHEMA}}."team"(created_at);

CREATE INDEX {{SCHEMA}}.idx_team_member_team_active ON {{SCHEMA}}."team_member"(team_id, is_active);
CREATE INDEX {{SCHEMA}}.idx_team_member_user_active ON {{SCHEMA}}."team_member"(user_id, is_active);
CREATE INDEX {{SCHEMA}}.idx_team_member_role ON {{SCHEMA}}."team_member"(role_name);
CREATE INDEX {{SCHEMA}}.idx_team_member_joined_at ON {{SCHEMA}}."team_member"(joined_at);