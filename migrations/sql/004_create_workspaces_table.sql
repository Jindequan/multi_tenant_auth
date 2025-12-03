-- 创建工作空间表
CREATE TABLE {{SCHEMA}}."workspace" (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    description TEXT,
    workspace_type VARCHAR(20) DEFAULT 'team',
    owner_id UUID NOT NULL REFERENCES {{SCHEMA}}."user"(id) ON DELETE CASCADE,
    team_id UUID REFERENCES {{SCHEMA}}."team"(id) ON DELETE CASCADE,
    visibility VARCHAR(20) DEFAULT 'private',
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 创建用户工作空间权限表 (核心权限表!)
CREATE TABLE {{SCHEMA}}."user_workspace_actions" (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES {{SCHEMA}}."user"(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES {{SCHEMA}}."workspace"(id) ON DELETE CASCADE,
    actions JSONB DEFAULT '[]' NOT NULL,
    granted_by UUID NOT NULL REFERENCES {{SCHEMA}}."user"(id) ON DELETE CASCADE,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(user_id, workspace_id)
);

-- 创建索引
CREATE INDEX {{SCHEMA}}.idx_workspace_slug ON {{SCHEMA}}."workspace"(slug);
CREATE INDEX {{SCHEMA}}.idx_workspace_owner ON {{SCHEMA}}."workspace"(owner_id);
CREATE INDEX {{SCHEMA}}.idx_workspace_team ON {{SCHEMA}}."workspace"(team_id);
CREATE INDEX {{SCHEMA}}.idx_workspace_type ON {{SCHEMA}}."workspace"(workspace_type);
CREATE INDEX {{SCHEMA}}.idx_workspace_visibility ON {{SCHEMA}}."workspace"(visibility);
CREATE INDEX {{SCHEMA}}.idx_workspace_created_at ON {{SCHEMA}}."workspace"(created_at);

CREATE INDEX {{SCHEMA}}.idx_user_workspace_actions_user_workspace ON {{SCHEMA}}."user_workspace_actions"(user_id, workspace_id);
CREATE INDEX {{SCHEMA}}.idx_user_workspace_actions_expires_at ON {{SCHEMA}}."user_workspace_actions"(expires_at);
CREATE INDEX {{SCHEMA}}.idx_user_workspace_actions_granted_by ON {{SCHEMA}}."user_workspace_actions"(granted_by);