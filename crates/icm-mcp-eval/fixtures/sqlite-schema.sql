PRAGMA foreign_keys = ON;

CREATE TABLE memories (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT '',
    last_accessed TEXT NOT NULL,
    access_count INTEGER DEFAULT 0,
    weight REAL DEFAULT 1.0,
    topic TEXT NOT NULL,
    summary TEXT NOT NULL,
    raw_excerpt TEXT,
    keywords TEXT,
    importance TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_data TEXT,
    related_ids TEXT,
    summary_hash TEXT,
    embedding BLOB
);

CREATE INDEX idx_memories_topic ON memories(topic);
CREATE INDEX idx_memories_weight ON memories(weight);
CREATE INDEX idx_memories_created ON memories(created_at);
CREATE UNIQUE INDEX idx_memories_summary_hash
    ON memories(summary_hash) WHERE summary_hash IS NOT NULL;

CREATE VIRTUAL TABLE memories_fts USING fts5(
    id,
    topic,
    summary,
    keywords,
    content='memories',
    content_rowid='rowid'
);

CREATE TRIGGER memories_ai AFTER INSERT ON memories BEGIN
    INSERT INTO memories_fts(rowid, id, topic, summary, keywords)
    VALUES (new.rowid, new.id, new.topic, new.summary, new.keywords);
END;

CREATE TRIGGER memories_ad AFTER DELETE ON memories BEGIN
    INSERT INTO memories_fts(memories_fts, rowid, id, topic, summary, keywords)
    VALUES ('delete', old.rowid, old.id, old.topic, old.summary, old.keywords);
END;

CREATE TRIGGER memories_au AFTER UPDATE OF topic, summary, keywords ON memories BEGIN
    INSERT INTO memories_fts(memories_fts, rowid, id, topic, summary, keywords)
    VALUES ('delete', old.rowid, old.id, old.topic, old.summary, old.keywords);
    INSERT INTO memories_fts(rowid, id, topic, summary, keywords)
    VALUES (new.rowid, new.id, new.topic, new.summary, new.keywords);
END;

CREATE TABLE feedback (
    id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    context TEXT NOT NULL,
    predicted TEXT NOT NULL,
    corrected TEXT NOT NULL,
    reason TEXT,
    source TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    applied_count INTEGER DEFAULT 0,
    embedding BLOB
);

CREATE INDEX idx_feedback_topic ON feedback(topic);

CREATE VIRTUAL TABLE feedback_fts USING fts5(
    id,
    topic,
    context,
    predicted,
    corrected,
    reason,
    content='feedback',
    content_rowid='rowid'
);

CREATE TRIGGER feedback_ai AFTER INSERT ON feedback BEGIN
    INSERT INTO feedback_fts(rowid, id, topic, context, predicted, corrected, reason)
    VALUES (new.rowid, new.id, new.topic, new.context, new.predicted, new.corrected, new.reason);
END;

CREATE TRIGGER feedback_ad AFTER DELETE ON feedback BEGIN
    INSERT INTO feedback_fts(feedback_fts, rowid, id, topic, context, predicted, corrected, reason)
    VALUES ('delete', old.rowid, old.id, old.topic, old.context, old.predicted, old.corrected, old.reason);
END;

CREATE TRIGGER feedback_au AFTER UPDATE ON feedback BEGIN
    INSERT INTO feedback_fts(feedback_fts, rowid, id, topic, context, predicted, corrected, reason)
    VALUES ('delete', old.rowid, old.id, old.topic, old.context, old.predicted, old.corrected, old.reason);
    INSERT INTO feedback_fts(rowid, id, topic, context, predicted, corrected, reason)
    VALUES (new.rowid, new.id, new.topic, new.context, new.predicted, new.corrected, new.reason);
END;

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    agent TEXT NOT NULL DEFAULT '',
    project TEXT,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_sessions_project ON sessions(project);
CREATE INDEX idx_sessions_started ON sessions(started_at);

CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    tool_name TEXT,
    tokens INTEGER,
    ts TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_messages_session ON messages(session_id);
CREATE INDEX idx_messages_ts ON messages(ts);
CREATE INDEX idx_messages_role ON messages(role);

CREATE VIRTUAL TABLE messages_fts USING fts5(
    id UNINDEXED,
    session_id UNINDEXED,
    role,
    content,
    tool_name,
    content='messages',
    content_rowid='rowid'
);

CREATE TRIGGER messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, id, session_id, role, content, tool_name)
    VALUES (new.rowid, new.id, new.session_id, new.role, new.content, COALESCE(new.tool_name, ''));
END;

CREATE TRIGGER messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, id, session_id, role, content, tool_name)
    VALUES ('delete', old.rowid, old.id, old.session_id, old.role, old.content, COALESCE(old.tool_name, ''));
END;

CREATE TRIGGER messages_au AFTER UPDATE OF role, content, tool_name ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, id, session_id, role, content, tool_name)
    VALUES ('delete', old.rowid, old.id, old.session_id, old.role, old.content, COALESCE(old.tool_name, ''));
    INSERT INTO messages_fts(rowid, id, session_id, role, content, tool_name)
    VALUES (new.rowid, new.id, new.session_id, new.role, new.content, COALESCE(new.tool_name, ''));
END;

CREATE TABLE icm_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
