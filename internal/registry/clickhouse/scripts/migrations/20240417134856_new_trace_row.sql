-- +goose Up
-- +goose StatementBegin
ALTER TABLE swarm.traces ADD COLUMN IF NOT EXISTS hash_rule UInt64;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE swarm.trace_part ADD COLUMN IF NOT EXISTS hash_rule UInt64;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS swarm.trace_rules_new (
    handle UInt64,
    verdict String,
    rule String,
    hash_rule UInt64,
    agent_id String,
    timestamp DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(timestamp) 
PARTITION BY agent_id
TTL timestamp + INTERVAL 1 DAY DELETE
ORDER BY (handle, hash_rule);
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO swarm.trace_rules_new (handle, verdict, rule, agent_id, timestamp) 
SELECT handle, verdict, rule, agent_id, timestamp FROM swarm.trace_rules;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE swarm.trace_rules;
-- +goose StatementEnd

-- +goose StatementBegin
DROP VIEW IF EXISTS swarm.rules_mv;
-- +goose StatementEnd

-- +goose StatementBegin
RENAME TABLE swarm.trace_rules_new TO swarm.trace_rules;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE MATERIALIZED VIEW swarm.rules_mv TO swarm.trace_rules AS
SELECT 
    handle,
    verdict,
    rule,
    hash_rule,
    agent_id,
    timestamp
FROM swarm.traces;
-- +goose StatementEnd

-- +goose StatementBegin
DROP VIEW IF EXISTS swarm.tracepart_mv;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE MATERIALIZED VIEW swarm.tracepart_mv TO swarm.trace_part AS
SELECT 
    trace_id,
    table,
    chain,
    jump_target,
    handle,
    hash_rule,
    family,
    ifin,
    ifout,
    mac_s,
    mac_d,
    ip_s,
    ip_d,
    sport,
    dport,
    len,
    ip_proto,
    agent_id,
    timestamp
FROM swarm.traces;
-- +goose StatementEnd



-- +goose Down
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS swarm.trace_rules_old (
    handle UInt64,
    verdict String,
    rule String,
    agent_id String,
    timestamp DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(timestamp) 
PARTITION BY agent_id
TTL timestamp + INTERVAL 1 DAY DELETE
ORDER BY (handle);
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO swarm.trace_rules_old (handle, verdict, rule, agent_id, timestamp) 
SELECT handle, verdict, rule, agent_id, timestamp FROM swarm.trace_rules;
-- +goose StatementEnd

-- +goose StatementBegin
DROP VIEW IF EXISTS swarm.rules_mv;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE swarm.trace_rules;
-- +goose StatementEnd

-- +goose StatementBegin
RENAME TABLE swarm.trace_rules_old TO swarm.trace_rules;
-- +goose StatementEnd

-- +goose StatementBegin
DROP VIEW IF EXISTS swarm.tracepart_mv;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE swarm.traces DROP COLUMN IF EXISTS hash_rule;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE swarm.trace_part DROP COLUMN IF EXISTS hash_rule;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE MATERIALIZED VIEW swarm.rules_mv TO swarm.trace_rules AS
SELECT 
    handle,
    verdict,
    rule,
    agent_id,
    timestamp
FROM swarm.traces;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE MATERIALIZED VIEW swarm.tracepart_mv TO swarm.trace_part AS
SELECT 
    trace_id,
    table,
    chain,
    jump_target,
    handle,
    family,
    ifin,
    ifout,
    mac_s,
    mac_d,
    ip_s,
    ip_d,
    sport,
    dport,
    len,
    ip_proto,
    agent_id,
    timestamp
FROM swarm.traces;
-- +goose StatementEnd