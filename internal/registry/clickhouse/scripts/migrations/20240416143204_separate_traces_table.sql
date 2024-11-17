-- +goose Up
-- +goose StatementBegin
ALTER TABLE swarm.traces
    MODIFY TTL timestamp + INTERVAL 1 SECOND;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS swarm.trace_rules (
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
CREATE TABLE IF NOT EXISTS swarm.trace_part (
        trace_id UInt32,
        table String,
        chain String,
        jump_target String,
        handle UInt64,
        family String,
        ifin String,
        ifout String,
        mac_s String,
        mac_d String,
        ip_s String,
        ip_d String,
        sport UInt32,
        dport UInt32,
        len UInt32,
        ip_proto String,
        agent_id String,
        timestamp DateTime DEFAULT now()
    ) ENGINE = MergeTree 
    PARTITION BY agent_id
    TTL timestamp + INTERVAL 1 DAY DELETE
    ORDER BY (timestamp, trace_id, handle);
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

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS swarm.tracepart_mv;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS swarm.rules_mv;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS swarm.trace_part;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS swarm.trace_rules;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE swarm.traces
    MODIFY TTL timestamp + INTERVAL 1 DAY;
-- +goose StatementEnd
