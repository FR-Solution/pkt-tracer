-- +goose Up
-- +goose StatementBegin
DROP VIEW IF EXISTS swarm.rules_mv;
-- +goose StatementEnd
-- +goose StatementBegin
DROP VIEW IF EXISTS swarm.tracepart_mv;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE swarm.traces DROP COLUMN IF EXISTS hash_rule;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS swarm.trace_rules_new (
    rule_id UInt64,
    table String,
    chain String,
    jump_target String,
    handle UInt64,
    rule String,
    verdict String,
    agent_id String,
    timestamp DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(timestamp) PARTITION BY agent_id TTL timestamp + INTERVAL 1 DAY DELETE
ORDER BY (rule_id);
-- +goose StatementEnd
-- +goose StatementBegin
INSERT INTO swarm.trace_rules_new (
        rule_id,
        table,
        chain,
        jump_target,
        handle,
        rule,
        verdict,
        agent_id,
        timestamp
    )
SELECT rules.hash_rule,
    tracepart.table,
    tracepart.chain,
    tracepart.jump_target,
    rules.handle,
    rules.rule,
    rules.verdict,
    rules.agent_id,
    timestamp
FROM swarm.trace_part AS tracepart
    LEFT JOIN swarm.trace_rules AS rules ON tracepart.handle = rules.handle
    AND tracepart.verdict = rules.verdict;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE swarm.trace_rules;
-- +goose StatementEnd
-- +goose StatementBegin
RENAME TABLE swarm.trace_rules_new TO swarm.trace_rules;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS swarm.trace_part_new (
    trace_id UInt32,
    rule_id UInt64,
    family String,
    ifin String,
    ifout String,
    mac_s String,
    mac_d String,
    ip_s String,
    ip_d String,
    sport UInt32,
    dport UInt32,
    sgname_s String,
    sgname_d String,
    sgnet_s String,
    sgnet_d String,
    len UInt32,
    ip_proto String,
    agent_id String,
    timestamp DateTime DEFAULT now()
) ENGINE = MergeTree PARTITION BY agent_id TTL timestamp + INTERVAL 1 DAY DELETE
ORDER BY (
        timestamp,
        trace_id,
        rule_id
    );
-- +goose StatementEnd
-- +goose StatementBegin
INSERT INTO swarm.trace_part_new (
        trace_id,
        rule_id,
        family,
        ifin,
        ifout,
        mac_s,
        mac_d,
        ip_s,
        ip_d,
        sport,
        dport,
        sgname_s,
        sgname_d,
        sgnet_s,
        sgnet_d,
        len,
        ip_proto,
        agent_id,
        timestamp
    )
SELECT trace_id,
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
    sgname_s,
    sgname_d,
    sgnet_s,
    sgnet_d,
    len,
    ip_proto,
    agent_id,
    timestamp
FROM swarm.trace_part;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE swarm.trace_part;
-- +goose StatementEnd
-- +goose StatementBegin
RENAME TABLE swarm.trace_part_new TO swarm.trace_part;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE MATERIALIZED VIEW swarm.tracepart_mv TO swarm.trace_part AS
SELECT trace_id,
    sipHash64(table, family, chain, rule) as rule_id,
    family,
    ifin,
    ifout,
    mac_s,
    mac_d,
    ip_s,
    ip_d,
    sport,
    dport,
    sgname_s,
    sgname_d,
    sgnet_s,
    sgnet_d,
    len,
    ip_proto,
    agent_id,
    timestamp
FROM swarm.traces;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE MATERIALIZED VIEW swarm.rules_mv TO swarm.trace_rules AS
SELECT handle,
    table,
    chain,
    jump_target,
    verdict,
    rule,
    sipHash64(table, family, chain, rule) as rule_id,
    agent_id,
    timestamp
FROM swarm.traces;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP VIEW IF EXISTS swarm.rules_mv;
-- +goose StatementEnd
-- +goose StatementBegin
DROP VIEW IF EXISTS swarm.tracepart_mv;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE swarm.traces
ADD COLUMN IF NOT EXISTS hash_rule UInt64;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS swarm.trace_part_old (
    trace_id UInt32,
    hash_rule UInt64,
    table String,
    chain String,
    jump_target String,
    verdict String,
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
    sgname_s String,
    sgname_d String,
    sgnet_s String,
    sgnet_d String,
    len UInt32,
    ip_proto String,
    agent_id String,
    timestamp DateTime DEFAULT now()
) ENGINE = MergeTree PARTITION BY agent_id TTL timestamp + INTERVAL 1 DAY DELETE
ORDER BY (timestamp, trace_id, handle);
-- +goose StatementEnd
-- +goose StatementBegin
INSERT INTO swarm.trace_part_old (
        trace_id,
        hash_rule,
        table,
        chain,
        jump_target,
        verdict,
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
        sgname_s,
        sgname_d,
        sgnet_s,
        sgnet_d,
        len,
        ip_proto,
        agent_id,
        timestamp
    )
SELECT tracepart.trace_id,
    tracepart.rule_id,
    rules.table,
    rules.chain,
    rules.jump_target,
    rules.verdict,
    rules.handle,
    tracepart.family,
    tracepart.ifin,
    tracepart.ifout,
    tracepart.mac_s,
    tracepart.mac_d,
    tracepart.ip_s,
    tracepart.ip_d,
    tracepart.sport,
    tracepart.dport,
    tracepart.sgname_s,
    tracepart.sgname_d,
    tracepart.sgnet_s,
    tracepart.sgnet_d,
    tracepart.len,
    tracepart.ip_proto,
    tracepart.agent_id,
    tracepart.timestamp
FROM swarm.trace_part AS tracepart
    LEFT JOIN swarm.trace_rules AS rules ON tracepart.rule_id = rules.rule_id;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE swarm.trace_part;
-- +goose StatementEnd
-- +goose StatementBegin
RENAME TABLE swarm.trace_part_old TO swarm.trace_part;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS swarm.trace_rules_old (
    handle UInt64,
    verdict String,
    rule String,
    hash_rule UInt64,
    agent_id String,
    timestamp DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(timestamp) PARTITION BY agent_id TTL timestamp + INTERVAL 1 DAY DELETE
ORDER BY (handle, hash_rule, verdict);
-- +goose StatementEnd
-- +goose StatementBegin
INSERT INTO swarm.trace_rules_old (
        handle,
        verdict,
        rule,
        hash_rule,
        agent_id,
        timestamp
    )
SELECT handle,
    verdict,
    rule,
    rule_id,
    agent_id,
    timestamp
FROM swarm.trace_rules;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE swarm.trace_rules;
-- +goose StatementEnd
-- +goose StatementBegin
RENAME TABLE swarm.trace_rules_old TO swarm.trace_rules;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE MATERIALIZED VIEW swarm.tracepart_mv TO swarm.trace_part AS
SELECT trace_id,
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
    sgname_s,
    sgname_d,
    sgnet_s,
    sgnet_d,
    len,
    ip_proto,
    agent_id,
    verdict,
    timestamp
FROM swarm.traces;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE MATERIALIZED VIEW swarm.rules_mv TO swarm.trace_rules AS
SELECT handle,
    verdict,
    rule,
    hash_rule,
    agent_id,
    timestamp
FROM swarm.traces;
-- +goose StatementEnd