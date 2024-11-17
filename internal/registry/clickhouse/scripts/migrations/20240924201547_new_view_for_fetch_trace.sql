-- +goose Up
-- +goose StatementBegin
CREATE VIEW IF NOT EXISTS swarm.vu_fetch_trace AS
SELECT trace.trace_id AS trace_id,
    rt.table_id AS table_id,
    rules.table AS table_name,
    rules.chain AS chain_name,
    rules.jump_target AS jump_target,
    rules.handle AS handle,
    rules.rule AS rule,
    rules.verdict AS verdict,
    trace.ifin AS ifin,
    trace.ifout AS ifout,
    trace.family AS family,
    trace.ip_proto AS ip_proto,
    trace.len AS len,
    trace.mac_s as mac_s,
    trace.mac_d as mac_d,
    trace.ip_s AS ip_s,
    trace.ip_d AS ip_d,
    trace.sport AS sport,
    trace.dport AS dport,
    trace.sgname_s AS sgname_s,
    trace.sgname_d AS sgname_d,
    trace.sgnet_s AS sgnet_s,
    trace.sgnet_d AS sgnet_d,
    trace.agent_id AS agent_id,
    trace.timestamp AS timestamp
FROM swarm.trace_part AS trace
    JOIN swarm.trace_rules AS rules ON trace.rule_id = rules.rule_id
    JOIN swarm.rule_to_table AS rt ON trace.rule_id = rt.rule_id;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP VIEW IF EXISTS swarm.vu_fetch_trace;
-- +goose StatementEnd