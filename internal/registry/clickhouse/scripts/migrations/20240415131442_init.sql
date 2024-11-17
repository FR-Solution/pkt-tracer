-- +goose Up
-- +goose StatementBegin
CREATE DATABASE IF NOT EXISTS swarm;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS swarm.traces (
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
    verdict String,
    rule String,
    agent_id String,
    timestamp DateTime DEFAULT now()
) ENGINE = MergeTree PARTITION BY agent_id TTL timestamp + INTERVAL 1 DAY DELETE
ORDER BY (timestamp, trace_id, handle);
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE swarm.traces;
-- +goose StatementEnd
-- +goose StatementBegin
DROP DATABASE IF EXISTS swarm;
-- +goose StatementEnd