-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS swarm.nftables_tmp (
    table_name String,
    table_family String,
    chain_name String,
    rule String,
    table_str String,
    timestamp DateTime DEFAULT now()
) ENGINE = MergeTree TTL timestamp + INTERVAL 1 SECOND DELETE
ORDER BY tuple();
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS swarm.rule_to_table (
    rule_id UInt64,
    table_id UInt64,
    timestamp DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(timestamp)
ORDER BY (table_id, rule_id);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS swarm.nftables (
    table_id UInt64,
    table_str String,
    timestamp DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(timestamp)
ORDER BY (table_id);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE MATERIALIZED VIEW swarm.rule_to_table_mv TO swarm.rule_to_table AS
SELECT sipHash64(table_name, table_family, chain_name, rule) as rule_id,
    sipHash64(table_str) as table_id,
    timestamp
FROM swarm.nftables_tmp;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE MATERIALIZED VIEW swarm.nftables_mv TO swarm.nftables AS
SELECT sipHash64(table_str) as table_id,
    table_str,
    timestamp
FROM swarm.nftables_tmp;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS swarm.rule_to_table_mv;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS swarm.nftables_mv;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS swarm.nftables_tmp;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS swarm.rule_to_table;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS swarm.nftables;
-- +goose StatementEnd