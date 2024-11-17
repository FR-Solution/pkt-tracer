-- +goose Up
-- +goose StatementBegin
ALTER TABLE swarm.traces ADD COLUMN IF NOT EXISTS sgname_s String;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE swarm.trace_part ADD COLUMN IF NOT EXISTS sgname_s String;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE swarm.traces ADD COLUMN IF NOT EXISTS sgname_d String;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE swarm.trace_part ADD COLUMN IF NOT EXISTS sgname_d String;
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
    sgname_s,
    sgname_d,
    len,
    ip_proto,
    agent_id,
    timestamp
FROM swarm.traces;
-- +goose StatementEnd



-- +goose Down
-- +goose StatementBegin
DROP VIEW IF EXISTS swarm.tracepart_mv;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE swarm.traces DROP COLUMN IF EXISTS sgname_s;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE swarm.trace_part DROP COLUMN IF EXISTS sgname_s;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE swarm.traces DROP COLUMN IF EXISTS sgname_d;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE swarm.trace_part DROP COLUMN IF EXISTS sgname_d;
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