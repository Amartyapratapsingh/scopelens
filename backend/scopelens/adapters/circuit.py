"""Shared provider circuit breakers. Redis serializes cooldown and recovery probes."""

import hashlib
import json
import uuid
from dataclasses import dataclass
from functools import lru_cache

from redis import Redis

ACQUIRE = """
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local epoch = redis.call('HGET', KEYS[1], 'epoch') or ARGV[1]
redis.call('HSETNX', KEYS[1], 'epoch', epoch)
redis.call('EXPIRE', KEYS[1], 86400)
local opened = tonumber(redis.call('HGET', KEYS[1], 'until') or '0')
if opened > now then return {} end
if opened > 0 then
  local probe_until = tonumber(redis.call('HGET', KEYS[1], 'probe_until') or '0')
  if probe_until > now then return {} end
  redis.call('HSET', KEYS[1], 'probe', ARGV[1], 'probe_until', now + tonumber(ARGV[2]))
  return {epoch, ARGV[1]}
end
return {epoch, ''}
"""
FINISH = """
if redis.call('HGET', KEYS[1], 'epoch') ~= ARGV[1] then return 0 end
if ARGV[2] ~= '' and redis.call('HGET', KEYS[1], 'probe') ~= ARGV[2] then return 0 end
if ARGV[3] == 'success' then
  redis.call('HSET', KEYS[1], 'failures', 0, 'until', 0, 'epoch', ARGV[6])
  redis.call('HDEL', KEYS[1], 'probe', 'probe_until')
else
  local failures = redis.call('HINCRBY', KEYS[1], 'failures', 1)
  if ARGV[2] ~= '' or failures >= tonumber(ARGV[4]) then
    local t = redis.call('TIME')
    local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
    redis.call('HSET', KEYS[1], 'until', now + tonumber(ARGV[5]), 'epoch', ARGV[6])
    redis.call('HDEL', KEYS[1], 'probe', 'probe_until')
  end
end
redis.call('EXPIRE', KEYS[1], 86400)
return 1
"""


@dataclass(frozen=True)
class Ticket:
    key: str
    epoch: str
    probe: str


class ProviderCircuit:
    def __init__(self, redis, *, prefix="scopelens:model-circuit:v1:", threshold=2, cooldown=60):
        self.redis = redis
        self.prefix = prefix
        self.threshold = threshold
        self.cooldown = cooldown

    def key(self, route):
        # Credential isolation without putting keys or provider URLs into Redis key names.
        identity = [
            route.base_url,
            route.model,
            route.api_key.get_secret_value() if route.api_key else "",
        ]
        return self.prefix + hashlib.sha256(json.dumps(identity).encode()).hexdigest()

    def acquire(self, route):
        key = self.key(route)
        grant = self.redis.eval(ACQUIRE, 1, key, uuid.uuid4().hex, route.timeout_seconds + 15)
        return Ticket(key, *grant) if grant else None

    def finish(self, ticket, *, success):
        self.redis.eval(
            FINISH,
            1,
            ticket.key,
            ticket.epoch,
            ticket.probe,
            "success" if success else "failure",
            self.threshold,
            self.cooldown,
            uuid.uuid4().hex,
        )


@lru_cache(maxsize=8)
def shared_circuit(redis_url):
    return ProviderCircuit(
        Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_timeout=1,
            socket_connect_timeout=1,
        )
    )
