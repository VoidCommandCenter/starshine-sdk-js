#!/bin/sh
set -eu

secret_dir=/run/secrets/starshine
umask 077
mkdir -p "$secret_dir"

if [ -n "${STARSHINE_WALLET_JSON:-}" ]; then
    if [ -n "${STARSHINE_WALLET_FILE:-}" ]; then
        echo "configure STARSHINE_WALLET_JSON or STARSHINE_WALLET_FILE, not both" >&2
        exit 1
    fi
    wallet_path="$secret_dir/wallet.json"
    printf '%s' "$STARSHINE_WALLET_JSON" > "$wallet_path"
    export STARSHINE_WALLET_FILE="$wallet_path"
    unset STARSHINE_WALLET_JSON
fi

if [ -n "${STARSHINE_RELAY_OUTBOX_KEY:-}" ]; then
    if [ -n "${STARSHINE_RELAY_OUTBOX_KEY_FILE:-}" ]; then
        echo "configure STARSHINE_RELAY_OUTBOX_KEY or STARSHINE_RELAY_OUTBOX_KEY_FILE, not both" >&2
        exit 1
    fi
    outbox_key_path="$secret_dir/outbox-key"
    printf '%s' "$STARSHINE_RELAY_OUTBOX_KEY" > "$outbox_key_path"
    export STARSHINE_RELAY_OUTBOX_KEY_FILE="$outbox_key_path"
    unset STARSHINE_RELAY_OUTBOX_KEY
fi

if [ -n "${STARSHINE_RELAY_BEARER_TOKEN:-}" ]; then
    if [ -n "${STARSHINE_RELAY_BEARER_TOKEN_FILE:-}" ]; then
        echo "configure STARSHINE_RELAY_BEARER_TOKEN or STARSHINE_RELAY_BEARER_TOKEN_FILE, not both" >&2
        exit 1
    fi
    bearer_token_path="$secret_dir/bearer-token"
    printf '%s' "$STARSHINE_RELAY_BEARER_TOKEN" > "$bearer_token_path"
    export STARSHINE_RELAY_BEARER_TOKEN_FILE="$bearer_token_path"
    unset STARSHINE_RELAY_BEARER_TOKEN
fi

if [ -z "${STARSHINE_RELAY_PORT:-}" ] && [ -n "${PORT:-}" ]; then
    export STARSHINE_RELAY_PORT="$PORT"
fi

exec "$@"
