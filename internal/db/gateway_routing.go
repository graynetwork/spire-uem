package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// GatewayNotifyChannel is the Postgres LISTEN/NOTIFY channel used to route gateway
// push/trigger frames to the instance that holds a device's WebSocket.
const GatewayNotifyChannel = "spire_gateway"

// staleInstanceTTL bounds how long a device's recorded WS ownership is trusted without a
// heartbeat from the owning instance. Beyond this the ownership is treated as stale.
const staleInstanceTTL = 90 * time.Second

// RegisterServerInstance records (or refreshes) this instance's heartbeat row.
func (r *Repository) RegisterServerInstance(ctx context.Context, instanceID, listenAddr string) error {
	const q = `
		INSERT INTO server_instances (instance_id, listen_addr, started_at, last_seen_at)
		VALUES ($1, $2, NOW(), NOW())
		ON CONFLICT (instance_id) DO UPDATE
		SET listen_addr = EXCLUDED.listen_addr, last_seen_at = NOW()`
	if _, err := r.pool.Exec(ctx, q, instanceID, listenAddr); err != nil {
		return fmt.Errorf("register server instance: %w", err)
	}
	return nil
}

// HeartbeatServerInstance refreshes this instance's last_seen_at.
func (r *Repository) HeartbeatServerInstance(ctx context.Context, instanceID string) error {
	_, err := r.pool.Exec(ctx, `UPDATE server_instances SET last_seen_at = NOW() WHERE instance_id = $1`, instanceID)
	return err
}

// DeregisterServerInstance removes this instance's row and clears any device ownership it
// still holds (clean shutdown).
func (r *Repository) DeregisterServerInstance(ctx context.Context, instanceID string) error {
	if _, err := r.pool.Exec(ctx,
		`UPDATE devices SET ws_instance_id = NULL, ws_owned_at = NULL WHERE ws_instance_id = $1`, instanceID); err != nil {
		return fmt.Errorf("clear device ownership for instance: %w", err)
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM server_instances WHERE instance_id = $1`, instanceID)
	return err
}

// SetDeviceWSOwner marks a device's WebSocket as held by instanceID and sets ws_connected.
func (r *Repository) SetDeviceWSOwner(ctx context.Context, deviceID, instanceID string) error {
	const q = `
		UPDATE devices
		SET ws_connected = true, ws_instance_id = $2, ws_owned_at = NOW(),
		    last_ws_seen_at = NOW(), updated_at = NOW()
		WHERE id = $1`
	_, err := r.pool.Exec(ctx, q, deviceID, instanceID)
	return err
}

// ClearDeviceWSOwner clears ownership only if instanceID still holds it, so a reconnect to a
// different instance (which already took ownership) is not clobbered by a late disconnect.
func (r *Repository) ClearDeviceWSOwner(ctx context.Context, deviceID, instanceID string) error {
	const q = `
		UPDATE devices
		SET ws_connected = false, ws_instance_id = NULL, ws_owned_at = NULL, updated_at = NOW()
		WHERE id = $1 AND ws_instance_id = $2`
	_, err := r.pool.Exec(ctx, q, deviceID, instanceID)
	return err
}

// GetDeviceWSOwner returns the instance id currently holding the device's socket and
// whether that ownership is fresh (heartbeat within staleInstanceTTL). An empty owner
// means the device is not connected anywhere.
func (r *Repository) GetDeviceWSOwner(ctx context.Context, deviceID string) (owner string, fresh bool, err error) {
	const q = `
		SELECT COALESCE(ws_instance_id, ''), ws_owned_at
		FROM devices WHERE id = $1`
	var ownedAt *time.Time
	if err := r.pool.QueryRow(ctx, q, deviceID).Scan(&owner, &ownedAt); err != nil {
		if err == pgx.ErrNoRows {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get device ws owner: %w", err)
	}
	if owner == "" || ownedAt == nil {
		return "", false, nil
	}
	fresh = time.Since(*ownedAt) <= staleInstanceTTL
	return owner, fresh, nil
}

// PublishGatewayNotify sends a NOTIFY on the gateway channel. The payload is an opaque
// string (the gateway layer encodes a JSON routing command). Postgres caps NOTIFY payloads
// at 8000 bytes, which is ample for a routing envelope that carries IDs, not bulk data.
func (r *Repository) PublishGatewayNotify(ctx context.Context, payload string) error {
	if _, err := r.pool.Exec(ctx, `SELECT pg_notify($1, $2)`, GatewayNotifyChannel, payload); err != nil {
		return fmt.Errorf("pg_notify gateway: %w", err)
	}
	return nil
}

// ListenGateway opens a dedicated connection, issues LISTEN on the gateway channel, and
// invokes handle for every notification until ctx is cancelled. It reconnects on error with
// a short backoff. The connection is dedicated (not pooled) because LISTEN state is
// per-connection.
func (r *Repository) ListenGateway(ctx context.Context, handle func(payload string)) {
	for ctx.Err() == nil {
		conn, err := r.pool.Acquire(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		if _, err := conn.Exec(ctx, "LISTEN "+GatewayNotifyChannel); err != nil {
			conn.Release()
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		for ctx.Err() == nil {
			n, err := conn.Conn().WaitForNotification(ctx)
			if err != nil {
				break // connection error or ctx cancelled; reconnect
			}
			if n != nil {
				handle(n.Payload)
			}
		}
		conn.Release()
	}
}
