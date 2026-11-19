package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/campaign"
)

// DeferCampaignForDevice records a user deferral for a device using the campaign's own max
// deferral count and deadline. It returns (used, left, granted). A granted=false means the
// deferral was refused (max reached or deadline passed); the install proceeds without a
// deferral in that case. The campaign must be RUNNING.
func (r *Repository) DeferCampaignForDevice(ctx context.Context, campaignID, deviceID string, now time.Time) (used, left int, granted bool, err error) {
	c, err := r.GetCampaign(ctx, campaignID)
	if err != nil {
		return 0, 0, false, err
	}
	if c == nil {
		return 0, 0, false, errors.New("campaign not found")
	}
	if c.State != campaign.StateRunning {
		return 0, 0, false, nil
	}
	used, granted, err = r.RecordDeferral(ctx, campaignID, deviceID, c.MaxDeferrals, c.DeadlineAt, now)
	if err != nil {
		return 0, 0, false, err
	}
	left = c.MaxDeferrals - used
	if left < 0 {
		left = 0
	}
	return used, left, granted, nil
}

// GetCampaignWorkState returns a device's current work state in a campaign, or ("",false) if
// there is no work row.
func (r *Repository) GetCampaignWorkState(ctx context.Context, campaignID, deviceID string) (campaign.DeviceWorkState, bool, error) {
	var s string
	err := r.pool.QueryRow(ctx, `SELECT state FROM campaign_device_work WHERE campaign_id=$1 AND device_id=$2`, campaignID, deviceID).Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return campaign.DeviceWorkState(s), true, nil
}
