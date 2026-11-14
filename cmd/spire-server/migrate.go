package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"text/tabwriter"

	"github.com/spire-uem/spire-uem/internal/config"
	"github.com/spire-uem/spire-uem/internal/db"
)

// runMigrateSubcommand implements `spire-server migrate <status|up|down>`.
// It is dispatched from main() when the first CLI argument is "migrate", and always
// exits the process (it never returns to the server boot path).
func runMigrateSubcommand(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to YAML configuration file")
	downN := fs.Int("n", 1, "down: number of migrations to roll back")
	confirm := fs.Bool("confirm", false, "down: required confirmation flag for the destructive rollback")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: spire-server migrate <command> [flags]

Commands:
  status        Show every migration and whether it has been applied.
  up            Apply all pending migrations (same as the automatic boot-time run).
  down          Roll back the last N applied migrations (requires --confirm). N defaults to 1.

Flags:
`)
		fs.PrintDefaults()
	}

	if len(args) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	sub := args[0]
	_ = fs.Parse(args[1:])

	cfg := config.Load(*configPath)
	ctx := context.Background()

	pool, err := db.NewPool(ctx, cfg.Server.DatabaseURL)
	if err != nil {
		log.Fatalf("[spire-server migrate] database connection failed: %v", err)
	}
	defer pool.Close()

	switch sub {
	case "status":
		statuses, err := db.MigrationStatuses(ctx, pool, cfg.Server.MigrationsPath)
		if err != nil {
			log.Fatalf("[spire-server migrate] status failed: %v", err)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "VERSION\tSTATUS\tNAME\tAPPLIED_AT")
		pending := 0
		for _, s := range statuses {
			state := "pending"
			appliedAt := "-"
			if s.Applied {
				state = "applied"
				if s.AppliedRecord != nil {
					appliedAt = s.AppliedRecord.AppliedAt.Format("2006-01-02 15:04:05Z07:00")
				}
				if s.ChecksumDrift {
					state = "applied(DRIFT!)"
				}
			} else {
				pending++
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Version, state, s.Name, appliedAt)
		}
		tw.Flush()
		fmt.Printf("\n%d migration(s), %d pending\n", len(statuses), pending)

	case "up":
		applied, err := db.MigrateUp(ctx, pool, cfg.Server.MigrationsPath, log.Printf)
		if err != nil {
			log.Fatalf("[spire-server migrate] up failed: %v", err)
		}
		if len(applied) == 0 {
			fmt.Println("No pending migrations; schema is up to date.")
		} else {
			fmt.Printf("Applied %d migration(s): %v\n", len(applied), applied)
		}

	case "down":
		if !*confirm {
			log.Fatalf("[spire-server migrate] down is destructive and refused without --confirm (would roll back the last %d migration(s))", *downN)
		}
		reverted, err := db.MigrateDown(ctx, pool, cfg.Server.MigrationsPath, *downN, log.Printf)
		if err != nil {
			log.Fatalf("[spire-server migrate] down failed after reverting %v: %v", reverted, err)
		}
		fmt.Printf("Rolled back %d migration(s): %v\n", len(reverted), reverted)

	default:
		fs.Usage()
		os.Exit(2)
	}
	os.Exit(0)
}
