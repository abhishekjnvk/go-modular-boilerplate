package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"go-boilerplate/internal/app/config"
	"go-boilerplate/migration"
)

func main() {
	cfg, err := config.LoadConfig("./configs")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	var dir string
	var target string
	flag.StringVar(&dir, "dir", "up", "direction: up or down")
	flag.StringVar(&target, "target", "", "target migration id when running down")
	flag.Parse()

	fmt.Println("direction:", dir)
	switch dir {
	case "up":
		if err := migration.ApplyUp(cfg.DBURL); err != nil {
			fmt.Printf("migration up failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("migrations applied")
	case "down":
		if target == "" {
			fmt.Fprintln(os.Stderr, "down migrations require --target to be provided (e.g. --target 001). Aborting to avoid accidental rollbacks.")
			os.Exit(2)
		}
		if err := migration.ApplyDown(cfg.DBURL, target); err != nil {
			fmt.Printf("migration down failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("migrations rolled back")
	default:
		fmt.Println("unknown dir; use up or down")
		os.Exit(2)
	}
}
