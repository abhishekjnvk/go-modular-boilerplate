# Architecture Overview

This project uses a Clean Architecture-inspired layout with clear separation between delivery (HTTP), service (business logic), and repository (data access) layers.

Key points:
- `cmd/` contains application entry points (`api`, `worker`).
- `internal/pkg/<feature>/` contains feature packages with layers: `delivery/`, `service/`, `repository/`.
- `internal/shared/` contains cross-cutting concerns: `database`, `cache`, `logger`, `middleware`, `utils`, `metrics`.
- Wiring (dependency injection) is centralized in `cmd/api/main.go` following: Config → Logger → DB → Repos → Services → Handlers → Server.

Conventions:
- Package names should be lowercase and singular (e.g., `user`, `auth`).
- Constructors: `NewXxx(...)` should be provided for repositories, services and handlers.
- Domain types live in feature root (e.g., `internal/pkg/auth/auth_types.go`).
- Delivery layer should only depend on service interfaces and shared utils.

