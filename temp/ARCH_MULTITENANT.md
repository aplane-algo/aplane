# Superseded: multitenant architecture

Status: superseded 2026-08-16.

APlane is now intentionally designed as a single-operator,
single-signing-identity product. The former working multi-identity backend is
being removed rather than retained as dormant product infrastructure.

See [single-tenant.md](single-tenant.md) for the decision, compatibility
posture, target invariants, and implementation slices. A future multitenant
product must introduce an explicit tenant composition and authorization layer;
this document is retained only as historical context.
