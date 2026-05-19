use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;

use crate::config::DbPoolConfig;

const POOL_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);

pub async fn create_pool(database_url: &str, cfg: &DbPoolConfig) -> PgPool {
    // Disable sqlx's prepared-statement cache so we're safe under pgBouncer
    // transaction-pool mode. See Kick-Channel-Role/src/db.rs for the full
    // rationale.
    let connect_options = PgConnectOptions::from_str(database_url)
        .expect("invalid DATABASE_URL")
        .statement_cache_capacity(0);

    PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(cfg.min_connections)
        .acquire_timeout(Duration::from_secs(cfg.acquire_timeout_secs))
        .idle_timeout(Duration::from_secs(cfg.idle_timeout_secs))
        .max_lifetime(POOL_MAX_LIFETIME)
        .test_before_acquire(false)
        .connect_with(connect_options)
        .await
        .expect("Failed to connect to PostgreSQL")
}

/// Migrations are applied in order on startup. They are idempotent
/// (`CREATE … IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`, etc.) so a replica
/// that finds them already applied is a no-op.
///
/// When you add a migration file, add the matching entry here. The app will
/// NOT discover new migration files automatically.
pub async fn run_migrations(pool: &PgPool) {
    let migrations: &[(&str, &str)] = &[
        ("001", include_str!("../migrations/001_initial_schema.sql")),
        ("002", include_str!("../migrations/002_bsky_accounts.sql")),
        ("003", include_str!("../migrations/003_bsky_users.sql")),
        (
            "004",
            include_str!("../migrations/004_account_relations.sql"),
        ),
        ("005", include_str!("../migrations/005_lists_and_packs.sql")),
        ("006", include_str!("../migrations/006_jobs.sql")),
        ("007", include_str!("../migrations/007_guild_settings.sql")),
        (
            "008",
            include_str!("../migrations/008_guild_bsky_accounts.sql"),
        ),
    ];
    for (id, sql) in migrations {
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration {id} failed: {e}"));
    }
    tracing::info!("Applied {} migrations", migrations.len());
}
