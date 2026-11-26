use anyhow::{Context, Result};
use ark_watchtower::bounty::{BountyScript, BountySpec};
use ark_watchtower::client::{EsploraClient, HttpArkIndexer};
use ark_watchtower::config::Config;
use ark_watchtower::nostr_io;
use ark_watchtower::service::{now, WatchtowerService};
use ark_watchtower::storage::{WatchtowerPackage, WatchtowerStorage};
use ark_watchtower::wallet::{parse_network, WatchtowerWallet};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(version, about = "Keyless Ark watchtower with tiered Taproot exit bounties (p2pFiat Experiment 13)")]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new independent P2TR watchtower fee wallet key.
    Init,
    /// Show watchtower pubkey (for bounty scripts & NIP-17), P2TR funding address, and profit summary.
    Info,
    /// Validate and register a JSON WatchtowerPackage file locally.
    Register { file: PathBuf },
    /// List all watched contracts and their states/accounting as JSON.
    List,
    /// Run the watchtower loop (Nostr NIP-17 intake + external oracle kind-89 sync + Esplora).
    Run {
        /// Run a single tick and exit.
        #[arg(long)]
        once: bool,
    },
    /// Compile a tiered Taproot bounty script and print its scriptPubKey and address.
    BountyScript {
        #[arg(long)]
        primary: String,
        #[arg(long)]
        backup: Vec<String>,
        #[arg(long, default_value_t = 4)]
        backup_csv: u16,
        #[arg(long, default_value_t = 5000)]
        amount: u64,
        #[arg(long, default_value = "bitcoin")]
        network: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    if let Cmd::BountyScript { primary, backup, backup_csv, amount, network } = cli.cmd {
        let net = parse_network(&network)?;
        let compiled = BountyScript::compile(BountySpec {
            amount_sats: amount,
            vout: 2,
            primary_pubkey: primary,
            backup_pubkeys: backup,
            backup_csv,
        })?;
        let addr = kormir::bitcoin::Address::from_script(&compiled.script_pubkey, net)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "address": addr.to_string(),
                "script_pubkey": hex::encode(compiled.script_pubkey.as_bytes()),
                "output_key": compiled.spend_info.output_key().to_x_only_public_key().to_string(),
                "backup_csv": backup_csv,
                "amount_sats": amount,
            }))?
        );
        return Ok(());
    }

    let cfg = Config::load(&cli.config)?;
    let net = parse_network(&cfg.network)?;

    match cli.cmd {
        Cmd::Init => {
            let wallet = WatchtowerWallet::generate_and_save(&cfg.wallet_key_file, net)?;
            WatchtowerStorage::open(&cfg.db_file)?;
            println!(
                "created {:?}\npubkey (bounty script & Nostr): {}\nP2TR fee wallet address ({}): {}",
                cfg.wallet_key_file, wallet.xonly_pubkey, cfg.network, wallet.address
            );
        }
        Cmd::Info => {
            let svc = open_service(cfg, net)?;
            println!("{}", serde_json::to_string_pretty(&svc.summary())?);
        }
        Cmd::Register { file } => {
            let svc = open_service(cfg, net)?;
            let raw = std::fs::read_to_string(&file).with_context(|| format!("read {file:?}"))?;
            let pkg: WatchtowerPackage =
                serde_json::from_str(&raw).with_context(|| format!("parse {file:?}"))?;
            let id = pkg.id.clone();
            let role = svc.register_package(pkg, now())?;
            println!("registered watchtower package {id} (role: {role:?})");
        }
        Cmd::List => {
            let storage = WatchtowerStorage::open(&cfg.db_file)?;
            println!("{}", serde_json::to_string_pretty(&storage.list())?);
        }
        Cmd::Run { once } => {
            let tick = Duration::from_secs(cfg.tick_secs);
            let relays = cfg.relays.clone();
            let accept_nostr = cfg.accept_nostr_packages;
            let svc = open_service(cfg, net)?;
            log::info!(
                "ark-watchtower started (pubkey {}, address {})",
                svc.wallet.xonly_pubkey,
                svc.wallet.address
            );
            let nostr = if !relays.is_empty() {
                Some(nostr_io::connect_client(svc.wallet.nostr_keys(), &relays).await?)
            } else {
                None
            };
            let http = reqwest::Client::builder()
                .user_agent(concat!("ark-watchtower/", env!("CARGO_PKG_VERSION")))
                .build()?;
            loop {
                let t = now();
                let mut attestations = HashMap::new();
                let mut dispute_txs = HashMap::new();
                if let Some(client) = &nostr {
                    if accept_nostr {
                        if let Err(e) = nostr_io::process_incoming_packages(client, &svc, t).await {
                            log::warn!("NIP-17 intake: {e:#}");
                        }
                    }
                    match nostr_io::fetch_external_attestations(client, &svc).await {
                        Ok(map) => attestations = map,
                        Err(e) => log::warn!("fetch oracle attestations: {e:#}"),
                    }
                    match nostr_io::resolve_pending_disputes(client, &http, &svc, t).await {
                        Ok(map) => dispute_txs = map,
                        Err(e) => log::warn!("resolve Leaf 2 disputes: {e:#}"),
                    }
                }
                if let Err(e) = svc.tick_with_disputes(&attestations, &dispute_txs, t).await {
                    log::error!("watchtower tick: {e:#}");
                }
                if once {
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(tick) => {}
                    _ = tokio::signal::ctrl_c() => { log::info!("shutting down"); break; }
                }
            }
        }
        Cmd::BountyScript { .. } => unreachable!(),
    }
    Ok(())
}

fn open_service(cfg: Config, net: kormir::bitcoin::Network) -> Result<WatchtowerService> {
    let wallet = WatchtowerWallet::load(&cfg.wallet_key_file, net)
        .with_context(|| format!("load {:?} (run `ark-watchtower init` first)", cfg.wallet_key_file))?;
    let storage = WatchtowerStorage::open(&cfg.db_file)?;
    let http = reqwest::Client::builder()
        .user_agent(concat!("ark-watchtower/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let chain = Arc::new(EsploraClient::new(http.clone(), cfg.esplora_url.clone()));
    let indexer = Arc::new(HttpArkIndexer::new(http));
    Ok(WatchtowerService::new(cfg, wallet, storage, chain, indexer))
}
