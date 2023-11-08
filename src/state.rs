use std::{sync::Arc, collections::HashMap};

use ::config::Config;
use mail_send::{SmtpClient, SmtpClientBuilder};
use sqlx::{Pool, MySql, mysql::MySqlPoolOptions};
use tokio::{net::TcpStream, sync::{Mutex, RwLock}};
use tokio_rustls::client::TlsStream;

use crate::{config, geolocate};

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool<MySql>,
    pub mmdb_data: Arc<Vec<u8>>,
    pub config: Config,
    pub verification_tokens: Arc<RwLock<HashMap<String, String>>>,
}

pub async fn init_state() -> AppState {
    let config = config::init_config();

    let db_url = config
        .get_string(config::DB_URL)
        .expect("Database configuration should have a connection string.");
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&db_url)
        .await
        .expect("Connecting to MySql DB");

    let mmdb_data = Arc::new(geolocate::load_mmdb_data().expect("Loading MMDB data"));

    tracing::info!("Loaded MMDB ({}b)", mmdb_data.len());

    let verification_tokens = Arc::new(RwLock::new(HashMap::new()));

    AppState {
        pool,
        mmdb_data,
        config,
        verification_tokens,
    }
}