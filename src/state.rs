use std::sync::Arc;

use ::config::Config;
use mail_send::{SmtpClient, SmtpClientBuilder};
use sqlx::{Pool, MySql, mysql::MySqlPoolOptions};
use tokio::{net::TcpStream, sync::Mutex};
use tokio_rustls::client::TlsStream;

use crate::{config, geolocate};

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool<MySql>,
    pub smtp: Arc<Mutex<SmtpClient<TlsStream<TcpStream>>>>,
    pub mmdb_data: Arc<Vec<u8>>,
    pub config: Config,
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

    let (smtp_host, smtp_port, smtp_username, smtp_password) = config::get_smtp_config(&config).expect("Valid SMTP configuration");
    let smtp = Arc::new(Mutex::new(
        SmtpClientBuilder::new(smtp_host, smtp_port)
            .implicit_tls(false)
            .credentials((smtp_username, smtp_password))
            .connect()
            .await
            .expect("Connecting to the SMTP server."),
    ));

    tracing::info!("Loaded MMDB ({}b)", mmdb_data.len());

    AppState {
        pool,
        smtp,
        mmdb_data,
        config,
    }
}