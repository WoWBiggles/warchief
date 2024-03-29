use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sqlx::{MySql, Pool};
use thiserror::Error;

use crate::errors::AuthenticationError;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("missing values in DB: {0}")]
    MissingValues(String),
    #[error("SQL error: {0}")]
    SqlError(#[from] sqlx::Error),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum GmLevel {
    None = 0,
}

impl From<u8> for GmLevel {
    fn from(value: u8) -> Self {
        if value == 0 {
            GmLevel::None
        } else {
            GmLevel::None
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Account {
    pub id: u32,
    pub username: String,
    pub email_verified: bool,
    pub gmlevel: GmLevel,
    pub v: String,
    pub s: String,
    pub banned: bool,
}

pub async fn add_account(
    pool: &Pool<MySql>,
    username: &str,
    verifier_hex: &str,
    salt_hex: &str,
) -> Result<(), AuthenticationError> {
    // Check for existing account.
    if let Ok(existing_accounts) =
        sqlx::query!("SELECT id FROM account WHERE username = ?", username)
            .fetch_all(pool)
            .await
    {
        if !existing_accounts.is_empty() {
            return Err(AuthenticationError::ExistingUser);
        }
    }

    // Add the account to the database.
    sqlx::query!(
        "INSERT INTO account(username, v, s, joindate) VALUES (
      ?, ?, ?, NOW()
    )",
        username,
        verifier_hex,
        salt_hex
    )
    .execute(pool)
    .await?;

    sqlx::query!(
        "REPLACE INTO `realmcharacters` (`realmid`, `acctid`, `numchars`)
        SELECT `realmlist`.`id`, `account`.`id`, 0 FROM `realmlist`,`account`
        LEFT JOIN `realmcharacters` ON `acctid`=`account`.`id` WHERE `acctid` IS NULL"
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn verify_account(pool: &Pool<MySql>, username: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE account SET email_verif = 1 WHERE username = ?",
        username
    )
    .execute(pool)
    .await?;
    Ok(())
}

// TODO: Convert last two args to LoginResult enum.
pub async fn add_login_attempt(pool: &Pool<MySql>, id: &u32, ip: IpAddr, successful: bool, fail_reason: Option<&str>) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO warchief_login_attempts (id, ip, successful, fail_reason) VALUES (?, ?, ?, ?)",
        id,
        ip.to_string(),
        successful,
        fail_reason
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_srp_values(
    pool: &Pool<MySql>,
    username: &str,
    verifier_hex: &str,
    salt_hex: &str,
) -> Result<(), AuthenticationError> {
    sqlx::query!(
        "UPDATE account SET v = ?, s = ? WHERE username = ?",
        verifier_hex,
        salt_hex,
        username,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_account(
    pool: &Pool<MySql>,
    username: &str,
) -> Result<Account, DatabaseError> {
    match sqlx::query!("SELECT a.id, a.username, a.gmlevel, a.v, a.s, a.email_verif, ab.banid as `ban_id?` FROM account a LEFT JOIN account_banned ab ON ab.id = a.id AND ab.unbandate > UNIX_TIMESTAMP(NOW()) WHERE username = ?", username)
            .fetch_one(pool)
            .await
    {
        Ok(account) => {
            Ok(Account {
                id: account.id,
                username: account.username,
                email_verified: account.email_verif == 1,
                gmlevel: account.gmlevel.into(),
                v: account.v.ok_or(DatabaseError::MissingValues(String::from("v")))?,
                s: account.s.ok_or(DatabaseError::MissingValues(String::from("s")))?,
                banned: account.ban_id.is_some(),
            })
        },
        Err(e) => Err(DatabaseError::SqlError(e)),
    }
}

pub async fn is_ip_banned(pool: &Pool<MySql>, ip: IpAddr) -> bool {
    let record = sqlx::query!("SELECT ip as `ip?` FROM ip_banned WHERE unbandate IS null OR unbandate > UNIX_TIMESTAMP(NOW()) AND ip = ?", ip.to_string()).fetch_optional(pool).await.unwrap_or_default();
    if let Some(record) = record {
        record.ip.is_some()
    } else {
        false
    }
}

#[derive(Deserialize, Debug)]
pub struct Realm {
    pub name: String,
    pub n_characters: u8,
}

pub async fn get_account_realms(
    pool: &Pool<MySql>,
    account_id: u32,
) -> Result<Vec<Realm>, AuthenticationError> {
    let records = sqlx::query!("SELECT r.id, r.name, rc.numchars FROM realmlist r JOIN realmcharacters rc ON rc.realmid = r.id AND acctid = ?;", account_id).fetch_all(pool).await?;
    Ok(records
        .into_iter()
        .map(|r| Realm {
            name: r.name,
            n_characters: r.numchars,
        })
        .collect())
}
