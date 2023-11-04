use serde::{Deserialize, Serialize};
use sqlx::{MySql, Pool};

use crate::errors::AuthenticationError;

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    pub id: u32,
    pub username: String,
    pub gmlevel: GmLevel,
    pub v: String,
    pub s: String,
}

pub async fn add_account(
    pool: &Pool<MySql>,
    username: String,
    verifier_hex: String,
    salt_hex: String,
) -> Result<(), AuthenticationError> {
    // Check for existing account.
    if let Ok(existing_accounts) =
        sqlx::query!("SELECT id FROM account WHERE username = ?", username)
            .fetch_all(pool)
            .await
    {
        if existing_accounts.len() > 0 {
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

pub async fn get_account(
    pool: &Pool<MySql>,
    username: &String,
) -> Result<Account, AuthenticationError> {
    match sqlx::query!("SELECT id, username, gmlevel, v, s FROM account WHERE username = ?", username)
            .fetch_one(pool)
            .await
    {
        Ok(account) => {
            Ok(Account {
                id: account.id,
                username: account.username,
                gmlevel: account.gmlevel.into(),
                v: account.v.ok_or(AuthenticationError::MissingSrpValues(String::from("v")))?,
                s: account.s.ok_or(AuthenticationError::MissingSrpValues(String::from("s")))?,
            })
        },
        Err(e) => Err(AuthenticationError::DatabaseError(e)),
    }
}