use sqlx::{MySql, Pool};

use crate::errors::AuthenticationError;

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
