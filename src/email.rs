use ::config::Config;
use mail_send::mail_builder::MessageBuilder;
use mail_send::SmtpClientBuilder;

use crate::config;
use crate::routes::forms::UserForm;

pub async fn send_verification_email(
    config: &Config,
    token: &str,
    user: UserForm,
) -> Result<(), mail_send::Error> {
    let server_name = config
        .get_string(config::SERVER_NAME)
        .expect("Server name should be defined in the config.");

    let domain = config
        .get_string(config::DOMAIN)
        .expect("Domain should be defined in the config.");

    let message = MessageBuilder::new()
        .from(("Biggles", "wowbiggles@proton.me"))
        .to(vec![(
            user.username,
            user.email
                .expect("Tried to send verification email without email in form."),
        )])
        .subject(format!("[{}] Verification email", server_name))
        .text_body(format!(
            "Click the link to verify your WoW account: http://{}/verify/{}",
            domain, token
        ));

    let (smtp_host, smtp_port, smtp_username, smtp_password) =
        config::get_smtp_config(&config).expect("Valid SMTP configuration");

    let mut smtp = SmtpClientBuilder::new(smtp_host, smtp_port)
        .implicit_tls(false)
        .credentials((smtp_username, smtp_password))
        .connect()
        .await?;

    smtp.send(message).await?;

    Ok(())
}
