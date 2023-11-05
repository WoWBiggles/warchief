use askama::Template;

#[derive(Template, Default)]
#[template(path = "banned.html")]
pub struct BannedTemplate {
}

#[derive(Template, Default)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
}

impl LoginTemplate {
    pub fn error(error: impl Into<String>) -> Self {
        Self {
            error: Some(error.into())
        }
    }
}

#[derive(Template, Default)]
#[template(path = "register.html")]
pub struct RegisterTemplate {
    pub success: Option<bool>,
    pub error: Option<String>,
}

#[derive(Template, Default)]
#[template(path = "account.html")]
pub struct AccountManagementTemplate {
}
