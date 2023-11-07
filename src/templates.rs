use askama::Template;



#[derive(Template, Default)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub message: String,
}

#[derive(Template, Default)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    error: Option<String>,
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

impl RegisterTemplate {
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: Some(false),
            error: Some(message.into()),
        }
    }
}

#[derive(Template, Default)]
#[template(path = "account.html")]
pub struct AccountManagementTemplate {
    pub account_id: u32,
}

#[derive(Template, Default)]
#[template(path = "change_password.html")]
pub struct ChangePasswordForm {
    pub success: Option<bool>,
    pub error: Option<String>,
}

impl ChangePasswordForm {
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: Some(false),
            error: Some(message.into()),
        }
    }
}
