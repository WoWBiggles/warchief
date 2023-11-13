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
            error: Some(error.into()),
        }
    }
}

#[derive(Template, Default)]
#[template(path = "register.html")]
pub struct RegisterTemplate {
    pub email_required: bool,
    pub success: Option<bool>,
    pub error: Option<String>,
}

impl RegisterTemplate {
    pub fn error(email_required: bool, message: impl Into<String>) -> Self {
        Self {
            email_required,
            success: Some(false),
            error: Some(message.into()),
        }
    }
}

#[derive(Template, Default)]
#[template(path = "verify.html")]
pub struct VerifyTemplate {
    pub username: Option<String>,
    pub success: Option<bool>,
    pub error: Option<String>,
}

impl VerifyTemplate {
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            username: None,
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
pub struct ChangePassword {
    pub success: Option<bool>,
    pub error: Option<String>,
}

impl ChangePassword {
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: Some(false),
            error: Some(message.into()),
        }
    }
}

#[derive(Template, Default)]
#[template(path = "validation_response.html")]
pub struct ValidationResponse {
    pub success: Option<String>,
    pub error: Option<String>,
}

impl ValidationResponse {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            success: Some(message.into()),
            error: None
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: None,
            error: Some(message.into())
        }
    }

    pub fn blank() -> Self {
        Self {
            success: None,
            error: None,
        }
    }
}