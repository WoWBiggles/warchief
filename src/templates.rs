use askama::Template;

#[derive(Template, Default)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
}

#[derive(Template, Default)]
#[template(path = "register.html")]
pub struct RegisterTemplate {
    pub success: Option<bool>,
    pub error: Option<String>,
}
