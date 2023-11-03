use askama::Template;

#[derive(Template, Default)]
#[template(path = "register.html")]
pub struct RegisterTemplate {
    pub success: Option<bool>,
    pub error: Option<String>,
}
