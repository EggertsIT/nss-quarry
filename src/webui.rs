use crate::config::AuthMode;

static DASHBOARD_HTML_TEMPLATE: &str = include_str!("dashboard.html");

pub fn render_dashboard_html(mode: AuthMode) -> String {
    let mode_value = match mode {
        AuthMode::OidcEntra => "oidc_entra",
        AuthMode::OidcOkta => "oidc_okta",
        AuthMode::LocalUsers => "local_users",
    };
    DASHBOARD_HTML_TEMPLATE.replace("__AUTH_MODE__", mode_value)
}
