mod localize;
mod model;
mod tray;

use cosmic::app::{Settings, Task, context_drawer};
use cosmic::iced::{self, Alignment, Length, Size};
use cosmic::prelude::*;
use cosmic::widget::{self, nav_bar};
use model::{Application, Policy, ProxyEditor, ProxyTestResult, Snapshot};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

fn main() -> iced::Result {
    tracing_subscriber::fmt().with_env_filter("warn").init();
    if std::env::args().nth(1).as_deref() == Some("--launch")
        && let Some(id) = std::env::args().nth(2)
    {
        let status = std::process::Command::new(client_path())
            .arg("--client")
            .args(["launch", &id])
            .args(std::env::args().skip(3))
            .status();
        std::process::exit(status.map_or(1, |s| s.code().unwrap_or(1)));
    }
    cosmic::app::run_single_instance::<Astroute>(
        Settings::default()
            .size(Size::new(1180., 780.))
            .exit_on_close(false),
        Flags,
    )
}

fn client_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.parent().unwrap().join("astroute-helper");
        if sibling.exists() {
            return sibling;
        }
    }
    PathBuf::from("/usr/libexec/astroute-helper")
}

async fn client(args: Vec<String>) -> Result<Value, String> {
    client_with_input(args, None).await
}

async fn client_with_input(args: Vec<String>, input: Option<Value>) -> Result<Value, String> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new(client_path())
        .arg("--client")
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(value) = input {
        let mut stdin = child.stdin.take().ok_or("Unable to open helper input")?;
        let mut bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        stdin.write_all(&bytes).await.map_err(|e| e.to_string())?;
    }
    let output = child.wait_with_output().await.map_err(|e| e.to_string())?;
    let response: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from_utf8_lossy(&output.stderr).trim().to_owned())?;
    if response["ok"].as_bool() == Some(true) {
        Ok(response["data"].clone())
    } else {
        Err(response["error"]
            .as_str()
            .unwrap_or("Network helper failed")
            .to_owned())
    }
}

#[derive(Clone, Debug)]
struct Flags;

impl cosmic::app::CosmicFlags for Flags {
    type SubCommand = String;
    type Args = Vec<String>;
}

#[derive(Clone)]
struct Password(String);

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Clone, Debug)]
enum Message {
    Tick,
    TrayReady(tray::Controller),
    TrayAvailable(bool),
    TrayUnavailable(String),
    TrayAction(tray::Action, Option<String>),
    Show(Option<String>),
    Hide,
    Quit,
    QuitFinished(Result<Value, String>),
    WindowOpened(iced::window::Id, Option<String>),
    WindowClosed(iced::window::Id),
    Loaded(u64, Result<Snapshot, String>),
    Select(String),
    CloseRuleEditor,
    RuleOperation {
        result: Result<Value, String>,
        show_notice: bool,
    },
    Search(String),
    Mode(usize),
    Interface(Option<String>),
    Proxy(Option<String>),
    ProxyFallback(usize),
    EditProxy(Option<String>),
    CloseProxyEditor,
    ProxyName(String),
    ProxyProtocol(usize),
    ProxyHost(String),
    ProxyPort(String),
    ProxyUsername(String),
    ProxyPassword(Password),
    ClearProxyCredentials,
    TestProxy(String),
    ProxyTested(String, Result<ProxyTestResult, String>),
    SaveProxy,
    RemoveProxy,
    ProxyOperation(Result<Value, String>),
    RulesOnly(bool),
    Save,
    Launch,
    Remove,
    Apply,
    Enable,
    Disable,
    Operation(Result<Value, String>),
    Dismiss,
}

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Apps,
    Connections,
    Interfaces,
    Proxies,
    Activity,
}

struct Astroute {
    core: cosmic::Core,
    tray: Option<tray::Controller>,
    tray_available: bool,
    quit_requested: bool,
    quitting: bool,
    window_size: Size,
    revision: u64,
    nav: nav_bar::Model,
    data: Snapshot,
    selected: Option<String>,
    search: String,
    mode: usize,
    interface: Option<String>,
    proxy: Option<String>,
    proxy_fallback: usize,
    proxy_editor: ProxyEditor,
    proxy_error: Option<String>,
    testing_proxy: Option<String>,
    proxy_tests: HashMap<String, Result<ProxyTestResult, String>>,
    rule_error: Option<String>,
    dirty: bool,
    polling: bool,
    busy: bool,
    loaded: bool,
    rules_only: bool,
    notice: Option<String>,
    failed: bool,
}

impl cosmic::Application for Astroute {
    type Executor = cosmic::executor::Default;
    type Flags = Flags;
    type Message = Message;
    const APP_ID: &'static str = "io.github.astroute.Astroute";

    fn core(&self) -> &cosmic::Core {
        &self.core
    }
    fn core_mut(&mut self) -> &mut cosmic::Core {
        &mut self.core
    }

    fn init(core: cosmic::Core, _: Flags) -> (Self, Task<Message>) {
        let mut nav = nav_bar::Model::default();
        for (page, label, icon) in [
            (
                Page::Apps,
                fl!("applications"),
                "application-x-executable-symbolic",
            ),
            (
                Page::Connections,
                fl!("connections"),
                "network-transmit-receive-symbolic",
            ),
            (
                Page::Interfaces,
                fl!("interfaces"),
                "network-wired-symbolic",
            ),
            (Page::Proxies, fl!("proxies"), "network-server-symbolic"),
            (
                Page::Activity,
                fl!("activity"),
                "document-open-recent-symbolic",
            ),
        ] {
            nav.insert()
                .text(label)
                .icon(widget::icon::from_name(icon))
                .data(page);
        }
        nav.activate_position(0);
        let mut app = Self {
            core,
            tray: None,
            tray_available: false,
            quit_requested: false,
            quitting: false,
            window_size: Size::new(1180., 780.),
            revision: 0,
            nav,
            data: Snapshot::default(),
            selected: None,
            search: String::new(),
            mode: 0,
            interface: None,
            proxy: None,
            proxy_fallback: 0,
            proxy_editor: ProxyEditor::default(),
            proxy_error: None,
            testing_proxy: None,
            proxy_tests: HashMap::new(),
            rule_error: None,
            dirty: false,
            polling: false,
            busy: false,
            loaded: false,
            rules_only: false,
            notice: None,
            failed: false,
        };
        app.set_header_title(fl!("app-title"));
        let title = if let Some(id) = app.core.main_window_id() {
            app.set_window_title("Astroute".into(), id)
        } else {
            Task::none()
        };
        let icon = app
            .core
            .main_window_id()
            .and_then(|id| tray::window_icon().map(|icon| iced::window::set_icon(id, icon)))
            .unwrap_or_else(Task::none);
        let load = app.load();
        (app, Task::batch([title, icon, load]))
    }

    fn nav_model(&self) -> Option<&nav_bar::Model> {
        Some(&self.nav)
    }

    fn on_nav_select(&mut self, id: nav_bar::Id) -> Task<Message> {
        self.nav.activate(id);
        self.search.clear();
        self.set_show_context(false);
        self.proxy_editor = ProxyEditor::default();
        self.proxy_error = None;
        self.rule_error = None;
        self.dirty = false;
        self.load_draft();
        Task::none()
    }

    fn context_drawer(&self) -> Option<context_drawer::ContextDrawer<'_, Message>> {
        if !self.core.window.show_context {
            return None;
        }
        match self.nav.active_data::<Page>() {
            Some(Page::Apps) => {
                let app = self.selected_app()?;
                Some(
                    context_drawer::context_drawer(
                        self.rule_editor_view(app),
                        Message::CloseRuleEditor,
                    )
                    .title(if self.has_rule(&app.id) {
                        fl!("edit-rule")
                    } else {
                        fl!("new-rule")
                    })
                    .footer(self.rule_editor_actions(app)),
                )
            }
            Some(Page::Proxies) => Some(
                context_drawer::context_drawer(self.proxy_editor_view(), Message::CloseProxyEditor)
                    .title(if self.proxy_editor.id.is_some() {
                        fl!("edit-proxy")
                    } else {
                        fl!("new-proxy")
                    })
                    .footer(self.proxy_editor_actions()),
            ),
            _ => None,
        }
    }

    fn subscription(&self) -> iced::Subscription<Message> {
        iced::Subscription::batch([
            iced::time::every(std::time::Duration::from_secs(3)).map(|_| Message::Tick),
            tray::subscription(),
            iced::window::close_requests().map(|_| Message::Hide),
            iced::event::listen_with(|event, _, _| match event {
                iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                    key, modifiers, ..
                }) if modifiers.control()
                    && matches!(key, iced::keyboard::Key::Character(ref c) if c.eq_ignore_ascii_case("q")) =>
                {
                    Some(Message::Quit)
                }
                _ => None,
            }),
            Self::signal_subscription(),
        ])
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        if matches!(
            message,
            Message::Save
                | Message::SaveProxy
                | Message::Remove
                | Message::RemoveProxy
                | Message::Enable
                | Message::Disable
                | Message::Apply
                | Message::Operation(_)
                | Message::RuleOperation { .. }
                | Message::ProxyOperation(_)
                | Message::TrayAction(tray::Action::Enable | tray::Action::Disable, _)
        ) {
            self.revision = self.revision.wrapping_add(1);
        }
        let task = self.handle_message(message);
        let shutdown = if self.quit_requested && !self.busy && !self.quitting {
            self.quitting = true;
            self.busy = true;
            Task::perform(client(vec!["disable".into()]), |result| {
                cosmic::Action::App(Message::QuitFinished(result))
            })
        } else {
            Task::none()
        };
        if let Some(tray) = &self.tray {
            tray.update(tray::State {
                enabled: self.loaded.then_some(self.data.enabled),
                busy: self.busy,
                quitting: self.quit_requested,
                error: self.failed.then(|| self.notice.clone()).flatten(),
            });
        }
        Task::batch([task, shutdown])
    }

    fn on_app_exit(&mut self) -> Option<Message> {
        Some(Message::Hide)
    }

    fn on_close_requested(&self, id: iced::window::Id) -> Option<Message> {
        Some(Message::WindowClosed(id))
    }

    fn on_window_resize(&mut self, _: iced::window::Id, width: f32, height: f32) {
        self.window_size = Size::new(width, height);
    }

    fn dbus_activation(&mut self, message: cosmic::dbus_activation::Message) -> Task<Message> {
        self.update(Message::Show(message.activation_token))
    }

    fn header_end(&self) -> Vec<Element<'_, Message>> {
        let mut button = if self.data.enabled {
            widget::button::standard(fl!("disable-controls"))
        } else {
            widget::button::suggested(fl!("enable-controls"))
                .leading_icon(widget::icon::from_name("security-high-symbolic").handle())
        };
        if !self.busy {
            button = button.on_press(if self.data.enabled {
                Message::Disable
            } else {
                Message::Enable
            });
        }
        let mut buttons = Vec::with_capacity(2);
        if self.data.enabled && !self.data.pending_rules.is_empty() {
            let mut apply = widget::button::suggested(fl!("apply-rules"));
            if !self.busy {
                apply = apply.on_press(Message::Apply);
            }
            buttons.push(apply.into());
        }
        buttons.push(button.into());
        buttons
    }

    fn view(&self) -> Element<'_, Message> {
        let mut content = widget::column::with_capacity(16).spacing(16).padding(20);
        let status_icon = if self.data.enabled {
            "security-high-symbolic"
        } else {
            "security-medium-symbolic"
        };
        let mut status_icon = widget::icon::from_name(status_icon).size(32).icon();
        if self.data.enabled {
            status_icon =
                status_icon.class(cosmic::theme::Svg::custom(|theme| widget::svg::Style {
                    color: Some(theme.cosmic().accent_text_color().into()),
                }));
        }
        let status = widget::row::with_capacity(8)
            .spacing(16)
            .align_y(Alignment::Center)
            .push(status_icon)
            .push(
                widget::column::with_capacity(16)
                    .spacing(4)
                    .push(
                        widget::text::heading(if self.data.enabled {
                            fl!("controls-active")
                        } else {
                            fl!("monitor-only")
                        })
                        .class(if self.data.enabled {
                            cosmic::theme::Text::Accent
                        } else {
                            cosmic::theme::Text::Default
                        }),
                    )
                    .push(widget::text::body(fl!("status-description"))),
            )
            .push(widget::Space::new().width(Length::Fill))
            .push(Self::stat(self.data.policies.len(), fl!("saved-rules")))
            .push(Self::stat(
                self.data.connections.len(),
                fl!("open-connections"),
            ));
        content = content.push(
            widget::container(status)
                .padding(18)
                .class(cosmic::theme::Container::Card),
        );
        if let Some(notice) = &self.notice {
            content = content.push(
                widget::container(
                    widget::row::with_capacity(8)
                        .spacing(12)
                        .align_y(Alignment::Center)
                        .push(if self.failed {
                            Self::error_icon()
                        } else {
                            widget::icon::from_name("dialog-information-symbolic")
                                .size(20)
                                .icon()
                        })
                        .push(widget::text::body(notice).width(Length::Fill).class(
                            if self.failed {
                                cosmic::theme::Text::Color(
                                    cosmic::theme::active().cosmic().destructive.base.into(),
                                )
                            } else {
                                cosmic::theme::Text::Default
                            },
                        ))
                        .push(
                            widget::button::text(fl!("close-message")).on_press(Message::Dismiss),
                        ),
                )
                .padding(12)
                .class(cosmic::theme::Container::Card),
            );
        }
        if !self.loaded {
            return content.push(widget::text::body(fl!("loading"))).into();
        }
        let page = self
            .nav
            .active_data::<Page>()
            .copied()
            .unwrap_or(Page::Apps);
        content = content.push(match page {
            Page::Apps => self.apps_view(),
            Page::Connections => self.connections_view(),
            Page::Interfaces => self.interfaces_view(),
            Page::Proxies => self.proxies_view(),
            Page::Activity => self.activity_view(),
        });
        content.width(Length::Fill).height(Length::Fill).into()
    }
}

impl Astroute {
    fn show_window(&mut self, token: Option<String>) -> Task<Message> {
        if let Some(id) = self.core.main_window_id() {
            return Self::focus_window(id, token);
        }
        let (id, open) = iced::window::open(iced::window::Settings {
            size: self.window_size,
            min_size: Some(Size::new(760., 540.)),
            decorations: false,
            transparent: true,
            exit_on_close_request: false,
            icon: tray::window_icon(),
            platform_specific: iced::window::settings::PlatformSpecific {
                application_id: <Self as cosmic::Application>::APP_ID.into(),
                ..Default::default()
            },
            ..Default::default()
        });
        self.core.set_main_window_id(Some(id));
        Task::batch([
            self.set_window_title(fl!("app-title"), id),
            open.map(move |id| cosmic::Action::App(Message::WindowOpened(id, token.clone()))),
        ])
    }

    fn focus_window(id: iced::window::Id, token: Option<String>) -> Task<Message> {
        let focus = token.map_or_else(
            || iced::window::gain_focus(id),
            |token| Task::done(cosmic::Action::Cosmic(cosmic::app::Action::Activate(token))),
        );
        iced::window::minimize(id, false).chain(focus)
    }

    fn signal_subscription() -> iced::Subscription<Message> {
        use cosmic::iced::futures::{SinkExt, channel::mpsc};
        iced::Subscription::run(|| {
            iced::stream::channel(1, |mut output: mpsc::Sender<Message>| async move {
                use tokio::signal::unix::{SignalKind, signal};
                let (Ok(mut interrupt), Ok(mut terminate)) = (
                    signal(SignalKind::interrupt()),
                    signal(SignalKind::terminate()),
                ) else {
                    return;
                };
                loop {
                    tokio::select! {
                        signal = interrupt.recv() => if signal.is_none() { break },
                        signal = terminate.recv() => if signal.is_none() { break },
                    }
                    if output.send(Message::Quit).await.is_err() {
                        break;
                    }
                }
            })
        })
    }

    fn handle_message(&mut self, message: Message) -> Task<Message> {
        if self.quit_requested
            && matches!(
                message,
                Message::Save
                    | Message::SaveProxy
                    | Message::Remove
                    | Message::RemoveProxy
                    | Message::Enable
                    | Message::Disable
                    | Message::Apply
                    | Message::Launch
                    | Message::TestProxy(_)
            )
        {
            return Task::none();
        }
        if matches!(
            &message,
            Message::Select(_)
                | Message::CloseRuleEditor
                | Message::Mode(_)
                | Message::Interface(_)
                | Message::Proxy(_)
                | Message::ProxyFallback(_)
                | Message::Save
                | Message::Remove
        ) {
            if self.busy {
                return Task::none();
            }
            self.rule_error = None;
        }
        if matches!(
            &message,
            Message::ProxyName(_)
                | Message::ProxyProtocol(_)
                | Message::ProxyHost(_)
                | Message::ProxyPort(_)
                | Message::ProxyUsername(_)
                | Message::ProxyPassword(_)
                | Message::ClearProxyCredentials
        ) {
            self.proxy_error = None;
        }
        match message {
            Message::TrayReady(controller) => self.tray = Some(controller),
            Message::TrayAvailable(available) => {
                let restore = self.tray_available && !available;
                self.tray_available = available;
                if restore {
                    return self.show_window(None);
                }
            }
            Message::TrayUnavailable(error) => {
                self.tray_available = false;
                eprintln!("Astroute tray: {error}");
            }
            Message::TrayAction(action, token) => {
                return match action {
                    tray::Action::Show => self.show_window(token),
                    tray::Action::Enable => self.handle_message(Message::Enable),
                    tray::Action::Disable => self.handle_message(Message::Disable),
                    tray::Action::Quit => self.handle_message(Message::Quit),
                };
            }
            Message::Show(token) => return self.show_window(token),
            Message::Hide => {
                if self.tray_available && !self.quit_requested {
                    if let Some(id) = self.core.main_window_id() {
                        self.core.set_main_window_id(None);
                        return iced::window::close(id);
                    }
                } else if !self.quit_requested {
                    self.quit_requested = true;
                }
            }
            Message::Quit => self.quit_requested = true,
            Message::QuitFinished(result) => match result {
                Ok(_) => return iced::exit(),
                Err(error) => {
                    self.quit_requested = false;
                    self.quitting = false;
                    self.busy = false;
                    self.failed = true;
                    self.notice = Some(format!("{} {error}", fl!("quit-failed")));
                    return self.show_window(None);
                }
            },
            Message::WindowOpened(id, token) => {
                if self.core.main_window_id() == Some(id) {
                    return Self::focus_window(id, token);
                }
            }
            Message::WindowClosed(id) => {
                if self.core.main_window_id() == Some(id) {
                    self.core.set_main_window_id(None);
                    if !self.tray_available {
                        self.quit_requested = true;
                    }
                }
            }
            Message::Tick => {
                if !self.polling && !self.busy {
                    self.polling = true;
                    return self.load();
                }
            }
            Message::Loaded(revision, result) => {
                self.polling = false;
                if self.busy || self.quit_requested || revision != self.revision {
                    return Task::none();
                }
                self.loaded = true;
                match result {
                    Ok(mut data) => {
                        data.apps.retain(|app| app.controllable);
                        self.proxy_tests
                            .retain(|id, _| data.proxies.iter().any(|profile| &profile.id == id));
                        self.data = data;
                        if !self
                            .data
                            .apps
                            .iter()
                            .any(|app| Some(&app.id) == self.selected.as_ref())
                        {
                            if self.selected.is_some()
                                && self.nav.active_data::<Page>() == Some(&Page::Apps)
                            {
                                self.set_show_context(false);
                                self.rule_error = None;
                            }
                            self.selected = self.data.apps.first().map(|app| app.id.clone());
                            self.dirty = false;
                            self.load_draft();
                        } else if !self.dirty {
                            self.load_draft();
                        }
                    }
                    Err(error) => {
                        self.notice = Some(error);
                        self.failed = true;
                    }
                }
            }
            Message::Select(id) => self.open_rule(id),
            Message::CloseRuleEditor => {
                self.set_show_context(false);
                self.dirty = false;
                self.load_draft();
            }
            Message::Search(value) => self.search = value,
            Message::Mode(value) => {
                self.mode = value;
                self.dirty = true;
            }
            Message::Interface(value) => {
                self.interface = value;
                self.dirty = true;
            }
            Message::Proxy(value) => {
                self.proxy = value;
                self.dirty = true;
            }
            Message::ProxyFallback(value) => {
                self.proxy_fallback = value;
                self.dirty = true;
            }
            Message::EditProxy(id) => {
                self.proxy_error = None;
                self.proxy_editor = self
                    .data
                    .proxies
                    .iter()
                    .find(|p| Some(&p.id) == id.as_ref())
                    .map(ProxyEditor::from)
                    .unwrap_or_default();
                self.set_show_context(true);
            }
            Message::CloseProxyEditor => {
                self.set_show_context(false);
                self.proxy_editor = ProxyEditor::default();
                self.proxy_error = None;
            }
            Message::ProxyName(value) => self.proxy_editor.name = value,
            Message::ProxyProtocol(value) => {
                self.proxy_editor.protocol = value;
                if self.proxy_editor.id.is_none() {
                    self.proxy_editor.port = ["1080", "8080", "443"][value].into();
                }
            }
            Message::ProxyHost(value) => self.proxy_editor.host = value,
            Message::ProxyPort(value) => self.proxy_editor.port = value,
            Message::ProxyUsername(value) => self.proxy_editor.username = value,
            Message::ProxyPassword(value) => self.proxy_editor.password = value.0,
            Message::ClearProxyCredentials => {
                self.proxy_editor.username.clear();
                self.proxy_editor.password.clear();
                self.proxy_editor.has_password = false;
            }
            Message::TestProxy(id) => {
                if self.busy {
                    return Task::none();
                }
                self.proxy_tests.remove(&id);
                self.testing_proxy = Some(id.clone());
                self.busy = true;
                let tested_id = id.clone();
                return Task::perform(
                    async move {
                        let value = tokio::time::timeout(
                            std::time::Duration::from_secs(20),
                            client(vec!["test-proxy".into(), id]),
                        )
                        .await
                        .map_err(|_| fl!("proxy-test-timeout"))??;
                        serde_json::from_value(value).map_err(|e| e.to_string())
                    },
                    move |result| {
                        cosmic::Action::App(Message::ProxyTested(tested_id.clone(), result))
                    },
                );
            }
            Message::ProxyTested(id, result) => {
                self.busy = false;
                self.testing_proxy = None;
                if self.data.proxies.iter().any(|profile| profile.id == id) {
                    self.proxy_tests.insert(id, result);
                }
            }
            Message::SaveProxy => {
                self.proxy_error = None;
                let editor = &self.proxy_editor;
                if editor.name.trim().is_empty() {
                    self.proxy_error = Some(fl!("invalid-proxy-name"));
                    return Task::none();
                }
                if editor.host.trim().is_empty() {
                    self.proxy_error = Some(fl!("invalid-proxy-host"));
                    return Task::none();
                }
                let Some(port) = editor.port.parse::<u16>().ok().filter(|port| *port > 0) else {
                    self.proxy_error = Some(fl!("invalid-proxy-port"));
                    return Task::none();
                };
                let password = if editor.password.is_empty() && editor.has_password {
                    None
                } else {
                    Some(editor.password.clone())
                };
                let profile = serde_json::json!({"id": editor.id, "name": editor.name,
                    "protocol": (["socks5", "http", "https"][editor.protocol]), "host": editor.host,
                    "port": port, "username": editor.username, "password": password});
                self.busy = true;
                return Task::perform(
                    client_with_input(vec!["save-proxy".into()], Some(profile)),
                    |r| cosmic::Action::App(Message::ProxyOperation(r)),
                );
            }
            Message::RemoveProxy => {
                if let Some(id) = self.proxy_editor.id.clone() {
                    self.busy = true;
                    return Task::perform(client(vec!["remove-proxy".into(), id]), |r| {
                        cosmic::Action::App(Message::ProxyOperation(r))
                    });
                }
            }
            Message::ProxyOperation(result) => {
                self.busy = false;
                self.failed = result.is_err();
                self.notice = match result {
                    Ok(value) => {
                        if let Some(id) = value["profile"]["id"].as_str() {
                            self.proxy_tests.remove(id);
                        }
                        self.proxy_editor = ProxyEditor::default();
                        self.proxy_error = None;
                        self.set_show_context(false);
                        value["message"].as_str().map(str::to_owned)
                    }
                    Err(error) => {
                        self.proxy_error = Some(error);
                        None
                    }
                };
                return self.load();
            }
            Message::RulesOnly(value) => self.rules_only = value,
            Message::Dismiss => self.notice = None,
            Message::Save => {
                if let Some(app_id) = self.selected.clone() {
                    self.busy = true;
                    let policy = Policy {
                        app_id,
                        mode: ["allow", "block", "local"][self.mode].into(),
                        interface: self.interface.clone(),
                        proxy: self.proxy.clone(),
                        proxy_fallback: ["block", "direct"][self.proxy_fallback].into(),
                    };
                    return Task::perform(
                        client(vec!["save".into(), serde_json::to_string(&policy).unwrap()]),
                        |result| {
                            cosmic::Action::App(Message::RuleOperation {
                                result,
                                show_notice: false,
                            })
                        },
                    );
                }
            }
            Message::Launch | Message::Remove => {
                if let Some(id) = self.selected.clone() {
                    self.busy = true;
                    let method = if matches!(message, Message::Launch) {
                        "launch"
                    } else {
                        "remove"
                    };
                    if matches!(message, Message::Remove) {
                        return Task::perform(client(vec![method.into(), id]), |result| {
                            cosmic::Action::App(Message::RuleOperation {
                                result,
                                show_notice: true,
                            })
                        });
                    }
                    return Self::operate(vec![method.into(), id]);
                }
            }
            Message::Apply | Message::Enable | Message::Disable => {
                if self.busy {
                    return Task::none();
                }
                self.busy = true;
                return Self::operate(vec![
                    match message {
                        Message::Apply => "apply",
                        Message::Enable => "enable",
                        _ => "disable",
                    }
                    .into(),
                ]);
            }
            Message::RuleOperation {
                result,
                show_notice,
            } => {
                self.busy = false;
                self.failed = result.is_err();
                match result {
                    Ok(value) => {
                        self.dirty = false;
                        self.rule_error = None;
                        self.notice = if show_notice {
                            value["message"].as_str().map(str::to_owned)
                        } else {
                            None
                        };
                        if self.nav.active_data::<Page>() == Some(&Page::Apps) {
                            self.set_show_context(false);
                        }
                    }
                    Err(error) => {
                        if self.core.window.show_context
                            && self.nav.active_data::<Page>() == Some(&Page::Apps)
                        {
                            self.rule_error = Some(error);
                            self.notice = None;
                        } else {
                            self.notice = Some(error);
                        }
                    }
                }
                return self.load();
            }
            Message::Operation(result) => {
                self.busy = false;
                self.failed = result.is_err();
                self.notice = Some(match result {
                    Ok(value) => {
                        self.dirty = false;
                        if let Some(enabled) = value["enabled"].as_bool() {
                            self.data.enabled = enabled;
                        }
                        value["message"].as_str().unwrap_or("Done").into()
                    }
                    Err(error) => error,
                });
                let reload = self.load();
                if self.failed && !self.quit_requested && self.core.main_window_id().is_none() {
                    return Task::batch([reload, self.show_window(None)]);
                }
                return reload;
            }
        }
        Task::none()
    }

    fn selected_app(&self) -> Option<&Application> {
        self.data
            .apps
            .iter()
            .find(|app| Some(&app.id) == self.selected.as_ref())
    }

    fn has_rule(&self, app_id: &str) -> bool {
        self.data.policies.iter().any(|p| p.app_id == app_id)
    }

    fn open_rule(&mut self, app_id: String) {
        if !self.data.apps.iter().any(|app| app.id == app_id) {
            return;
        }
        self.selected = Some(app_id);
        self.dirty = false;
        self.rule_error = None;
        self.load_draft();
        self.set_show_context(true);
    }

    fn error_icon() -> widget::icon::Icon {
        widget::icon::from_name("dialog-error-symbolic")
            .size(20)
            .icon()
            .class(cosmic::theme::Svg::custom(|theme| widget::svg::Style {
                color: Some(theme.cosmic().destructive.base.into()),
            }))
    }

    fn load(&self) -> Task<Message> {
        let revision = self.revision;
        Task::perform(
            async {
                serde_json::from_value(client(vec!["snapshot".into()]).await?)
                    .map_err(|e| e.to_string())
            },
            move |r| cosmic::Action::App(Message::Loaded(revision, r)),
        )
    }

    fn operate(args: Vec<String>) -> Task<Message> {
        Task::perform(client(args), |r| cosmic::Action::App(Message::Operation(r)))
    }

    fn load_draft(&mut self) {
        let policy = self
            .data
            .policies
            .iter()
            .find(|p| Some(&p.app_id) == self.selected.as_ref());
        self.mode = match policy.map(|p| p.mode.as_str()) {
            Some("block") => 1,
            Some("local") => 2,
            _ => 0,
        };
        self.interface = policy.and_then(|p| p.interface.clone());
        self.proxy = policy.and_then(|p| p.proxy.clone());
        self.proxy_fallback = usize::from(policy.is_some_and(|p| p.proxy_fallback == "direct"));
    }

    fn stat(value: usize, label: String) -> Element<'static, Message> {
        widget::column::with_capacity(16)
            .spacing(2)
            .push(widget::text::title3(value.to_string()))
            .push(widget::text::caption(label))
            .into()
    }

    fn apps_view(&self) -> Element<'_, Message> {
        let search = self.search.to_lowercase();
        let mut list = widget::column::with_capacity(16).spacing(8);
        let mut pending: Option<Element<'_, Message>> = None;
        let mut count = 0;
        for app in &self.data.apps {
            let policy = self.data.policies.iter().find(|p| p.app_id == app.id);
            if (self.rules_only && policy.is_none())
                || (!app.name.to_lowercase().contains(&search)
                    && !app.id.to_lowercase().contains(&search))
            {
                continue;
            }
            let mut subtitle = if let Some(p) = policy {
                format!(
                    "{} · {}",
                    match p.mode.as_str() {
                        "block" => fl!("block"),
                        "local" => fl!("local"),
                        _ => fl!("allow"),
                    },
                    p.interface.as_deref().unwrap_or("Automatic")
                )
            } else {
                fl!("unmanaged")
            };
            if self.data.pending_rules.contains(&app.id) {
                subtitle.push_str(&format!(" · {}", fl!("pending-rule")));
            }
            let row = widget::row::with_capacity(8)
                .spacing(12)
                .align_y(Alignment::Center)
                .push(widget::icon::from_name(app.icon.clone()).size(32))
                .push(
                    widget::column::with_capacity(16)
                        .spacing(4)
                        .push(widget::text::body(&app.name))
                        .push(widget::text::caption(subtitle))
                        .width(Length::Fill),
                )
                .push(widget::icon::from_name("document-edit-symbolic").size(20));
            let mut button = widget::button::custom(row)
                .padding(12)
                .width(Length::Fill)
                .class(cosmic::theme::Button::ListItem([8.; 4]))
                .selected(
                    self.core.window.show_context && self.selected.as_deref() == Some(&app.id),
                );
            if !self.busy {
                button = button.on_press(Message::Select(app.id.clone()));
            }
            if let Some(first) = pending.take() {
                list = list.push(
                    widget::row::with_capacity(2)
                        .spacing(12)
                        .width(Length::Fill)
                        .push(first)
                        .push(button),
                );
            } else {
                pending = Some(button.into());
            }
            count += 1;
        }
        if let Some(last) = pending {
            list = list.push(
                widget::row::with_capacity(2)
                    .spacing(12)
                    .width(Length::Fill)
                    .push(last)
                    .push(widget::Space::new().width(Length::Fill)),
            );
        }
        if count == 0 {
            list = list.push(widget::text::body(fl!("no-apps")));
        }
        widget::column::with_capacity(4)
            .spacing(12)
            .push(widget::text::title3(fl!("applications")))
            .push(
                widget::row::with_capacity(2)
                    .spacing(12)
                    .width(Length::Fill)
                    .push(
                        widget::container(
                            widget::text_input::search_input(fl!("search-apps"), &self.search)
                                .on_input(Message::Search),
                        )
                        .width(Length::Fill),
                    )
                    .push(widget::Space::new().width(Length::Fill)),
            )
            .push(
                widget::toggler(self.rules_only)
                    .label(fl!("rules-only"))
                    .spacing(12)
                    .width(Length::Shrink)
                    .on_toggle(Message::RulesOnly),
            )
            .push(widget::scrollable(list).height(Length::Fill))
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn rule_editor_view<'a>(&'a self, app: &'a Application) -> Element<'a, Message> {
        let active = self
            .data
            .active
            .iter()
            .filter(|a| a.app_id == app.id)
            .count();
        let mut content = widget::column::with_capacity(16).spacing(12);
        if !self.has_rule(&app.id) {
            let apps: Vec<_> = self
                .data
                .apps
                .iter()
                .filter(|app| !self.has_rule(&app.id))
                .collect();
            let names = apps.iter().map(|app| app.name.clone()).collect::<Vec<_>>();
            let selected = apps.iter().position(|candidate| candidate.id == app.id);
            let ids = apps.iter().map(|app| app.id.clone()).collect::<Vec<_>>();
            content = content
                .push(widget::text::heading(fl!("application")))
                .push(
                    widget::dropdown(names, selected, move |index| {
                        Message::Select(ids[index].clone())
                    })
                    .width(Length::Fill),
                );
        }
        content = content
            .push(
                widget::row::with_capacity(8)
                    .spacing(16)
                    .align_y(Alignment::Center)
                    .push(widget::icon::from_name(app.icon.clone()).size(32))
                    .push(
                        widget::column::with_capacity(16)
                            .spacing(4)
                            .push(widget::text::heading(&app.name))
                            .push(widget::text::caption(&app.id)),
                    ),
            )
            .push(widget::text::caption(if active > 0 {
                format!("{} · {active}", fl!("running-controlled"))
            } else {
                fl!("not-running")
            }));
        if self.data.pending_rules.contains(&app.id) {
            content = content.push(widget::text::caption(fl!("rule-pending-description")));
        }
        let modes = vec![fl!("allow"), fl!("block"), fl!("local")];
        content = content
            .push(widget::text::heading(fl!("access")))
            .push(widget::dropdown(modes, Some(self.mode), Message::Mode).width(Length::Fill));
        let mut names = vec![fl!("automatic")];
        let mut values = vec![None];
        for interface in &self.data.interfaces {
            names.push(format!(
                "{} · {}{}",
                interface.name,
                interface.kind,
                if interface.up { "" } else { " · offline" }
            ));
            values.push(Some(interface.name.clone()));
        }
        if self.interface.is_some() && !values.contains(&self.interface) {
            names.push(format!(
                "{} · unavailable",
                self.interface.as_deref().unwrap()
            ));
            values.push(self.interface.clone());
        }
        let selected = values
            .iter()
            .position(|v| v == &self.interface)
            .unwrap_or(0);
        content = content
            .push(widget::text::heading(fl!("route")))
            .push(
                widget::dropdown(names, Some(selected), move |index| {
                    Message::Interface(values[index].clone())
                })
                .width(Length::Fill),
            )
            .push(widget::text::caption(fl!("interface-description")));
        let mut proxy_names = vec![fl!("no-proxy")];
        let mut proxy_values = vec![None];
        for profile in &self.data.proxies {
            proxy_names.push(format!(
                "{} · {}",
                profile.name,
                profile.protocol.to_uppercase()
            ));
            proxy_values.push(Some(profile.id.clone()));
        }
        if self.proxy.is_some() && !proxy_values.contains(&self.proxy) {
            proxy_names.push(fl!("proxy-unavailable"));
            proxy_values.push(self.proxy.clone());
        }
        let proxy_selected = proxy_values
            .iter()
            .position(|v| v == &self.proxy)
            .unwrap_or(0);
        content = content
            .push(widget::text::heading(fl!("app-proxy")))
            .push(
                widget::dropdown(proxy_names, Some(proxy_selected), move |index| {
                    Message::Proxy(proxy_values[index].clone())
                })
                .width(Length::Fill),
            )
            .push(widget::text::caption(if self.proxy.is_some() {
                fl!("proxy-traffic-description")
            } else {
                fl!("proxy-choose-description")
            }));
        if self.proxy.is_some() {
            content = content
                .push(widget::text::heading(fl!("proxy-failure")))
                .push(
                    widget::dropdown(
                        vec![fl!("proxy-failure-block"), fl!("proxy-failure-direct")],
                        Some(self.proxy_fallback),
                        Message::ProxyFallback,
                    )
                    .width(Length::Fill),
                )
                .push(widget::text::caption(if self.proxy_fallback == 0 {
                    fl!("proxy-failure-block-description")
                } else {
                    fl!("proxy-failure-direct-description")
                }));
        }
        content = content.push(widget::text::caption(fl!("launcher-description")));
        if !self.data.enabled {
            content = content.push(widget::text::body(fl!("setup-hint")));
        }
        content = content
            .push(widget::text::caption(fl!("route-description")))
            .push(widget::divider::horizontal::default())
            .push(widget::text::heading(fl!("recent-connections")));
        let mut shown = 0;
        let exe = app.argv.first().map(|s| s.rsplit('/').next().unwrap_or(s));
        for connection in &self.data.connections {
            if exe != Some(connection.exe.rsplit('/').next().unwrap_or(&connection.exe)) {
                continue;
            }
            content = content.push(
                widget::row::with_capacity(8)
                    .spacing(12)
                    .push(widget::text::caption(&connection.protocol).width(Length::Fixed(40.)))
                    .push(widget::text::body(&connection.remote).width(Length::Fill))
                    .push(widget::text::caption(&connection.state)),
            );
            shown += 1;
            if shown >= 12 {
                break;
            }
        }
        if shown == 0 {
            content = content.push(widget::text::body(fl!("no-connections")));
        }
        content.into()
    }

    fn rule_editor_actions(&self, app: &Application) -> Element<'_, Message> {
        let saved = self.has_rule(&app.id);
        let mut save = widget::button::suggested(if self.busy {
            fl!("working")
        } else {
            fl!("save-rule")
        });
        let mut secondary = widget::button::text(if saved {
            fl!("remove-rule")
        } else {
            fl!("cancel")
        });
        if !self.busy {
            save = save.on_press(Message::Save);
            secondary = secondary.on_press(if saved {
                Message::Remove
            } else {
                Message::CloseRuleEditor
            });
        }
        let mut footer = widget::column::with_capacity(3).spacing(12);
        if let Some(error) = &self.rule_error {
            footer = footer.push(
                widget::row::with_capacity(2)
                    .spacing(10)
                    .push(Self::error_icon())
                    .push(widget::text::body(error).width(Length::Fill).class(
                        cosmic::theme::Text::Color(
                            cosmic::theme::active().cosmic().destructive.base.into(),
                        ),
                    )),
            );
        }
        footer = footer.push(
            widget::row::with_capacity(2)
                .spacing(12)
                .push(save)
                .push(secondary),
        );
        if saved {
            let mut launch = widget::button::standard(fl!("launch-app")).width(Length::Fill);
            if !self.busy
                && self.data.enabled
                && !self.dirty
                && !self.data.pending_rules.contains(&app.id)
            {
                launch = launch.on_press(Message::Launch);
            }
            footer = footer.push(launch);
        }
        footer.into()
    }

    fn connections_view(&self) -> Element<'_, Message> {
        let mut list = widget::column::with_capacity(16).spacing(8);
        let search = self.search.to_lowercase();
        for c in &self.data.connections {
            if !format!("{} {}", c.name, c.remote)
                .to_lowercase()
                .contains(&search)
            {
                continue;
            }
            let process = widget::column::with_capacity(16)
                .spacing(4)
                .push(widget::text::body(&c.name))
                .push(widget::text::caption(format!(
                    "PID {} · {}",
                    c.pid, c.protocol
                )))
                .width(Length::Fixed(200.));
            list = list.push(
                widget::container(
                    widget::row::with_capacity(8)
                        .spacing(16)
                        .align_y(Alignment::Center)
                        .push(process)
                        .push(widget::text::body(&c.remote).width(Length::Fill))
                        .push(widget::text::caption(&c.state)),
                )
                .padding(14)
                .class(cosmic::theme::Container::Card),
            );
        }
        widget::column::with_capacity(16)
            .spacing(16)
            .push(
                widget::text_input::search_input(fl!("search-connections"), &self.search)
                    .on_input(Message::Search),
            )
            .push(widget::scrollable(list).height(Length::Fill))
            .push(widget::text::caption(fl!("privacy-description")))
            .into()
    }

    fn proxies_view(&self) -> Element<'_, Message> {
        let mut list = widget::column::with_capacity(16).spacing(12);
        for profile in &self.data.proxies {
            let detail = format!(
                "{} · {}:{}",
                profile.protocol.to_uppercase(),
                profile.host,
                profile.port
            );
            let mut details = widget::column::with_capacity(4)
                .spacing(5)
                .width(Length::Fill)
                .push(widget::text::heading(&profile.name))
                .push(widget::text::caption(detail));
            if let Some(result) = self.proxy_tests.get(&profile.id) {
                match result {
                    Ok(result) => {
                        details = details
                            .push(
                                widget::text::body(format!(
                                    "{} · {} ms",
                                    fl!("proxy-test-passed"),
                                    result.elapsed_ms
                                ))
                                .class(
                                    cosmic::theme::Text::Color(
                                        cosmic::theme::active().cosmic().success.base.into(),
                                    ),
                                ),
                            )
                            .push(widget::text::caption(format!(
                                "{} · {}",
                                result.target,
                                fl!("proxy-test-system-route")
                            )));
                    }
                    Err(error) => {
                        details = details.push(
                            widget::row::with_capacity(2)
                                .spacing(10)
                                .push(Self::error_icon())
                                .push(widget::text::body(error).width(Length::Fill).class(
                                    cosmic::theme::Text::Color(
                                        cosmic::theme::active().cosmic().destructive.base.into(),
                                    ),
                                )),
                        );
                    }
                }
            }
            let mut test =
                widget::button::standard(if self.testing_proxy.as_ref() == Some(&profile.id) {
                    fl!("proxy-testing")
                } else {
                    fl!("test-proxy")
                });
            if !self.busy {
                test = test.on_press(Message::TestProxy(profile.id.clone()));
            }
            list = list.push(
                widget::row::with_capacity(2)
                    .spacing(12)
                    .width(Length::Fill)
                    .align_y(Alignment::Center)
                    .push(
                        widget::button::custom(
                            widget::row::with_capacity(3)
                                .spacing(16)
                                .align_y(Alignment::Center)
                                .push(widget::icon::from_name("network-server-symbolic").size(32))
                                .push(details)
                                .push(widget::icon::from_name("document-edit-symbolic").size(20)),
                        )
                        .padding(12)
                        .width(Length::Fill)
                        .class(cosmic::theme::Button::ListItem([8.; 4]))
                        .selected(
                            self.core.window.show_context
                                && self.proxy_editor.id.as_ref() == Some(&profile.id),
                        )
                        .on_press(Message::EditProxy(Some(profile.id.clone()))),
                    )
                    .push(test),
            );
        }
        if self.data.proxies.is_empty() {
            list = list.push(
                widget::container(widget::text::body(fl!("no-proxies")))
                    .padding(24)
                    .width(Length::Fill)
                    .class(cosmic::theme::Container::Card),
            );
        }
        widget::column::with_capacity(3)
            .spacing(16)
            .push(
                widget::row::with_capacity(3)
                    .align_y(Alignment::Center)
                    .spacing(16)
                    .push(widget::text::title3(fl!("proxies")))
                    .push(widget::Space::new().width(Length::Fill))
                    .push(
                        widget::button::suggested(fl!("new-proxy"))
                            .on_press(Message::EditProxy(None)),
                    ),
            )
            .push(widget::text::body(fl!("proxies-description")))
            .push(widget::scrollable(list).height(Length::Fill))
            .into()
    }

    fn proxy_editor_actions(&self) -> Element<'_, Message> {
        let editor = &self.proxy_editor;
        let used = editor.id.as_ref().is_some_and(|id| {
            self.data
                .policies
                .iter()
                .any(|p| p.proxy.as_ref() == Some(id))
        });
        let mut save = widget::button::suggested(if self.busy && self.testing_proxy.is_none() {
            fl!("working")
        } else {
            fl!("save-proxy")
        });
        let mut remove = widget::button::text(fl!("remove-proxy"));
        if !self.busy {
            save = save.on_press(Message::SaveProxy);
            if editor.id.is_some() && !used {
                remove = remove.on_press(Message::RemoveProxy);
            }
        }
        let actions =
            widget::row::with_capacity(3)
                .spacing(12)
                .push(save)
                .push(if editor.id.is_some() {
                    remove
                } else {
                    widget::button::text(fl!("cancel")).on_press(Message::CloseProxyEditor)
                });
        let mut footer = widget::column::with_capacity(2).spacing(12);
        if let Some(error) = &self.proxy_error {
            footer = footer.push(
                widget::row::with_capacity(2)
                    .spacing(10)
                    .push(Self::error_icon())
                    .push(widget::text::body(error).class(cosmic::theme::Text::Color(
                        cosmic::theme::active().cosmic().destructive.base.into(),
                    ))),
            );
        }
        footer.push(actions).into()
    }

    fn proxy_editor_view(&self) -> Element<'_, Message> {
        let editor = &self.proxy_editor;
        let form = widget::column::with_capacity(24)
            .spacing(12)
            .push(widget::text::heading(fl!("proxy-name")))
            .push(
                widget::text_input(fl!("proxy-name-placeholder"), &editor.name)
                    .on_input(Message::ProxyName),
            )
            .push(widget::text::heading(fl!("proxy-protocol")))
            .push(
                widget::dropdown(
                    vec!["SOCKS5", "HTTP", "HTTPS"],
                    Some(editor.protocol),
                    Message::ProxyProtocol,
                )
                .width(Length::Fill),
            )
            .push(
                widget::row::with_capacity(2)
                    .spacing(12)
                    .push(
                        widget::column::with_capacity(2)
                            .spacing(8)
                            .width(Length::Fill)
                            .push(widget::text::heading(fl!("proxy-host")))
                            .push(
                                widget::text_input("proxy.example.com", &editor.host)
                                    .on_input(Message::ProxyHost),
                            ),
                    )
                    .push(
                        widget::column::with_capacity(2)
                            .spacing(8)
                            .width(Length::Fixed(100.))
                            .push(widget::text::heading(fl!("proxy-port")))
                            .push(
                                widget::text_input("1080", &editor.port)
                                    .on_input(Message::ProxyPort),
                            ),
                    ),
            )
            .push(widget::text::heading(fl!("proxy-username")))
            .push(
                widget::text_input(fl!("optional"), &editor.username)
                    .on_input(Message::ProxyUsername),
            )
            .push(widget::text::heading(fl!("proxy-password")))
            .push(
                widget::text_input::secure_input(
                    if editor.has_password {
                        fl!("proxy-keep-password")
                    } else {
                        fl!("optional")
                    },
                    &editor.password,
                    None,
                    true,
                )
                .on_input(|value| Message::ProxyPassword(Password(value))),
            )
            .push(
                widget::button::text(fl!("clear-credentials"))
                    .on_press(Message::ClearProxyCredentials),
            );
        form.into()
    }

    fn interfaces_view(&self) -> Element<'_, Message> {
        let mut list = widget::column::with_capacity(16)
            .spacing(12)
            .push(widget::text::title3(fl!("network-interfaces")))
            .push(widget::text::body(fl!("interfaces-description")));
        for interface in &self.data.interfaces {
            let addresses = if interface.addresses.is_empty() {
                fl!("no-address")
            } else {
                interface.addresses.join(" · ")
            };
            list = list.push(
                widget::container(
                    widget::row::with_capacity(8)
                        .spacing(16)
                        .align_y(Alignment::Center)
                        .push(
                            widget::icon::from_name(if interface.kind == "Wi-Fi" {
                                "network-wireless-symbolic"
                            } else {
                                "network-wired-symbolic"
                            })
                            .size(32),
                        )
                        .push(
                            widget::column::with_capacity(16)
                                .spacing(5)
                                .push(widget::text::heading(format!(
                                    "{} · {}",
                                    interface.name, interface.kind
                                )))
                                .push(widget::text::body(addresses))
                                .width(Length::Fill),
                        )
                        .push(widget::text::caption(if interface.default {
                            fl!("default-route")
                        } else if interface.up {
                            fl!("up")
                        } else {
                            fl!("down")
                        })),
                )
                .padding(18)
                .class(cosmic::theme::Container::Card),
            );
        }
        widget::scrollable(list).height(Length::Fill).into()
    }

    fn activity_view(&self) -> Element<'_, Message> {
        let mut list = widget::column::with_capacity(16)
            .spacing(14)
            .push(widget::text::title3(fl!("activity")))
            .push(widget::text::body(fl!("activity-description")));
        if self.data.events.is_empty() {
            list = list.push(widget::text::body(fl!("no-activity")));
        }
        for event in &self.data.events {
            list = list.push(
                widget::row::with_capacity(8)
                    .spacing(20)
                    .push(widget::text::caption(&event.time).width(Length::Fixed(72.)))
                    .push(widget::text::body(&event.text)),
            );
        }
        widget::scrollable(list).height(Length::Fill).into()
    }
}
