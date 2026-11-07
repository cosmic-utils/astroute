use crate::{Message, fl};
use cosmic::iced::{
    self, Subscription,
    futures::{SinkExt, StreamExt, channel::mpsc},
};
use ksni::TrayMethods;
use std::{sync::LazyLock, time::Duration};

const ICON: &[u8] =
    include_bytes!("../resources/icons/hicolor/scalable/apps/io.github.astroute.Astroute.svg");

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Show,
    Enable,
    Disable,
    Quit,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct State {
    pub enabled: Option<bool>,
    pub busy: bool,
    pub quitting: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Controller(mpsc::UnboundedSender<Command>);

impl Controller {
    pub fn update(&self, state: State) {
        let _ = self.0.unbounded_send(Command::State(state));
    }
}

#[derive(Debug)]
enum Command {
    State(State),
    Action(Action, Option<String>),
    Available(bool),
}

struct Service(ksni::Handle<Item>);

impl Drop for Service {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

pub fn subscription() -> Subscription<Message> {
    Subscription::run(|| {
        iced::stream::channel(16, |mut output: mpsc::Sender<Message>| async move {
            let (sender, mut input) = mpsc::unbounded();
            if output
                .send(Message::TrayReady(Controller(sender.clone())))
                .await
                .is_err()
            {
                return;
            }
            let mut service: Option<Service> = None;
            let mut retry = tokio::time::interval(Duration::from_secs(10));
            let mut state = State::default();
            loop {
                tokio::select! {
                    _ = retry.tick(), if service.is_none() => {
                        let item = Item { sender: sender.clone(), state: state.clone() };
                        let result = tokio::time::timeout(Duration::from_secs(5), item.spawn()).await;
                        match result {
                            Ok(Ok(handle)) => {
                                service = Some(Service(handle));
                                if output.send(Message::TrayAvailable(true)).await.is_err() {
                                    break;
                                }
                            }
                            error => {
                                let error = match error {
                                    Ok(Err(error)) => error.to_string(),
                                    _ => "Tray registration timed out".into(),
                                };
                                if output.send(Message::TrayUnavailable(error)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    command = input.next() => {
                        let Some(command) = command else { break };
                        let message = match command {
                            Command::State(next) => {
                                if state != next {
                                    state = next;
                                    if let Some(service) = &service {
                                        let next = state.clone();
                                        service.0.update(move |item| item.state = next).await;
                                    }
                                }
                                continue;
                            }
                            Command::Action(action, token) => Message::TrayAction(action, token),
                            Command::Available(available) => Message::TrayAvailable(available),
                        };
                        if output.send(message).await.is_err() {
                            break;
                        }
                    }
                }
            }
        })
    })
}

struct Item {
    sender: mpsc::UnboundedSender<Command>,
    state: State,
}

impl Item {
    fn send(&self, action: Action) {
        let _ = self.sender.unbounded_send(Command::Action(
            action,
            ksni::current_xdg_activation_token(),
        ));
    }

    fn action_item(&self, label: String, action: Action, enabled: bool) -> ksni::MenuItem<Self> {
        ksni::menu::StandardItem {
            label: label.replace('_', "__"),
            enabled,
            activate: Box::new(move |item: &mut Self| item.send(action)),
            ..Default::default()
        }
        .into()
    }

    fn status_text(&self) -> String {
        if self.state.quitting {
            fl!("quitting")
        } else if self.state.busy {
            fl!("working")
        } else {
            match self.state.enabled {
                Some(true) => fl!("controls-active"),
                Some(false) => fl!("monitor-only"),
                None => fl!("loading"),
            }
        }
    }
}

impl ksni::Tray for Item {
    fn id(&self) -> String {
        "io.github.astroute.Astroute".into()
    }

    fn title(&self) -> String {
        "Astroute".into()
    }

    fn icon_name(&self) -> String {
        "io.github.astroute.Astroute-symbolic".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        static PIXMAPS: LazyLock<Vec<ksni::Icon>> = LazyLock::new(|| {
            [16, 24, 32, 48]
                .into_iter()
                .filter_map(|size| {
                    let mut data = rasterize(size)?;
                    for pixel in data.as_chunks_mut::<4>().0 {
                        pixel.rotate_right(1);
                    }
                    Some(ksni::Icon {
                        width: size as i32,
                        height: size as i32,
                        data,
                    })
                })
                .collect()
        });
        PIXMAPS.clone()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        let description = self.state.error.as_deref().map_or_else(
            || self.status_text(),
            |error| {
                error
                    .replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
            },
        );
        ksni::ToolTip {
            icon_name: self.icon_name(),
            title: self.title(),
            description,
            ..Default::default()
        }
    }

    fn activate(&mut self, _: i32, _: i32) {
        self.send(Action::Show);
    }

    fn watcher_online(&self) {
        let _ = self.sender.unbounded_send(Command::Available(true));
    }

    fn watcher_offline(&self, _: ksni::OfflineReason) -> bool {
        let _ = self.sender.unbounded_send(Command::Available(false));
        true
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        let toggle = if self.state.enabled == Some(true) {
            (fl!("disable-controls"), Action::Disable)
        } else {
            (fl!("enable-controls"), Action::Enable)
        };
        vec![
            self.action_item(fl!("show-app"), Action::Show, true),
            ksni::MenuItem::Separator,
            ksni::menu::StandardItem {
                label: self.status_text(),
                enabled: false,
                ..Default::default()
            }
            .into(),
            self.action_item(
                toggle.0,
                toggle.1,
                self.state.enabled.is_some() && !self.state.busy && !self.state.quitting,
            ),
            ksni::MenuItem::Separator,
            self.action_item(fl!("quit-app"), Action::Quit, !self.state.quitting),
        ]
    }
}

pub fn window_icon() -> Option<iced::window::Icon> {
    iced::window::icon::from_rgba(rasterize(64)?, 64, 64).ok()
}

fn rasterize(size: u32) -> Option<Vec<u8>> {
    let tree = resvg::usvg::Tree::from_data(ICON, &resvg::usvg::Options::default()).ok()?;
    let mut pixmap = resvg::tiny_skia::Pixmap::new(size, size)?;
    resvg::render(
        &tree,
        resvg::tiny_skia::Transform::from_scale(
            size as f32 / tree.size().width(),
            size as f32 / tree.size().height(),
        ),
        &mut pixmap.as_mut(),
    );
    // tiny-skia stores premultiplied pixels; SNI and window icons use straight RGBA.
    let mut bytes = pixmap.take();
    for pixel in bytes.as_chunks_mut::<4>().0 {
        let alpha = u32::from(pixel[3]);
        if alpha > 0 && alpha < 255 {
            for channel in &mut pixel[..3] {
                *channel = ((u32::from(*channel) * 255 + alpha / 2) / alpha).min(255) as u8;
            }
        }
    }
    Some(bytes)
}
