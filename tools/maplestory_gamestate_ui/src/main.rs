use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, Sense, Shape, Stroke, Vec2};
use serde::Deserialize;

const DEFAULT_STATE_FILE: &str = "/tmp/maple-live-gamestate.json";
const REFRESH_INTERVAL: Duration = Duration::from_millis(75);

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct Snapshot {
    schema_version: u32,
    connection: Connection,
    handshake: Option<Handshake>,
    state: GameState,
    fold: FoldStatus,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct Connection {
    status: String,
    upstream_host: String,
    upstream_port: u16,
    updated_at_ns: u64,
    error: Option<String>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct Handshake {
    version: u16,
    subversion: String,
    locale: u8,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct GameState {
    phase: String,
    field_epoch: u64,
    map_id: Option<i64>,
    portal_index: Option<i64>,
    player: Player,
    platforms: Vec<Platform>,
    enemies: Vec<Enemy>,
    remote_players: Vec<RemotePlayer>,
    drops: Vec<FieldDrop>,
    inventory: Vec<InventoryGroup>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct Player {
    x: Option<i32>,
    y: Option<i32>,
    platform: Option<String>,
    current_hp: Option<i64>,
    max_hp: Option<i64>,
    current_mp: Option<i64>,
    max_mp: Option<i64>,
    level: Option<i64>,
    job_id: Option<i64>,
    mesos: Option<i64>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct Platform {
    id: String,
    foothold_id: Option<i64>,
    x_min: i32,
    x_max: i32,
    y: i32,
    confidence: String,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct Enemy {
    entity: String,
    template_id: i64,
    x: i32,
    y: i32,
    foothold_id: Option<i64>,
    health_percentage: Option<i64>,
    max_hp: Option<i64>,
    health_hp_min: Option<i64>,
    health_hp_max: Option<i64>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct RemotePlayer {
    entity: String,
    x: Option<i32>,
    y: Option<i32>,
    level: Option<i64>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct FieldDrop {
    drop: String,
    kind: String,
    value: i64,
    x: i32,
    y: i32,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct InventoryGroup {
    name: String,
    items: Vec<InventoryItem>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct InventoryItem {
    slot: i32,
    item_id: i64,
    cash_item: bool,
    quantity: Option<i64>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct FoldStatus {
    issues: Vec<String>,
    warnings: Vec<String>,
    decode_errors: Vec<String>,
    events: usize,
    last_packet: Option<LastPacket>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct LastPacket {
    direction: String,
    opcode: Option<i64>,
    kind: String,
    coverage: String,
}

struct MapleApp {
    state_file: PathBuf,
    snapshot: Snapshot,
    load_error: Option<String>,
    last_refresh: Instant,
}

impl MapleApp {
    fn new(state_file: PathBuf) -> Self {
        let mut app = Self {
            state_file,
            snapshot: Snapshot::default(),
            load_error: None,
            last_refresh: Instant::now()
                .checked_sub(REFRESH_INTERVAL)
                .unwrap_or_else(Instant::now),
        };
        app.reload();
        app
    }

    fn reload(&mut self) {
        if self.last_refresh.elapsed() < REFRESH_INTERVAL {
            return;
        }
        self.last_refresh = Instant::now();
        match fs::read_to_string(&self.state_file) {
            Ok(contents) => match serde_json::from_str::<Snapshot>(&contents) {
                Ok(snapshot) => {
                    self.snapshot = snapshot;
                    self.load_error = None;
                }
                Err(error) => {
                    self.load_error = Some(format!("invalid snapshot: {error}"));
                }
            },
            Err(error) => {
                self.load_error = Some(format!(
                    "waiting for {}: {error}",
                    self.state_file.display()
                ));
            }
        }
    }

    fn top_bar(&self, root: &mut egui::Ui) {
        egui::Panel::top("status").show(root, |ui| {
            ui.horizontal_wrapped(|ui| {
                let connected = self.snapshot.connection.status == "connected";
                let color = if connected {
                    Color32::from_rgb(76, 201, 137)
                } else {
                    Color32::from_rgb(232, 166, 66)
                };
                ui.colored_label(color, format!("● {}", self.snapshot.connection.status));
                ui.separator();
                ui.monospace(format!(
                    "{}:{}",
                    self.snapshot.connection.upstream_host, self.snapshot.connection.upstream_port
                ));
                ui.separator();
                ui.label(format!("phase {}", self.snapshot.state.phase));
                ui.label(format!("field #{}", self.snapshot.state.field_epoch));
                ui.label(
                    self.snapshot
                        .state
                        .map_id
                        .map_or_else(|| "map ?".to_owned(), |map| format!("map {map}")),
                );
                if let Some(age) = snapshot_age_seconds(self.snapshot.connection.updated_at_ns) {
                    ui.label(format!("{age:.1}s old"));
                }
                if self.snapshot.schema_version != 1 && self.snapshot.schema_version != 0 {
                    ui.colored_label(
                        Color32::YELLOW,
                        format!("schema {}", self.snapshot.schema_version),
                    );
                }
            });
        });
    }

    #[allow(clippy::too_many_lines)]
    fn player_panel(&self, root: &mut egui::Ui) {
        egui::Panel::left("player")
            .resizable(true)
            .default_size(250.0)
            .show(root, |ui| {
                ui.heading("Player");
                resource_bar(
                    ui,
                    "HP",
                    self.snapshot.state.player.current_hp,
                    self.snapshot.state.player.max_hp,
                    Color32::from_rgb(210, 64, 70),
                );
                resource_bar(
                    ui,
                    "MP",
                    self.snapshot.state.player.current_mp,
                    self.snapshot.state.player.max_mp,
                    Color32::from_rgb(61, 125, 222),
                );
                ui.separator();
                value_row(
                    ui,
                    "position",
                    match (self.snapshot.state.player.x, self.snapshot.state.player.y) {
                        (Some(x), Some(y)) => format!("{x}, {y}"),
                        _ => "unknown".to_owned(),
                    },
                );
                value_row(
                    ui,
                    "platform",
                    self.snapshot
                        .state
                        .player
                        .platform
                        .as_deref()
                        .unwrap_or("unknown"),
                );
                value_row(
                    ui,
                    "level",
                    optional_number(self.snapshot.state.player.level),
                );
                value_row(
                    ui,
                    "job",
                    optional_number(self.snapshot.state.player.job_id),
                );
                value_row(
                    ui,
                    "mesos",
                    optional_number(self.snapshot.state.player.mesos),
                );

                ui.add_space(12.0);
                ui.heading("Enemies");
                egui::ScrollArea::vertical()
                    .id_salt("enemy-list")
                    .max_height(260.0)
                    .show(ui, |ui| {
                        if self.snapshot.state.enemies.is_empty() {
                            ui.weak("No modeled enemies in the active field");
                        }
                        for enemy in &self.snapshot.state.enemies {
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.colored_label(Color32::LIGHT_RED, &enemy.entity);
                                    ui.monospace(format!("mob {}", enemy.template_id));
                                });
                                ui.small(format!(
                                    "({}, {}) · foothold {}",
                                    enemy.x,
                                    enemy.y,
                                    enemy
                                        .foothold_id
                                        .map_or_else(|| "?".to_owned(), |id| id.to_string())
                                ));
                                enemy_health(ui, enemy);
                            });
                        }
                    });

                ui.add_space(10.0);
                ui.heading("Decoder");
                ui.label(format!("{} folded events", self.snapshot.fold.events));
                if let Some(packet) = &self.snapshot.fold.last_packet {
                    ui.small(format!(
                        "{} opcode {} · {} · {}",
                        compact_direction(&packet.direction),
                        packet
                            .opcode
                            .map_or_else(|| "?".to_owned(), |opcode| opcode.to_string()),
                        packet.kind,
                        packet.coverage
                    ));
                }
                if let Some(handshake) = &self.snapshot.handshake {
                    ui.small(format!(
                        "protocol {} / {} · locale {}",
                        handshake.version, handshake.subversion, handshake.locale
                    ));
                }
            });
    }

    fn inventory_panel(&self, root: &mut egui::Ui) {
        egui::Panel::right("inventory")
            .resizable(true)
            .default_size(300.0)
            .show(root, |ui| {
                ui.heading("Inventory");
                egui::ScrollArea::vertical().show(ui, |ui| {
                    if self.snapshot.state.inventory.is_empty() {
                        ui.weak("Waiting for a typed initial-field snapshot");
                    }
                    for group in &self.snapshot.state.inventory {
                        egui::CollapsingHeader::new(format!(
                            "{} ({})",
                            title_case(&group.name),
                            group.items.len()
                        ))
                        .default_open(!group.items.is_empty())
                        .show(ui, |ui| {
                            egui::Grid::new(format!("inventory-{}", group.name))
                                .striped(true)
                                .num_columns(3)
                                .show(ui, |ui| {
                                    ui.strong("slot");
                                    ui.strong("item");
                                    ui.strong("qty");
                                    ui.end_row();
                                    for item in &group.items {
                                        ui.monospace(item.slot.to_string());
                                        let cash = if item.cash_item { " ◇" } else { "" };
                                        ui.monospace(format!("{}{cash}", item.item_id));
                                        ui.monospace(item.quantity.map_or_else(
                                            || "—".to_owned(),
                                            |quantity| quantity.to_string(),
                                        ));
                                        ui.end_row();
                                    }
                                });
                        });
                    }
                });
            });
    }

    #[allow(clippy::too_many_lines)]
    fn world_view(&self, root: &mut egui::Ui) {
        egui::CentralPanel::default().show(root, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Observed field");
                ui.weak("foothold spans are inferred from NPC ranges and entity positions");
            });
            let available = ui.available_size().max(Vec2::new(100.0, 100.0));
            let (response, painter) = ui.allocate_painter(available, Sense::hover());
            let rect = response.rect.shrink(12.0);
            painter.rect_filled(rect, 8.0, Color32::from_rgb(15, 20, 29));

            let bounds = WorldBounds::from_state(&self.snapshot.state);
            let project = |x: i32, y: i32| bounds.project(rect, x, y);

            draw_grid(&painter, rect);
            for platform in &self.snapshot.state.platforms {
                let left = project(platform.x_min, platform.y);
                let right = project(platform.x_max, platform.y);
                let color = match platform.confidence.as_str() {
                    "npc_range" => Color32::from_rgb(119, 192, 139),
                    "foothold_entity" => Color32::from_rgb(103, 151, 190),
                    _ => Color32::from_rgb(104, 112, 128),
                };
                painter.line_segment([left, right], Stroke::new(4.0, color));
                painter.circle_filled(left, 3.5, color);
                painter.circle_filled(right, 3.5, color);
                let label = platform.foothold_id.map_or_else(
                    || "estimated".to_owned(),
                    |foothold| format!("fh {foothold}"),
                );
                painter.text(
                    left + Vec2::new(4.0, 5.0),
                    Align2::LEFT_TOP,
                    label,
                    FontId::monospace(10.0),
                    Color32::from_gray(155),
                );
            }

            for drop in &self.snapshot.state.drops {
                let center = project(drop.x, drop.y);
                painter.add(Shape::convex_polygon(
                    vec![
                        center + Vec2::new(0.0, -5.0),
                        center + Vec2::new(5.0, 0.0),
                        center + Vec2::new(0.0, 5.0),
                        center + Vec2::new(-5.0, 0.0),
                    ],
                    Color32::from_rgb(239, 193, 72),
                    Stroke::NONE,
                ));
                painter.text(
                    center + Vec2::new(7.0, 0.0),
                    Align2::LEFT_CENTER,
                    format!("{} {} {}", drop.drop, drop.kind, drop.value),
                    FontId::monospace(10.0),
                    Color32::from_rgb(239, 211, 125),
                );
            }

            for player in &self.snapshot.state.remote_players {
                if let (Some(x), Some(y)) = (player.x, player.y) {
                    let center = project(x, y);
                    painter.circle_filled(center, 6.0, Color32::from_rgb(91, 160, 232));
                    painter.text(
                        center + Vec2::new(0.0, -9.0),
                        Align2::CENTER_BOTTOM,
                        player.level.map_or_else(
                            || player.entity.clone(),
                            |level| format!("{} L{level}", player.entity),
                        ),
                        FontId::monospace(10.0),
                        Color32::LIGHT_BLUE,
                    );
                }
            }

            for enemy in &self.snapshot.state.enemies {
                let center = project(enemy.x, enemy.y);
                painter.circle_filled(center, 7.0, Color32::from_rgb(221, 78, 83));
                painter.circle_stroke(center, 8.5, Stroke::new(1.5, Color32::LIGHT_RED));
                painter.text(
                    center + Vec2::new(0.0, -12.0),
                    Align2::CENTER_BOTTOM,
                    format!(
                        "{} · {}%",
                        enemy.entity,
                        enemy
                            .health_percentage
                            .map_or_else(|| "?".to_owned(), |hp| hp.to_string())
                    ),
                    FontId::monospace(10.0),
                    Color32::from_rgb(247, 166, 166),
                );
            }

            if let (Some(x), Some(y)) = (self.snapshot.state.player.x, self.snapshot.state.player.y)
            {
                let center = project(x, y);
                painter.circle_filled(center, 8.0, Color32::from_rgb(72, 222, 145));
                painter.circle_stroke(center, 10.0, Stroke::new(2.0, Color32::WHITE));
                painter.text(
                    center + Vec2::new(0.0, -14.0),
                    Align2::CENTER_BOTTOM,
                    format!("YOU ({x}, {y})"),
                    FontId::monospace(11.0),
                    Color32::WHITE,
                );
            } else {
                painter.text(
                    rect.center(),
                    Align2::CENTER_CENTER,
                    "Waiting for a modeled player position",
                    FontId::proportional(17.0),
                    Color32::from_gray(150),
                );
            }

            painter.text(
                rect.left_bottom() + Vec2::new(10.0, -10.0),
                Align2::LEFT_BOTTOM,
                "● you    ● enemy    ● remote player    ◆ drop",
                FontId::monospace(11.0),
                Color32::from_gray(170),
            );
        });
    }

    fn error_panel(&self, root: &mut egui::Ui) {
        let mut messages = Vec::new();
        if let Some(error) = &self.load_error {
            messages.push(error.as_str());
        }
        if let Some(error) = &self.snapshot.connection.error {
            messages.push(error.as_str());
        }
        messages.extend(self.snapshot.fold.decode_errors.iter().map(String::as_str));
        messages.extend(self.snapshot.fold.issues.iter().map(String::as_str));
        messages.extend(self.snapshot.fold.warnings.iter().map(String::as_str));
        if messages.is_empty() {
            return;
        }
        egui::Panel::bottom("problems")
            .resizable(true)
            .default_size(55.0)
            .show(root, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for message in messages {
                        ui.colored_label(Color32::from_rgb(235, 175, 91), message);
                    }
                });
            });
    }
}

impl eframe::App for MapleApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.reload();
        self.top_bar(ui);
        self.error_panel(ui);
        self.player_panel(ui);
        self.inventory_panel(ui);
        self.world_view(ui);
        ui.ctx().request_repaint_after(REFRESH_INTERVAL);
    }
}

#[derive(Clone, Copy)]
struct WorldBounds {
    min_x: f32,
    max_x: f32,
    min_y: f32,
    max_y: f32,
}

impl WorldBounds {
    #[allow(clippy::cast_precision_loss)]
    fn from_state(state: &GameState) -> Self {
        let mut points = Vec::new();
        if let (Some(x), Some(y)) = (state.player.x, state.player.y) {
            points.push((x, y));
        }
        points.extend(state.enemies.iter().map(|enemy| (enemy.x, enemy.y)));
        points.extend(
            state
                .remote_players
                .iter()
                .filter_map(|player| Some((player.x?, player.y?))),
        );
        points.extend(state.drops.iter().map(|drop| (drop.x, drop.y)));
        for platform in &state.platforms {
            points.push((platform.x_min, platform.y));
            points.push((platform.x_max, platform.y));
        }
        if points.is_empty() {
            return Self {
                min_x: -200.0,
                max_x: 200.0,
                min_y: -150.0,
                max_y: 150.0,
            };
        }
        let (mut min_x, mut max_x, mut min_y, mut max_y) = (
            f32::INFINITY,
            f32::NEG_INFINITY,
            f32::INFINITY,
            f32::NEG_INFINITY,
        );
        for (x, y) in points {
            min_x = min_x.min(x as f32);
            max_x = max_x.max(x as f32);
            min_y = min_y.min(y as f32);
            max_y = max_y.max(y as f32);
        }
        let x_padding = ((max_x - min_x) * 0.12).max(80.0);
        let y_padding = ((max_y - min_y) * 0.18).max(60.0);
        Self {
            min_x: min_x - x_padding,
            max_x: max_x + x_padding,
            min_y: min_y - y_padding,
            max_y: max_y + y_padding,
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn project(self, rect: Rect, x: i32, y: i32) -> Pos2 {
        let width = (self.max_x - self.min_x).max(1.0);
        let height = (self.max_y - self.min_y).max(1.0);
        let scale = (rect.width() / width).min(rect.height() / height);
        let drawn_width = width * scale;
        let drawn_height = height * scale;
        let origin = Pos2::new(
            rect.center().x - drawn_width / 2.0,
            rect.center().y - drawn_height / 2.0,
        );
        Pos2::new(
            origin.x + (x as f32 - self.min_x) * scale,
            origin.y + (y as f32 - self.min_y) * scale,
        )
    }
}

fn draw_grid(painter: &egui::Painter, rect: Rect) {
    let stroke = Stroke::new(1.0, Color32::from_rgb(29, 38, 51));
    let spacing = 48.0;
    let mut x = rect.left();
    while x <= rect.right() {
        painter.line_segment(
            [Pos2::new(x, rect.top()), Pos2::new(x, rect.bottom())],
            stroke,
        );
        x += spacing;
    }
    let mut y = rect.top();
    while y <= rect.bottom() {
        painter.line_segment(
            [Pos2::new(rect.left(), y), Pos2::new(rect.right(), y)],
            stroke,
        );
        y += spacing;
    }
}

#[allow(clippy::cast_precision_loss)]
fn resource_bar(
    ui: &mut egui::Ui,
    label: &str,
    current: Option<i64>,
    maximum: Option<i64>,
    color: Color32,
) {
    let fraction = match (current, maximum) {
        (Some(value), Some(maximum)) if maximum > 0 => value as f32 / maximum as f32,
        _ => 0.0,
    }
    .clamp(0.0, 1.0);
    let text = match (current, maximum) {
        (Some(value), Some(maximum)) => format!("{label}  {value} / {maximum}"),
        _ => format!("{label}  unknown"),
    };
    ui.add(egui::ProgressBar::new(fraction).text(text).fill(color));
}

#[allow(clippy::cast_precision_loss)]
fn enemy_health(ui: &mut egui::Ui, enemy: &Enemy) {
    let fraction = enemy
        .health_percentage
        .map_or(0.0, |health| health as f32 / 100.0)
        .clamp(0.0, 1.0);
    let text = match (
        enemy.health_percentage,
        enemy.health_hp_min,
        enemy.health_hp_max,
        enemy.max_hp,
    ) {
        (Some(percent), Some(low), Some(high), Some(maximum)) => {
            format!("{percent}% · {low}–{high} / {maximum}")
        }
        (Some(percent), _, _, _) => format!("{percent}%"),
        _ => "HP unknown".to_owned(),
    };
    ui.add(
        egui::ProgressBar::new(fraction)
            .text(text)
            .fill(Color32::from_rgb(194, 63, 69)),
    );
}

fn value_row(ui: &mut egui::Ui, label: &str, value: impl Into<egui::RichText>) {
    ui.horizontal(|ui| {
        ui.weak(label);
        ui.monospace(value);
    });
}

fn optional_number(value: Option<i64>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |number| number.to_string())
}

fn compact_direction(direction: &str) -> &str {
    match direction {
        "client_to_server" => "C→S",
        "server_to_client" => "S→C",
        other => other,
    }
}

fn title_case(value: &str) -> String {
    let mut chars = value.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + chars.as_str()
    })
}

fn snapshot_age_seconds(updated_at_ns: u64) -> Option<f64> {
    if updated_at_ns == 0 {
        return None;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    Some(
        now.checked_sub(Duration::from_nanos(updated_at_ns))
            .unwrap_or_default()
            .as_secs_f64(),
    )
}

fn state_file_from_args() -> Result<PathBuf, String> {
    let mut args = env::args_os().skip(1);
    let mut state_file = PathBuf::from(DEFAULT_STATE_FILE);
    while let Some(argument) = args.next() {
        if argument == "--state-file" {
            state_file = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--state-file requires a path".to_owned())?;
        } else if argument == "--help" || argument == "-h" {
            println!(
                "MapleStory Classic live game-state dashboard\n\n\
                 Usage: maple-gamestate-ui [--state-file PATH]\n\n\
                 Default state file: {DEFAULT_STATE_FILE}"
            );
            std::process::exit(0);
        } else {
            return Err(format!(
                "unknown argument: {}",
                Path::new(&argument).display()
            ));
        }
    }
    Ok(state_file)
}

fn main() -> eframe::Result {
    let state_file = match state_file_from_args() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1320.0, 820.0]),
        ..Default::default()
    };
    eframe::run_native(
        "MapleStory Classic · Live Game State",
        options,
        Box::new(move |_creation_context| Ok(Box::new(MapleApp::new(state_file)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_maple_coordinates_inside_the_canvas() {
        let bounds = WorldBounds {
            min_x: -100.0,
            max_x: 100.0,
            min_y: -50.0,
            max_y: 50.0,
        };
        let rect = Rect::from_min_max(Pos2::ZERO, Pos2::new(800.0, 600.0));
        let center = bounds.project(rect, 0, 0);
        assert_eq!(center, rect.center());
        let corner = bounds.project(rect, -100, -50);
        assert!(rect.contains(corner));
    }

    #[test]
    fn accepts_sparse_proxy_snapshots() {
        let snapshot: Snapshot = serde_json::from_str(
            r#"{"schema_version":1,"connection":{"status":"connected"},"state":{"player":{"x":7,"y":9}}}"#,
        )
        .expect("snapshot should parse");
        assert_eq!(snapshot.state.player.x, Some(7));
        assert!(snapshot.state.enemies.is_empty());
    }
}
