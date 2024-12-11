use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn install_options(&self) -> String {
        install_options()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn install_options();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAA2hpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMy1jMDExIDY2LjE0NTY2MSwgMjAxMi8wMi8wNi0xNDo1NjoyNyAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDpGOTVFNzEyRjA5MjA2ODExODIyQThBQ0ZERkYxNkMyQSIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDoyNjcyMDZBREM2MUIxMUUzOUM5NkI5REMzNEFGQzYwQiIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDoyNjcyMDZBQ0M2MUIxMUUzOUM5NkI5REMzNEFGQzYwQiIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ1M2IChNYWNpbnRvc2gpIj4gPHhtcE1NOkRlcml2ZWRGcm9tIHN0UmVmOmluc3RhbmNlSUQ9InhtcC5paWQ6QkFDMkFERTUxOEM2RTMxMUI2ODRGRDYwOEUwMDE1ODQiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6Rjk1RTcxMkYwOTIwNjgxMTgyMkE4QUNGREZGMTZDMkEiLz4gPC9yZGY6RGVzY3Jp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".into()
    }
}
