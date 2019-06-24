
use {
    std::{
        error::Error,
        fs::{self, File, OpenOptions},
        fmt::{self, Display, Formatter},
        io::{self, BufReader, BufRead, Seek, Write, SeekFrom},
        path::{Path, PathBuf},
        result::Result,
        str::FromStr,
    },
    regex::Regex,
    sha1::{Digest, Sha1},
    steamy_vdf as vdf,
};

fn err_box<T, E: Error + 'static>(e: E) -> Result<T, Box<dyn Error>> {
    Err(Box::new(e))
}

struct Change {
    offset:   u64,
    original: &'static [u8],
    patch:    &'static [u8],
}

struct Version {
    unpatched_hash: &'static str,
    patched_hash:   &'static str,
    changes:        &'static [Change],
}

enum Action {
    Apply, Undo
}

impl Version {
    fn modify_file(&self, action: Action, file: &mut File) -> Result<(), io::Error> {
        for change in self.changes {
            file.seek(SeekFrom::Start(change.offset))?;
            let bytes = match action {
                Action::Apply => &change.patch,
                Action::Undo  => &change.original
            };
            file.write_all(bytes)?;
        }
        Ok(())
    }
}

static VERSIONS: [Version; 1] = [
    Version { // win32, with cl:ffs, as of 2019-06-24
        unpatched_hash: "bc1d695c6fdb3dea491b367f73bbb045c316b32e",
        patched_hash:   "fc8afce04782532b0fe7a70a80ee1070da858e32",
        changes:        &[
            // remove the "say" string prefixed to console entries
            Change { offset: 0x012f_8b90, original: &[0x73], patch: &[0x00] },
            // enable dev commands
            Change { offset: 0x0169_9cb2, original: &[0xb8], patch: &[0xb7] },
            // enable 'set'
            Change { offset: 0x0042_d740, original: &[0xc0], patch: &[0xff] },
        ]
    },
];

#[derive(Clone, Debug)]
enum PatcherError {
    UnknownVersion { hash: Digest },
    BadVDF { path: String },
    CantFindManifest { appid: u32 },
}

impl Display for PatcherError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            PatcherError::UnknownVersion { hash } => {
                write!(f, "Unknown executable version: SHA1: {}", hash)
            }
            PatcherError::BadVDF { path } => {
                write!(f, "Invalid VDF file: {}", path)
            }
            PatcherError::CantFindManifest { appid } => {
                write!(f, "Cannot find manifest for appid {}", appid)
            }
        }
    }
}

impl Error for PatcherError { }

struct ExeState {
    version: &'static Version,
    patched: bool,
}

fn get_exe_state(file: &mut File) -> Result<ExeState, Box<dyn Error>> {
    file.seek(SeekFrom::Start(0))?;

    // compute the SHA-1
    let file_hash = {
        let mut buf = BufReader::with_capacity(0x10000, file);
        let mut hasher = Sha1::new();

        loop {
            let len = match buf.fill_buf().expect("I/O Error") {
                slice if !slice.is_empty() => {
                    hasher.update(slice);
                    slice.len()
                }
                _ => { break; }
            };
            buf.consume(len);
        }

        hasher.digest()
    };

    // check against known versions
    for version in VERSIONS.iter() {
        if file_hash == Digest::from_str(version.unpatched_hash).unwrap() {
            return Ok(ExeState { version, patched: false });
        }
        else if file_hash == Digest::from_str(version.patched_hash).unwrap() {
            return Ok(ExeState { version, patched: true });
        }
    }

    err_box(PatcherError::UnknownVersion { hash: file_hash })
}

fn load_libraries_vdf(path: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let fail = || err_box(PatcherError::BadVDF { path: path.to_string_lossy().to_string() });

    let root = match vdf::load(path)? {
        vdf::Entry::Table(tab) => tab,
        _ => return fail()
    };

    let entries = match root.get("LibraryFolders") {
        Some(vdf::Entry::Table(tab)) => tab,
        _ => return fail()
    };

    let paths = entries
        .iter()
        .filter_map(|(k, v)| -> Option<PathBuf> {
            let _index: u32 = k.parse().ok()?;
            match v {
                vdf::Entry::Value(path) => {
                    let path = PathBuf::from(path.to_string()).canonicalize().ok()?;
                    Some(path)
                }
                _ => None
            }
        })
        .collect();

    Ok(paths)
}

fn get_install_dir_from_manifest(manifest_path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let fail = || err_box(PatcherError::BadVDF {
        path: manifest_path.to_string_lossy().to_string()
    });

    //  println!("trying manifest path: {}", manifest_path.to_string_lossy());

    let manifest: String = fs::read_to_string(manifest_path)?;

    //                     multi-line          some space
    //                     |  start of line     | "<value>"
    //                     |   |some space?     |     |    some space?
    //                     |   | | "installdir" |     |     | end of line
    //                     |   | |      |       |     |     | |
    let re = Regex::new(r#"(?m)^\s*"installdir"\s+"([^"]+)"\s*$"#).unwrap();
    let captures = match re.captures(&manifest) {
        Some(caps) => caps,
        None => return fail()
    };

    let path = match captures.get(1) {
        Some(group) => PathBuf::from("common").join(group.as_str()),
        None => return fail()
    };

    Ok(path)

    // TODO: fix steamy_vdf so it can deal with manifests
    //       maybe empty items (like "") are tripping it up?
    //  let root = match vdf::load(manifest_path)? {
    //      vdf::Entry::Table(tab) => tab,
    //      _ => return fail()
    //  };
    //
    //  let entries = match root.get("AppState") {
    //      Some(vdf::Entry::Table(tab)) => tab,
    //      _ => return fail()
    //  };
    //
    //  match entries.get("installdir") {
    //      Some(vdf::Entry::Value(dir)) => Ok(PathBuf::from(dir.to_string())),
    //      _ => fail()
    //  }
}

fn find_install_path(appid: u32) -> Result<PathBuf, Box<dyn Error>> {
    // find library folders
    let home: PathBuf = std::env::var("HOME")?.into();
    let home_steam = home.join(".steam/steam").canonicalize()?;
    let home_steamapps = home_steam.join("steamapps");

    let libraries_file_path = home_steamapps.join("libraryfolders.vdf");
    let library_paths = {
        let mut paths = load_libraries_vdf(&libraries_file_path)?;
        paths.push(home_steam);
        paths
    };
    //  eprintln!("Steam library paths:");
    //  for path in &library_paths { eprintln!("    {}", path.to_string_lossy()); }

    // find and open the relevant manifest
    let manifest_filename = format!("appmanifest_{}.acf", appid);

    library_paths.iter()
        .find_map(|library_path| {
            let steamapps = library_path.join("steamapps");
            let manifest_path = steamapps.join(&manifest_filename);
            let install_dir = match get_install_dir_from_manifest(&manifest_path) {
                Ok(dir) => dir,
                e => return Some(e)
            };
            let install_path = steamapps.join(install_dir);
            Some(Ok(install_path))
        })
        .unwrap_or(err_box(PatcherError::CantFindManifest { appid }))
}

fn main() -> Result<(), Box<dyn Error>> {
    let install_path = find_install_path(49520)?;

    // println!("49520 install path: {}", install_path.to_string_lossy());

    let exe_path = install_path.join("Binaries/Win32/Borderlands2.exe");
    // println!("exe_path: {}", exe_path.to_string_lossy());

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .open(&exe_path)?;

    // check it's a file we know how to patch!
    let state = get_exe_state(&mut file)?;

    let result: Result<(), Box<dyn Error>> = {
        let action = if !state.patched {
            // make a backup!
            // TODO

            eprint!("Patching {} ...", exe_path.to_string_lossy());
            Action::Apply
        }
        else {
            // unpatch
            eprint!("Unpatching {} ...", exe_path.to_string_lossy());
            Action::Undo
        };

        // actually patch
        state.version.modify_file(action, &mut file)?;

        // verify
        get_exe_state(&mut file)?;

        Ok(())
    };

    if let Err(e) = result {
        eprintln!("Error while modifying executable: {}\nYou should restore from your backup.", e);
        // TODO: restore backup
    }
    else {
        eprintln!("OK!");
    }

    Ok(())
}
