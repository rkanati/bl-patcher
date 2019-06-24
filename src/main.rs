
use {
    std::{
        error::Error,
        fs::{File, OpenOptions},
        fmt::{self, Display, Formatter},
        io::{self, BufReader, BufRead, Seek, Write, SeekFrom},
        result::Result,
        str::FromStr,
    },
    sha1::{Digest, Sha1},
};

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

impl Version {
    fn apply_patch(&self, file: &mut File) -> Result<(), io::Error> {
        for change in self.changes {
            file.seek(SeekFrom::Start(change.offset))?;
            file.write_all(&change.patch)?;
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

#[derive(Clone, Copy, Debug)]
enum PatcherError {
    UnknownVersion { hash: Digest },
}

impl Display for PatcherError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            PatcherError::UnknownVersion { hash } => {
                write!(f, "Unknown executable version: SHA1: {}", hash)
            }
        }
    }
}

impl Error for PatcherError { }

fn find_version(file: &File) -> Result<&'static Version, Box<dyn Error>> {
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
        let expected_hash = Digest::from_str(version.unpatched_hash).unwrap();

        if file_hash == expected_hash {
            return Ok(version);
        }
    }

    let error = PatcherError::UnknownVersion { hash: file_hash };
    return Err(Box::new(error));
}

fn find_game() {
    // TODO
    // 1. use ~/.steam/steam/{steamapps,SteamApps}/libraryfolders.vcf to find roots
    // 2. check above + library roots for appmanifest_<appid>.acf
    // 3. open manifest, extract install dir
    // 4. look under <current root>/steamapps/<install dir>/Binaries for executable
}

fn main() -> Result<(), Box<dyn Error>> {
    eprintln!("checking bl2 executable");

    // open the exe
    const PATH: &'static str =
        "/steamlib/steamapps/common/Borderlands 2/Binaries/Win32/Borderlands2.exe";
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .open(PATH)?;

    // check it's a file we know how to patch!
    let version = find_version(&file)?;

    // make a backup!
    // TODO

    // actually patch
    if let Err(e) = version.apply_patch(&mut file) {
        // TODO: restore backup
        eprintln!("I/O error while patching: {}\nYou should restore from you backup.", e);
    }
    else {
        eprintln!("Patch successful");
    }

    Ok(())
}
