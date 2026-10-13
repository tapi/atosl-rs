use atosl::{atosl, ObjectSymbolizer, ResolverKind, SymbolizeOptions, SymbolizeOutcome};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

#[test]
fn object_symbolizer_matches_symbolize_path() {
    let fixture = Fixture::build().unwrap();
    let addresses = fixture.addresses();

    let report = atosl::symbolize_path(&SymbolizeOptions {
        object_path: fixture.binary_path.clone(),
        load_address: fixture.load_address,
        addresses: addresses.clone(),
        ..Default::default()
    })
    .unwrap();

    let symbolizer = ObjectSymbolizer::open(&fixture.options()).unwrap();
    let frames = addresses
        .iter()
        .map(|&address| symbolizer.symbolize(fixture.load_address, address, false))
        .collect::<Vec<_>>();

    assert_eq!(frames, report.frames);
    assert_eq!(symbolizer.object_path(), report.object_path);
    assert_eq!(symbolizer.object_name(), report.object_name);
    assert_eq!(symbolizer.selected_slice(), report.selected_slice.as_ref());
}

#[test]
fn object_symbolizer_is_reusable() {
    let fixture = Fixture::build().unwrap();
    let symbolizer = ObjectSymbolizer::open(&fixture.options()).unwrap();
    let addresses = fixture.addresses();

    let first = addresses
        .iter()
        .map(|&address| symbolizer.symbolize(fixture.load_address, address, false))
        .collect::<Vec<_>>();
    assert!(
        first.iter().all(|outcome| matches!(
            outcome,
            SymbolizeOutcome::Resolved(frame) if frame.resolver == ResolverKind::Dwarf
        )),
        "{first:#?}"
    );

    // Lookups in a different order, repeated, give the same answers.
    for _ in 0..3 {
        for (index, &address) in addresses.iter().enumerate().rev() {
            assert_eq!(
                symbolizer.symbolize(fixture.load_address, address, false),
                first[index]
            );
        }
    }
}

#[test]
fn object_symbolizer_reports_address_below_load_address() {
    let fixture = Fixture::build().unwrap();
    let symbolizer = ObjectSymbolizer::open(&fixture.options()).unwrap();

    let outcome = symbolizer.symbolize(fixture.load_address, fixture.load_address - 1, false);
    let SymbolizeOutcome::Unresolved { error, .. } = outcome else {
        panic!("expected an unresolved outcome, got {outcome:?}");
    };
    assert!(error.contains("smaller than load address"), "{error}");
}

#[test]
fn object_symbolizer_open_fails_for_missing_file() {
    let tempdir = tempfile::tempdir().unwrap();
    let err = ObjectSymbolizer::open(&SymbolizeOptions {
        object_path: tempdir.path().join("missing"),
        ..Default::default()
    })
    .unwrap_err();
    assert!(err.to_string().contains("missing"), "{err:#}");
}

#[test]
fn object_symbolizer_can_be_shared_behind_a_mutex() {
    fn assert_send<T: Send>() {}
    assert_send::<ObjectSymbolizer>();

    let fixture = Fixture::build().unwrap();
    let symbolizer = Arc::new(Mutex::new(
        ObjectSymbolizer::open(&fixture.options()).unwrap(),
    ));
    let addresses = fixture.addresses();
    let expected = addresses
        .iter()
        .map(|&address| {
            symbolizer
                .lock()
                .unwrap()
                .symbolize(fixture.load_address, address, false)
        })
        .collect::<Vec<_>>();

    let handles = (0..4)
        .map(|_| {
            let symbolizer = Arc::clone(&symbolizer);
            let addresses = addresses.clone();
            let load_address = fixture.load_address;
            std::thread::spawn(move || {
                addresses
                    .iter()
                    .map(|&address| {
                        symbolizer
                            .lock()
                            .unwrap()
                            .symbolize(load_address, address, false)
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        assert_eq!(handle.join().unwrap(), expected);
    }
}

struct Fixture {
    _tempdir: TempDir,
    binary_path: PathBuf,
    load_address: u64,
    symbol_addresses: Vec<u64>,
}

impl Fixture {
    fn build() -> anyhow::Result<Self> {
        let tempdir = tempfile::tempdir()?;
        let source_path = tempdir.path().join("library_fixture.c");
        let binary_path = tempdir.path().join("library_fixture");
        fs::write(
            &source_path,
            r#"
int library_target_a(int x) { return x + 1; }
int library_target_b(int x) { return library_target_a(x) * 2; }
int library_target_c(int x) { return library_target_b(x) - 3; }

int main(void) {
    return library_target_c(1);
}
"#,
        )?;

        // Compile and link separately: the object file must outlive the link
        // for dsymutil to find its DWARF on macOS.
        let object_file = tempdir.path().join("library_fixture.o");
        let compiled = Command::new("cc")
            .args([
                "-g",
                "-O0",
                "-c",
                source_path.to_str().unwrap(),
                "-o",
                object_file.to_str().unwrap(),
            ])
            .status()?;
        anyhow::ensure!(compiled.success(), "failed to compile test fixture");
        let status = Command::new("cc")
            .args([
                "-g",
                object_file.to_str().unwrap(),
                "-o",
                binary_path.to_str().unwrap(),
            ])
            .status()?;
        anyhow::ensure!(status.success(), "failed to build test fixture");

        let (load_address, symbol_addresses) = inspect(&binary_path)?;

        // On macOS the DWARF stays in the object files unless it is linked into
        // a dSYM; symbolize against that so the DWARF path is exercised.
        let dsym_path = tempdir.path().join("library_fixture.dSYM");
        let object_path = if cfg!(target_os = "macos")
            && Command::new("dsymutil")
                .args([
                    binary_path.to_str().unwrap(),
                    "-o",
                    dsym_path.to_str().unwrap(),
                ])
                .status()
                .map(|status| status.success())
                .unwrap_or(false)
        {
            dsym_path
        } else {
            binary_path
        };

        Ok(Self {
            _tempdir: tempdir,
            binary_path: object_path,
            load_address,
            symbol_addresses,
        })
    }

    fn options(&self) -> SymbolizeOptions {
        SymbolizeOptions {
            object_path: self.binary_path.clone(),
            ..Default::default()
        }
    }

    fn addresses(&self) -> Vec<u64> {
        self.symbol_addresses.clone()
    }
}

fn inspect(binary_path: &Path) -> anyhow::Result<(u64, Vec<u64>)> {
    let bytes = fs::read(binary_path)?;
    let object = object::File::parse(bytes.as_slice())?;

    let load_address = object
        .segments()
        .find(|segment| matches!(segment.name(), Ok(Some("__TEXT"))))
        .map(|segment| segment.address())
        .or_else(|| {
            object
                .sections()
                .find(|section| matches!(section.name(), Ok(".text")))
                .map(|section| section.address())
        })
        .unwrap_or(0);

    let mut addresses = ["library_target_a", "library_target_b", "library_target_c"]
        .iter()
        .map(|target| {
            object
                .symbols()
                .find(|symbol| {
                    symbol
                        .name()
                        .map(|name| name.contains(target))
                        .unwrap_or(false)
                })
                .map(|symbol| symbol.address())
                .ok_or_else(|| anyhow::anyhow!("symbol not found: {target}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    addresses.sort_unstable();
    Ok((load_address, addresses))
}
