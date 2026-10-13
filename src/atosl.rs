use crate::demangle;
use anyhow::{anyhow, Context as _, Result};
use gimli::{EndianSlice, RunTimeEndian};
use object::macho;
use object::read::macho::{FatArch, FatHeader};
use object::{Object, ObjectSection, ObjectSegment, SymbolMap, SymbolMapName};
use serde::Serialize;
use std::borrow;
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

type DwarfContext<'data> = addr2line::Context<EndianSlice<'data, RunTimeEndian>>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    JsonPretty,
    /// One JSON object per address, one per line (ndjson); streams in input mode.
    JsonLines,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverKind {
    Dwarf,
    SymbolTable,
}

#[derive(Clone, Debug, Default)]
pub struct SymbolizeOptions {
    pub object_path: PathBuf,
    pub load_address: u64,
    pub addresses: Vec<u64>,
    pub verbose: bool,
    pub file_offsets: bool,
    /// Expand inlined functions into the full call stack in text output (like
    /// `atos -i`). When false, only the outermost frame is printed. JSON output
    /// always carries the full inline chain under `inlined_by` regardless.
    pub inline_frames: bool,
    pub arch: Option<String>,
    pub uuid: Option<String>,
    pub format: OutputFormat,
    /// When no addresses are passed positionally, read them from this file, or
    /// from stdin when `None`.
    pub input: Option<PathBuf>,
    /// Extra roots to search for separate ELF debug files (`.gnu_debuglink` and
    /// `.build-id` layouts).
    pub debug_dirs: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SelectedSlice {
    pub arch: String,
    pub uuid: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InlineFrame {
    pub symbol: String,
    pub location: Option<SourceLocation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SymbolizedFrame {
    pub requested_address: u64,
    pub lookup_address: u64,
    pub symbol: String,
    pub object_name: String,
    pub offset: u64,
    pub resolver: ResolverKind,
    pub location: Option<SourceLocation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub inlined_by: Vec<InlineFrame>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SymbolizeOutcome {
    Resolved(SymbolizedFrame),
    Unresolved {
        requested_address: u64,
        error: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SymbolizeReport {
    pub object_path: String,
    pub object_name: String,
    pub selected_slice: Option<SelectedSlice>,
    pub frames: Vec<SymbolizeOutcome>,
}

struct FatSlice<'data> {
    object: object::File<'data, &'data [u8]>,
    selected_slice: SelectedSlice,
}

struct ResolvedObject<'data> {
    object: object::File<'data, &'data [u8]>,
    object_name: String,
    selected_slice: Option<SelectedSlice>,
}

pub fn run(options: SymbolizeOptions) -> Result<i32> {
    // Addresses given on the command line use the batch path.
    if !options.addresses.is_empty() {
        let report = symbolize_path(&options)?;
        emit_report(
            &report,
            options.format,
            options.verbose,
            options.inline_frames,
        );
        return Ok(0);
    }

    // Otherwise read addresses from a file or stdin. Text and json-lines stream
    // a result per address; the single-document JSON formats collect.
    match options.format {
        OutputFormat::Text | OutputFormat::JsonLines => run_streaming(&options),
        OutputFormat::Json | OutputFormat::JsonPretty => run_collected_input(&options),
    }
}

pub fn symbolize_path(options: &SymbolizeOptions) -> Result<SymbolizeReport> {
    let symbolizer = ObjectSymbolizer::open(options)?;
    let frames = options
        .addresses
        .iter()
        .copied()
        .map(|requested_address| {
            symbolizer.symbolize(
                options.load_address,
                requested_address,
                options.file_offsets,
            )
        })
        .collect();

    Ok(symbolizer.report(frames))
}

fn run_streaming(options: &SymbolizeOptions) -> Result<i32> {
    let symbolizer = ObjectSymbolizer::open(options)?;
    if options.format == OutputFormat::Text && options.verbose {
        emit_text_header(symbolizer.object_path(), symbolizer.selected_slice());
    }
    for_each_input_address(options.input.as_deref(), |parsed| {
        let outcome = symbolize_parsed(&symbolizer, options, parsed);
        emit_streaming_outcome(
            &outcome,
            options.format,
            options.verbose,
            options.inline_frames,
        );
    })?;
    Ok(0)
}

fn emit_streaming_outcome(
    outcome: &SymbolizeOutcome,
    format: OutputFormat,
    verbose: bool,
    inline_frames: bool,
) {
    match format {
        OutputFormat::JsonLines => println!("{}", serde_json::to_string(outcome).unwrap()),
        _ => emit_text_outcome(outcome, verbose, inline_frames),
    }
}

fn run_collected_input(options: &SymbolizeOptions) -> Result<i32> {
    let symbolizer = ObjectSymbolizer::open(options)?;
    let mut frames = Vec::new();
    for_each_input_address(options.input.as_deref(), |parsed| {
        frames.push(symbolize_parsed(&symbolizer, options, parsed));
    })?;
    emit_report(
        &symbolizer.report(frames),
        options.format,
        options.verbose,
        options.inline_frames,
    );
    Ok(0)
}

fn symbolize_parsed(
    symbolizer: &ObjectSymbolizer,
    options: &SymbolizeOptions,
    parsed: Result<u64, String>,
) -> SymbolizeOutcome {
    match parsed {
        Ok(address) => symbolizer.symbolize(options.load_address, address, options.file_offsets),
        Err(error) => SymbolizeOutcome::Unresolved {
            requested_address: 0,
            error,
        },
    }
}

/// An object file loaded once and kept ready for repeated lookups.
///
/// [`symbolize_path`] opens the object, builds its symbol map and DWARF
/// context, resolves the given addresses, and drops everything. When the same
/// object is symbolized repeatedly (a long-running service handling many
/// crash reports for one build, say), that setup dominates the cost of each
/// call. `ObjectSymbolizer` does the setup in [`open`](Self::open) and keeps
/// the result, so each [`symbolize`](Self::symbolize) call only pays for the
/// lookup.
///
/// The DWARF context parses compilation units lazily, so memory grows as more
/// of the object is looked up. Callers caching several symbolizers should bound
/// how many they keep.
///
/// `ObjectSymbolizer` is `Send` but not `Sync`: the DWARF context fills in its
/// per-unit caches through interior mutability. Share one across threads by
/// wrapping it in a `Mutex`.
///
/// ```no_run
/// use atosl::{ObjectSymbolizer, SymbolizeOptions};
///
/// let symbolizer = ObjectSymbolizer::open(&SymbolizeOptions {
///     object_path: "MyApp.app.dSYM/Contents/Resources/DWARF/MyApp".into(),
///     arch: Some("arm64".to_string()),
///     ..Default::default()
/// })?;
///
/// for address in [0x1000_1234, 0x1000_5678] {
///     println!("{:?}", symbolizer.symbolize(0x1000_0000, address, false));
/// }
/// # Ok::<(), anyhow::Error>(())
/// ```
pub struct ObjectSymbolizer {
    object_path: String,
    indexed: IndexedObject,
}

impl ObjectSymbolizer {
    /// Opens, parses, and indexes the object described by `options`.
    ///
    /// Uses `object_path`, `arch`, `uuid`, `debug_dirs`, and `verbose`. The
    /// per-lookup fields (`load_address`, `addresses`, `file_offsets`) and the
    /// output fields are ignored; pass the lookup values to
    /// [`symbolize`](Self::symbolize) instead.
    pub fn open(options: &SymbolizeOptions) -> Result<Self> {
        let object_path = resolve_object_path(
            &options.object_path,
            options.uuid.as_deref(),
            &options.debug_dirs,
        )?;
        if options.verbose && object_path != options.object_path {
            eprintln!("resolved_object: {}", object_path.display());
        }
        let file = fs::File::open(&object_path)
            .with_context(|| format!("failed to open object file: {}", object_path.display()))?;
        // SAFETY: the mapping is only read. As with any mmap, the file must not
        // be truncated or modified while the symbolizer is alive.
        let mmap = unsafe { memmap2::Mmap::map(&file) }
            .with_context(|| format!("failed to memory-map: {}", object_path.display()))?;

        let uuid_filter = match options.uuid.as_deref() {
            Some(value) => parse_uuid_filter(value)?,
            None => None,
        };
        let mapped = MappedObject::try_new(mmap, |mmap| {
            LoadedObject::load(
                mmap,
                &object_path,
                options.arch.as_deref(),
                uuid_filter,
                options.verbose,
            )
        })?;
        let indexed = IndexedObject::try_new(mapped, |mapped| mapped.borrow_dependent().index())?;

        Ok(Self {
            object_path: object_path.display().to_string(),
            indexed,
        })
    }

    /// Resolves one address. `load_address` and `file_offsets` have the same
    /// meaning as in [`SymbolizeOptions`].
    pub fn symbolize(
        &self,
        load_address: u64,
        requested_address: u64,
        file_offsets: bool,
    ) -> SymbolizeOutcome {
        self.indexed.with_dependent(|mapped, context| {
            let loaded = mapped.borrow_dependent();
            symbolize_address(
                &loaded.object_name,
                context.as_ref(),
                &loaded.symbol_map,
                load_address,
                requested_address,
                loaded.text_vmaddr,
                file_offsets,
            )
        })
    }

    /// The path that was opened, after resolving dSYM bundles and separate
    /// debug files.
    pub fn object_path(&self) -> &str {
        &self.object_path
    }

    /// The object's file name, as reported in each frame.
    pub fn object_name(&self) -> &str {
        &self.indexed.borrow_owner().borrow_dependent().object_name
    }

    /// The Mach-O slice that was selected, if the object is Mach-O.
    pub fn selected_slice(&self) -> Option<&SelectedSlice> {
        self.indexed
            .borrow_owner()
            .borrow_dependent()
            .selected_slice
            .as_ref()
    }

    fn report(&self, frames: Vec<SymbolizeOutcome>) -> SymbolizeReport {
        SymbolizeReport {
            object_path: self.object_path().to_string(),
            object_name: self.object_name().to_string(),
            selected_slice: self.selected_slice().cloned(),
            frames,
        }
    }
}

impl std::fmt::Debug for ObjectSymbolizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectSymbolizer")
            .field("object_path", &self.object_path)
            .field("object_name", &self.object_name())
            .field("selected_slice", &self.selected_slice())
            .finish_non_exhaustive()
    }
}

// The DWARF context borrows the sections, which borrow the mapped file, so an
// owned symbolizer needs two self-referential layers. `MappedObject` owns the
// mapping and the data parsed from it; `IndexedObject` owns that and the DWARF
// context built over its sections.
struct LoadedObject<'data> {
    object_name: String,
    selected_slice: Option<SelectedSlice>,
    endian: RunTimeEndian,
    text_vmaddr: u64,
    symbol_map: SymbolMap<SymbolMapName<'data>>,
    dwarf_sections: Option<gimli::DwarfSections<borrow::Cow<'data, [u8]>>>,
}

impl<'data> LoadedObject<'data> {
    fn load(
        data: &'data [u8],
        object_path: &Path,
        arch_filter: Option<&str>,
        uuid_filter: Option<[u8; 16]>,
        verbose: bool,
    ) -> Result<Self> {
        let resolved =
            resolve_object_from_data(data, object_path, arch_filter, uuid_filter, verbose)?;
        let endian = if resolved.object.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let dwarf_sections = if is_object_dwarf(&resolved.object) {
            Some(load_dwarf_sections(&resolved.object)?)
        } else {
            None
        };

        Ok(Self {
            text_vmaddr: find_text_vmaddr(&resolved.object)?,
            symbol_map: resolved.object.symbol_map(),
            object_name: resolved.object_name,
            selected_slice: resolved.selected_slice,
            endian,
            dwarf_sections,
        })
    }

    fn index(&self) -> Result<Option<DwarfContext<'_>>> {
        let Some(sections) = &self.dwarf_sections else {
            return Ok(None);
        };
        let mut dwarf = sections.borrow(|section| EndianSlice::new(section.as_ref(), self.endian));
        // dsymutil emits a single abbreviation table shared by every unit.
        // Without the cache, gimli re-parses and keeps a separate copy of it
        // per unit, which dominates context construction on large dSYMs.
        dwarf.populate_abbreviations_cache(gimli::AbbreviationsCacheStrategy::Duplicates);
        Ok(Some(
            DwarfContext::from_dwarf(dwarf).context("failed to build DWARF context")?,
        ))
    }
}

type OptionalDwarfContext<'a> = Option<DwarfContext<'a>>;

self_cell::self_cell!(
    struct MappedObject {
        owner: memmap2::Mmap,

        #[covariant]
        dependent: LoadedObject,
    }
);

self_cell::self_cell!(
    struct IndexedObject {
        owner: MappedObject,

        #[not_covariant]
        dependent: OptionalDwarfContext,
    }
);

fn for_each_input_address(
    input: Option<&Path>,
    mut handle: impl FnMut(Result<u64, String>),
) -> Result<()> {
    match input {
        Some(path) => {
            let file = fs::File::open(path)
                .with_context(|| format!("failed to open address input: {}", path.display()))?;
            read_addresses(BufReader::new(file), &mut handle)
        }
        None => {
            let stdin = io::stdin();
            read_addresses(stdin.lock(), &mut handle)
        }
    }
}

fn read_addresses(
    reader: impl BufRead,
    handle: &mut impl FnMut(Result<u64, String>),
) -> Result<()> {
    for line in reader.lines() {
        let line = line.context("failed to read address input")?;
        for token in line.split_whitespace() {
            handle(parse_address_token(token));
        }
    }
    Ok(())
}

fn parse_address_token(token: &str) -> Result<u64, String> {
    let parsed = match token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => token.parse::<u64>(),
    };
    parsed.map_err(|err| format!("invalid address '{token}': {err}"))
}

// Accepts a Mach-O/ELF file, a `.dSYM` bundle directory, or (with `uuid`) a
// directory of binaries/dSYMs to search, and returns the path to the binary
// that actually carries the symbols.
fn resolve_object_path(path: &Path, uuid: Option<&str>, debug_dirs: &[PathBuf]) -> Result<PathBuf> {
    if path.is_file() {
        return Ok(resolve_debug_companion(path, debug_dirs));
    }

    if path.is_dir() {
        let dwarf_dir = path.join("Contents/Resources/DWARF");
        if dwarf_dir.is_dir() {
            return select_dwarf_payload(&dwarf_dir, path);
        }
        if let Some(uuid) = uuid {
            return find_object_by_id(path, uuid);
        }
        return Err(anyhow!(
            "{} is a directory; pass --uuid to select a matching binary/dSYM, or point at a file",
            path.display()
        ));
    }

    Err(anyhow!("object path does not exist: {}", path.display()))
}

// Walks `dir` for a binary or dSYM payload whose Mach-O UUID or ELF build-id
// matches `uuid` (compared as hex, ignoring case and separators).
fn find_object_by_id(dir: &Path, uuid: &str) -> Result<PathBuf> {
    let wanted = normalize_hex_id(uuid);
    if wanted.is_empty() {
        return Err(anyhow!("invalid --uuid value: '{uuid}'"));
    }

    let mut candidates = Vec::new();
    collect_candidate_files(dir, &mut candidates)?;
    candidates.sort();

    for candidate in &candidates {
        if let Ok(data) = fs::read(candidate) {
            if collect_module_ids(&data).contains(&wanted) {
                return Ok(candidate.clone());
            }
        }
    }

    Err(anyhow!(
        "no binary or dSYM under {} matched uuid {}",
        dir.display(),
        uuid
    ))
}

// A stripped ELF can point at its DWARF in a separate file via `.gnu_debuglink`
// or its build-id. When the given file carries no DWARF, follow those hints to a
// companion debug file that exists; otherwise keep the original path.
fn resolve_debug_companion(path: &Path, debug_dirs: &[PathBuf]) -> PathBuf {
    let keep = || path.to_path_buf();

    let Ok(handle) = fs::File::open(path) else {
        return keep();
    };
    // mmap so checking large binaries only touches headers, not the whole file.
    let Ok(mmap) = (unsafe { memmap2::Mmap::map(&handle) }) else {
        return keep();
    };
    let Ok(file) = object::File::parse(&*mmap) else {
        return keep();
    };
    if is_object_dwarf(&file) {
        return keep();
    }

    if let Some((name, crc)) = read_debuglink(&file) {
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        for candidate in debuglink_candidates(dir, &name, debug_dirs) {
            // The CRC guards against using a debug file that no longer matches
            // the binary, matching gdb's behavior.
            if candidate.is_file() && file_crc32(&candidate) == Some(crc) {
                return candidate;
            }
        }
    }

    if let Ok(Some(build_id)) = file.build_id() {
        // The build-id path itself identifies the matching debug file.
        for candidate in build_id_candidates(build_id, debug_dirs) {
            if candidate.is_file() {
                return candidate;
            }
        }
    }

    keep()
}

fn read_debuglink<'data>(file: &object::File<'data, &'data [u8]>) -> Option<(String, u32)> {
    let section = file.section_by_name(".gnu_debuglink")?;
    let data = section.data().ok()?;
    if data.len() < 4 {
        return None;
    }
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(data.len());
    let name = std::str::from_utf8(&data[..end]).ok()?;
    if name.is_empty() {
        return None;
    }
    // The 4-byte CRC trails the NUL-padded name, in the file's byte order.
    let crc_bytes: [u8; 4] = data[data.len() - 4..].try_into().ok()?;
    let crc = if file.is_little_endian() {
        u32::from_le_bytes(crc_bytes)
    } else {
        u32::from_be_bytes(crc_bytes)
    };
    Some((name.to_string(), crc))
}

fn debuglink_candidates(binary_dir: &Path, name: &str, debug_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut candidates = vec![binary_dir.join(name), binary_dir.join(".debug").join(name)];

    let mirrored = binary_dir
        .canonicalize()
        .ok()
        .map(|abs| abs.strip_prefix("/").unwrap_or(&abs).to_path_buf());

    let roots = std::iter::once(PathBuf::from("/usr/lib/debug")).chain(debug_dirs.iter().cloned());
    for root in roots {
        candidates.push(root.join(name));
        if let Some(mirror) = &mirrored {
            candidates.push(root.join(mirror).join(name));
        }
    }

    candidates
}

fn build_id_candidates(build_id: &[u8], debug_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let subpath = build_id_debug_subpath(build_id);
    let mut candidates = vec![PathBuf::from("/usr/lib/debug/.build-id").join(&subpath)];

    for dir in debug_dirs {
        candidates.push(dir.join(".build-id").join(&subpath));
    }

    // debuginfod stores fetched debug files at <cache>/<build-id hex>/debuginfo.
    let hex = format_hex(build_id);
    for cache in debuginfod_cache_dirs() {
        candidates.push(cache.join(&hex).join("debuginfo"));
    }

    candidates
}

fn debuginfod_cache_dirs() -> Vec<PathBuf> {
    if let Ok(path) = env::var("DEBUGINFOD_CACHE_PATH") {
        return vec![PathBuf::from(path)];
    }
    if let Ok(xdg) = env::var("XDG_CACHE_HOME") {
        return vec![PathBuf::from(xdg).join("debuginfod_client")];
    }
    if let Ok(home) = env::var("HOME") {
        return vec![PathBuf::from(home).join(".cache").join("debuginfod_client")];
    }
    Vec::new()
}

fn build_id_debug_subpath(build_id: &[u8]) -> PathBuf {
    let hex = format_hex(build_id);
    match hex.split_at_checked(2) {
        Some((prefix, rest)) => PathBuf::from(prefix).join(format!("{rest}.debug")),
        None => PathBuf::from(format!("{hex}.debug")),
    }
}

fn file_crc32(path: &Path) -> Option<u32> {
    let handle = fs::File::open(path).ok()?;
    let mmap = unsafe { memmap2::Mmap::map(&handle) }.ok()?;
    Some(crc32(&mmap))
}

// Standard CRC-32 (reflected, polynomial 0xedb88320), as used by gnu_debuglink.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn collect_candidate_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(dir)
        .with_context(|| format!("failed to read directory: {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            collect_candidate_files(&path, out)?;
        } else if file_type.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn collect_module_ids(data: &[u8]) -> Vec<String> {
    match object::FileKind::parse(data) {
        Ok(object::FileKind::MachOFat32) => FatHeader::parse_arch32(data)
            .map(|arches| fat_slice_ids(arches, data))
            .unwrap_or_default(),
        Ok(object::FileKind::MachOFat64) => FatHeader::parse_arch64(data)
            .map(|arches| fat_slice_ids(arches, data))
            .unwrap_or_default(),
        Ok(_) => slice_ids(data),
        Err(_) => Vec::new(),
    }
}

fn fat_slice_ids<A: FatArch>(arches: &[A], data: &[u8]) -> Vec<String> {
    arches
        .iter()
        .filter_map(|arch| arch.data(data).ok())
        .flat_map(slice_ids)
        .collect()
}

fn slice_ids(data: &[u8]) -> Vec<String> {
    let Ok(file) = object::File::parse(data) else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    if let Ok(Some(uuid)) = file.mach_uuid() {
        ids.push(format_hex(&uuid));
    }
    if let Ok(Some(build_id)) = file.build_id() {
        ids.push(format_hex(build_id));
    }
    ids
}

fn format_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn normalize_hex_id(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

// A 16-byte value is a Mach-O slice UUID and is used to pick a fat slice and to
// validate non-fat files. Other hex lengths are build-ids used only to select a
// file from a directory, so they impose no slice filter here.
fn parse_uuid_filter(value: &str) -> Result<Option<[u8; 16]>> {
    let hex = normalize_hex_id(value);
    if hex.is_empty() || value.chars().any(|c| c != '-' && !c.is_ascii_hexdigit()) {
        return Err(anyhow!("invalid uuid format: '{value}'"));
    }
    if hex.len() == 32 {
        Ok(Some(parse_uuid_string(value)?))
    } else {
        Ok(None)
    }
}

fn select_dwarf_payload(dwarf_dir: &Path, bundle: &Path) -> Result<PathBuf> {
    let mut payloads = fs::read_dir(dwarf_dir)
        .with_context(|| format!("failed to read dSYM payload dir: {}", dwarf_dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    payloads.sort();

    match payloads.len() {
        0 => Err(anyhow!("no DWARF payload found in {}", dwarf_dir.display())),
        1 => Ok(payloads.remove(0)),
        _ => {
            // A fat dSYM ships one payload named after the bundle (Foo.dSYM -> Foo).
            let base = bundle
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.trim_end_matches(".dSYM"));
            if let Some(base) = base {
                if let Some(found) = payloads
                    .iter()
                    .find(|path| path.file_name().and_then(|name| name.to_str()) == Some(base))
                {
                    return Ok(found.clone());
                }
            }
            Err(anyhow!(
                "multiple DWARF payloads in {}; pass the file directly:\n{}",
                dwarf_dir.display(),
                payloads
                    .iter()
                    .map(|path| format!("- {}", path.display()))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
        }
    }
}

fn emit_report(report: &SymbolizeReport, format: OutputFormat, verbose: bool, inline_frames: bool) {
    match format {
        OutputFormat::Text => emit_text_report(report, verbose, inline_frames),
        OutputFormat::Json => println!("{}", serde_json::to_string(report).unwrap()),
        OutputFormat::JsonPretty => println!("{}", serde_json::to_string_pretty(report).unwrap()),
        OutputFormat::JsonLines => {
            for frame in &report.frames {
                println!("{}", serde_json::to_string(frame).unwrap());
            }
        }
    }
}

fn emit_text_report(report: &SymbolizeReport, verbose: bool, inline_frames: bool) {
    if verbose {
        emit_text_header(&report.object_path, report.selected_slice.as_ref());
    }
    for frame in &report.frames {
        emit_text_outcome(frame, verbose, inline_frames);
    }
}

fn emit_text_header(object_path: &str, selected_slice: Option<&SelectedSlice>) {
    eprintln!("object: {object_path}");
    if let Some(selected_slice) = selected_slice {
        eprintln!(
            "selected_slice: arch={} uuid={}",
            selected_slice.arch,
            selected_slice.uuid.as_deref().unwrap_or("-")
        );
    }
}

fn emit_text_outcome(outcome: &SymbolizeOutcome, verbose: bool, inline_frames: bool) {
    match outcome {
        SymbolizeOutcome::Resolved(frame) => {
            if verbose {
                eprintln!(
                    "frame: requested=0x{requested:016x} lookup=0x{lookup:016x} resolver={resolver:?} status=resolved",
                    requested = frame.requested_address,
                    lookup = frame.lookup_address,
                    resolver = frame.resolver,
                );
            }
            if inline_frames {
                // Full inline call stack, innermost first (like `atos -i`).
                println!("{}", format_text_frame(frame));
                for inline in &frame.inlined_by {
                    println!("{}", format_inline_frame(inline, &frame.object_name));
                }
            } else {
                // Only the outermost frame: the real (non-inlined) function that
                // physically contains the address. It is the last entry in the
                // inline chain, or the primary frame when nothing was inlined.
                match frame.inlined_by.last() {
                    Some(outermost) => {
                        println!("{}", format_inline_frame(outermost, &frame.object_name))
                    }
                    None => println!("{}", format_text_frame(frame)),
                }
            }
        }
        SymbolizeOutcome::Unresolved {
            requested_address,
            error,
        } => {
            if verbose {
                eprintln!(
                    "frame: requested=0x{requested_address:016x} status=unresolved error={error}"
                );
            }
            println!("N/A - {error}");
        }
    }
}

fn format_text_frame(frame: &SymbolizedFrame) -> String {
    match &frame.location {
        Some(location) => format!(
            "{} (in {}) ({}:{})",
            frame.symbol, frame.object_name, location.file, location.line
        ),
        None => format!(
            "{} (in {}) + {}",
            frame.symbol, frame.object_name, frame.offset
        ),
    }
}

fn format_inline_frame(frame: &InlineFrame, object_name: &str) -> String {
    match &frame.location {
        Some(location) => format!(
            "{} (in {}) ({}:{})",
            frame.symbol, object_name, location.file, location.line
        ),
        None => format!("{} (in {})", frame.symbol, object_name),
    }
}

#[allow(clippy::too_many_arguments)]
fn symbolize_address<'data>(
    object_name: &str,
    context: Option<&DwarfContext<'data>>,
    symbol_map: &SymbolMap<SymbolMapName<'data>>,
    load_address: u64,
    requested_address: u64,
    text_vmaddr: u64,
    file_offsets: bool,
) -> SymbolizeOutcome {
    let search_address = match calculate_search_address(
        load_address,
        requested_address,
        text_vmaddr,
        file_offsets,
    ) {
        Ok(search_address) => search_address,
        Err(err) => {
            return SymbolizeOutcome::Unresolved {
                requested_address,
                error: err.to_string(),
            };
        }
    };

    if let Some(context) = context {
        if let Ok(Some(frame)) = dwarf_symbolize_address(
            context,
            symbol_map,
            object_name,
            requested_address,
            search_address,
        ) {
            return SymbolizeOutcome::Resolved(frame);
        }
    }

    match symbol_symbolize_address(symbol_map, object_name, requested_address, search_address) {
        Ok(frame) => SymbolizeOutcome::Resolved(frame),
        Err(err) => SymbolizeOutcome::Unresolved {
            requested_address,
            error: err.to_string(),
        },
    }
}

fn resolve_object_from_data<'data>(
    data: &'data [u8],
    object_path: &Path,
    arch_filter: Option<&str>,
    uuid_filter: Option<[u8; 16]>,
    verbose: bool,
) -> Result<ResolvedObject<'data>> {
    let kind = object::FileKind::parse(data)?;
    let object_name = object_path
        .file_name()
        .ok_or_else(|| {
            anyhow!(
                "failed to derive object filename from {}",
                object_path.display()
            )
        })?
        .to_string_lossy()
        .to_string();

    match kind {
        object::FileKind::MachOFat32 => {
            let arches = FatHeader::parse_arch32(data)?;
            let selected = select_fat_slice(arches, data, arch_filter, uuid_filter, verbose)?;
            Ok(ResolvedObject {
                object: selected.object,
                object_name,
                selected_slice: Some(selected.selected_slice),
            })
        }
        object::FileKind::MachOFat64 => {
            let arches = FatHeader::parse_arch64(data)?;
            let selected = select_fat_slice(arches, data, arch_filter, uuid_filter, verbose)?;
            Ok(ResolvedObject {
                object: selected.object,
                object_name,
                selected_slice: Some(selected.selected_slice),
            })
        }
        _ => {
            let file = object::File::parse(data)?;
            validate_non_fat_filters(&file, arch_filter, uuid_filter)?;
            let selected_slice = file.mach_uuid()?.map(|uuid| SelectedSlice {
                arch: format!("{:?}", file.architecture()).to_lowercase(),
                uuid: Some(format_uuid(uuid)),
            });
            Ok(ResolvedObject {
                object: file,
                object_name,
                selected_slice,
            })
        }
    }
}

fn validate_non_fat_filters<'data>(
    file: &object::File<'data, &'data [u8]>,
    arch_filter: Option<&str>,
    uuid_filter: Option<[u8; 16]>,
) -> Result<()> {
    if let Some(uuid_filter) = uuid_filter {
        let actual_uuid = file
            .mach_uuid()?
            .ok_or_else(|| anyhow!("--uuid was provided, but this file has no Mach-O UUID"))?;
        if actual_uuid != uuid_filter {
            return Err(anyhow!(
                "uuid mismatch: requested {}, actual {}",
                format_uuid(uuid_filter),
                format_uuid(actual_uuid)
            ));
        }
    }

    if let Some(arch_filter) = arch_filter {
        let architecture = file.architecture();
        if !architecture_matches_filter(architecture, arch_filter) {
            return Err(anyhow!(
                "architecture mismatch: requested '{}', actual '{:?}'",
                arch_filter,
                architecture
            ));
        }
    }

    Ok(())
}

fn select_fat_slice<'data, A: FatArch>(
    arches: &'data [A],
    data: &'data [u8],
    arch_filter: Option<&str>,
    uuid_filter: Option<[u8; 16]>,
    verbose: bool,
) -> Result<FatSlice<'data>> {
    let mut slices = Vec::with_capacity(arches.len());
    for arch in arches {
        let arch_name = format_macho_arch_name(arch.cputype(), arch.cpusubtype());
        let object = object::File::parse(arch.data(data)?)?;
        let uuid = object.mach_uuid()?.map(format_uuid);
        slices.push(FatSlice {
            object,
            selected_slice: SelectedSlice {
                arch: arch_name,
                uuid,
            },
        });
    }

    if verbose {
        for slice in &slices {
            eprintln!(
                "fat_slice: arch={} uuid={}",
                slice.selected_slice.arch,
                slice.selected_slice.uuid.as_deref().unwrap_or("-")
            );
        }
    }

    if slices.is_empty() {
        return Err(anyhow!("fat Mach-O has no slices"));
    }

    if arch_filter.is_none() && uuid_filter.is_none() {
        return match slices.len() {
            1 => Ok(slices.remove(0)),
            _ => Err(anyhow!(
                "fat Mach-O contains multiple slices.\nUse -a/--arch or --uuid to select one.\nAvailable slices:\n{}",
                format_available_slices(&slices)
            )),
        };
    }

    let available_slices = format_available_slices(&slices);
    let mut matches = slices
        .into_iter()
        .filter(|slice| {
            let arch_ok = arch_filter
                .map(|filter| macho_arch_matches_filter(&slice.selected_slice.arch, filter))
                .unwrap_or(true);
            let uuid_ok = uuid_filter
                .map(|uuid| {
                    slice.selected_slice.uuid.as_deref() == Some(format_uuid(uuid).as_str())
                })
                .unwrap_or(true);
            arch_ok && uuid_ok
        })
        .collect::<Vec<_>>();

    match matches.len() {
        0 => Err(anyhow!(
            "no fat Mach-O slice matched arch={:?} uuid={:?}.\nAvailable slices:\n{}",
            arch_filter,
            uuid_filter.map(format_uuid),
            available_slices
        )),
        1 => Ok(matches.pop().expect("match length checked")),
        _ => Err(anyhow!(
            "filters are ambiguous and matched multiple slices:\n{}",
            format_available_slices(&matches)
        )),
    }
}

fn format_available_slices(slices: &[FatSlice<'_>]) -> String {
    slices
        .iter()
        .map(|slice| {
            format!(
                "- arch={} uuid={}",
                slice.selected_slice.arch,
                slice.selected_slice.uuid.as_deref().unwrap_or("-")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_uuid_string(value: &str) -> Result<[u8; 16]> {
    let hex = value
        .chars()
        .filter(|c| *c != '-')
        .collect::<String>()
        .to_ascii_lowercase();

    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "invalid uuid format: '{value}', expected 32 hex chars (with or without '-')"
        ));
    }

    let mut out = [0u8; 16];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk)?;
        out[index] = u8::from_str_radix(byte_str, 16)?;
    }
    Ok(out)
}

fn format_uuid(uuid: [u8; 16]) -> String {
    let hex = uuid
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn normalize_arch(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>()
}

fn architecture_matches_filter(architecture: object::Architecture, arch_filter: &str) -> bool {
    let filter = normalize_arch(arch_filter);
    match filter.as_str() {
        "arm" | "armv7" | "armv7s" | "armv7k" => architecture == object::Architecture::Arm,
        "arm64" | "arm64e" | "aarch64" => architecture == object::Architecture::Aarch64,
        "x8664" | "x64" | "amd64" | "x8664h" => architecture == object::Architecture::X86_64,
        "x86" | "i386" => architecture == object::Architecture::I386,
        _ => false,
    }
}

fn macho_arch_matches_filter(arch_name: &str, arch_filter: &str) -> bool {
    let actual = normalize_arch(arch_name);
    let filter = normalize_arch(arch_filter);

    if actual == filter {
        return true;
    }

    matches!(
        (actual.as_str(), filter.as_str()),
        ("arm64", "aarch64")
            | ("aarch64", "arm64")
            | ("x8664", "amd64")
            | ("x8664", "x64")
            | ("i386", "x86")
    )
}

fn format_macho_arch_name(cputype: u32, cpusubtype: u32) -> String {
    let cpusubtype = cpusubtype & !macho::CPU_SUBTYPE_MASK;
    match cputype {
        macho::CPU_TYPE_ARM64 => match cpusubtype {
            macho::CPU_SUBTYPE_ARM64E => "arm64e".to_string(),
            _ => "arm64".to_string(),
        },
        macho::CPU_TYPE_ARM => match cpusubtype {
            macho::CPU_SUBTYPE_ARM_V7 => "armv7".to_string(),
            macho::CPU_SUBTYPE_ARM_V7F => "armv7f".to_string(),
            macho::CPU_SUBTYPE_ARM_V7S => "armv7s".to_string(),
            macho::CPU_SUBTYPE_ARM_V7K => "armv7k".to_string(),
            macho::CPU_SUBTYPE_ARM_V8 => "armv8".to_string(),
            _ => "arm".to_string(),
        },
        macho::CPU_TYPE_X86_64 => match cpusubtype {
            macho::CPU_SUBTYPE_X86_64_H => "x86_64h".to_string(),
            _ => "x86_64".to_string(),
        },
        macho::CPU_TYPE_X86 => "i386".to_string(),
        _ => format!("cputype{cputype}_subtype{cpusubtype}"),
    }
}

fn is_object_dwarf<'data>(object: &object::File<'data, &'data [u8]>) -> bool {
    object.section_by_name("__debug_line").is_some()
        || object.section_by_name(".debug_line").is_some()
}

fn find_text_vmaddr<'data>(object: &object::File<'data, &'data [u8]>) -> Result<u64> {
    for segment in object.segments() {
        if let Some(name) = segment.name()? {
            if name == "__TEXT" {
                return Ok(segment.address());
            }
        }
    }

    if let Some(section) = object
        .section_by_name(".text")
        .or_else(|| object.section_by_name("__text"))
    {
        return Ok(section.address());
    }

    Ok(0)
}

fn calculate_search_address(
    load_address: u64,
    address: u64,
    text_vmaddr: u64,
    file_offset_type: bool,
) -> Result<u64> {
    let base = address.checked_sub(load_address).ok_or_else(|| {
        anyhow!(
            "address {address:#x} is smaller than load address {load_address:#x}; \
pass the runtime address as reported in the crash report"
        )
    })?;

    if file_offset_type {
        // File-offset mode uses `address - load_address` directly as the lookup
        // key, without re-basing onto the __TEXT vmaddr. This is the historical
        // behavior and is kept stable so existing callers are unaffected.
        //
        // Note: this is *not* the same as Apple `atos -offset N`. To reproduce
        // `atos -offset N`, use the default mode with a zero load address:
        // `atosl -l 0 N` computes `N + __TEXT vmaddr`, exactly what `atos
        // -offset` does.
        Ok(base)
    } else {
        base.checked_add(text_vmaddr).ok_or_else(|| {
            anyhow!("address {address:#x} overflows when applying __TEXT vmaddr {text_vmaddr:#x}")
        })
    }
}

fn symbol_symbolize_address(
    symbol_map: &SymbolMap<SymbolMapName<'_>>,
    object_name: &str,
    requested_address: u64,
    search_address: u64,
) -> Result<SymbolizedFrame> {
    let found_symbol = symbol_map
        .get(search_address)
        .ok_or_else(|| anyhow!("failed to search symbol table"))?;
    let offset = search_address.saturating_sub(found_symbol.address());

    Ok(SymbolizedFrame {
        requested_address,
        lookup_address: search_address,
        symbol: demangle::demangle_symbol(found_symbol.name()),
        object_name: object_name.to_string(),
        offset,
        resolver: ResolverKind::SymbolTable,
        location: None,
        inlined_by: Vec::new(),
    })
}

fn load_dwarf_sections<'data>(
    object: &object::File<'data, &'data [u8]>,
) -> Result<gimli::DwarfSections<borrow::Cow<'data, [u8]>>> {
    let sections = gimli::DwarfSections::load(
        |section_id| -> Result<borrow::Cow<'data, [u8]>, gimli::Error> {
            let macho_name = section_id
                .name()
                .strip_prefix('.')
                .map(|name| format!("__{name}"));

            match object.section_by_name(section_id.name()).or_else(|| {
                macho_name
                    .as_deref()
                    .and_then(|name| object.section_by_name(name))
            }) {
                Some(section) => Ok(section
                    .uncompressed_data()
                    .unwrap_or(borrow::Cow::Borrowed(&[][..]))),
                None => Ok(borrow::Cow::Borrowed(&[][..])),
            }
        },
    )?;
    Ok(sections)
}

// `atos` reports inlined call sites as a stack, innermost first. addr2line
// yields frames in the same order, so the first frame becomes the primary
// result and the remaining ones are the callers that inlined it.
fn dwarf_symbolize_address<'data>(
    context: &DwarfContext<'data>,
    symbol_map: &SymbolMap<SymbolMapName<'data>>,
    object_name: &str,
    requested_address: u64,
    search_address: u64,
) -> Result<Option<SymbolizedFrame>> {
    let mut iter = context.find_frames(search_address).skip_all_loads()?;
    let mut frames: Vec<(String, Option<SourceLocation>)> = Vec::new();

    while let Some(frame) = iter.next()? {
        let Some(function) = frame.function.as_ref() else {
            continue;
        };
        let Ok(raw_name) = function.raw_name() else {
            continue;
        };
        let symbol = demangle::demangle_symbol(raw_name.as_ref());
        let location = frame.location.as_ref().and_then(location_from_addr2line);
        frames.push((symbol, location));
    }

    if frames.is_empty() {
        return Ok(None);
    }

    let offset = function_offset(symbol_map, search_address);
    let (symbol, location) = frames.remove(0);
    let inlined_by = frames
        .into_iter()
        .map(|(symbol, location)| InlineFrame { symbol, location })
        .collect();

    Ok(Some(SymbolizedFrame {
        requested_address,
        lookup_address: search_address,
        symbol,
        object_name: object_name.to_string(),
        offset,
        resolver: ResolverKind::Dwarf,
        location,
        inlined_by,
    }))
}

fn location_from_addr2line(location: &addr2line::Location<'_>) -> Option<SourceLocation> {
    let file = location.file?;
    let line = location.line.unwrap_or(0);
    if line == 0 {
        return None;
    }
    Some(SourceLocation {
        file: normalize_debug_path(file),
        line: u64::from(line),
    })
}

// addr2line joins the compilation directory with the file path, which on some
// toolchains (notably dsymutil output) yields redundant "." segments such as
// "././tests/foo.c". Collapse them while preserving a single leading "./".
fn normalize_debug_path(path: &str) -> String {
    let components = path
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect::<Vec<_>>()
        .join("/");

    if path.starts_with('/') {
        format!("/{components}")
    } else if path.starts_with("./") {
        format!("./{components}")
    } else {
        components
    }
}

fn function_offset(symbol_map: &SymbolMap<SymbolMapName<'_>>, search_address: u64) -> u64 {
    symbol_map
        .get(search_address)
        .map(|symbol| search_address.saturating_sub(symbol.address()))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_accepts_hyphenated_and_plain() {
        let a = parse_uuid_string("29118F18-9DFC-36A8-9028-A19B13996D5E").unwrap();
        let b = parse_uuid_string("29118f189dfc36a89028a19b13996d5e").unwrap();
        assert_eq!(a, b);
        assert_eq!(format_uuid(a), "29118F18-9DFC-36A8-9028-A19B13996D5E");
    }

    #[test]
    fn parse_uuid_rejects_invalid() {
        assert!(parse_uuid_string("not-a-uuid").is_err());
        assert!(parse_uuid_string("1234").is_err());
    }

    #[test]
    fn macho_arch_aliases_match() {
        assert!(macho_arch_matches_filter("arm64", "aarch64"));
        assert!(macho_arch_matches_filter("x86_64", "amd64"));
        assert!(macho_arch_matches_filter("i386", "x86"));
    }

    #[test]
    fn calculate_search_address_for_file_offsets() {
        // File-offset mode uses `address - load_address` directly, without
        // re-basing onto the __TEXT vmaddr. This is the historical behavior.
        assert_eq!(
            calculate_search_address(0x1000, 0x1030, 0x2000, true).unwrap(),
            0x30
        );
    }

    #[test]
    fn calculate_search_address_for_vmaddr_mode() {
        assert_eq!(
            calculate_search_address(0x1000, 0x1030, 0x2000, false).unwrap(),
            0x2030
        );
    }

    #[test]
    fn format_text_frame_with_location() {
        let frame = SymbolizedFrame {
            requested_address: 1,
            lookup_address: 1,
            symbol: "demo".to_string(),
            object_name: "fixture".to_string(),
            offset: 0,
            resolver: ResolverKind::Dwarf,
            location: Some(SourceLocation {
                file: "src/main.rs".to_string(),
                line: 7,
            }),
            inlined_by: Vec::new(),
        };

        assert_eq!(
            format_text_frame(&frame),
            "demo (in fixture) (src/main.rs:7)"
        );
    }

    #[test]
    fn normalize_debug_path_collapses_redundant_dots() {
        assert_eq!(
            normalize_debug_path("././tests/fixtures/apple/macho_golden.c"),
            "./tests/fixtures/apple/macho_golden.c"
        );
        assert_eq!(
            normalize_debug_path("./tests/fixtures/apple/macho_golden.c"),
            "./tests/fixtures/apple/macho_golden.c"
        );
        assert_eq!(
            normalize_debug_path("/abs/path/main.rs"),
            "/abs/path/main.rs"
        );
        assert_eq!(normalize_debug_path("src/lib.rs"), "src/lib.rs");
    }

    #[test]
    fn format_inline_frame_with_and_without_location() {
        let with_location = InlineFrame {
            symbol: "leaf".to_string(),
            location: Some(SourceLocation {
                file: "src/lib.rs".to_string(),
                line: 3,
            }),
        };
        assert_eq!(
            format_inline_frame(&with_location, "fixture"),
            "leaf (in fixture) (src/lib.rs:3)"
        );

        let without_location = InlineFrame {
            symbol: "leaf".to_string(),
            location: None,
        };
        assert_eq!(
            format_inline_frame(&without_location, "fixture"),
            "leaf (in fixture)"
        );
    }
}
