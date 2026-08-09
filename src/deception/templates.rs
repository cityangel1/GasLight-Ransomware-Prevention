// Template generator.
//
// SCOPE NOTE on file formats: ransomware walks the filesystem matching
// extensions — it never validates that a .xlsx is byte-valid OOXML before
// encrypting it, so a decoy only needs to *be* a file with the right
// extension and plausible size to serve as bait. Given that, and given
// this code can't be compile-tested in the sandbox that wrote it, the
// content below is realistic plain-text/CSV for every "office" format
// (.xlsx, .docx, .csv, .txt) rather than attempting byte-valid OOXML —
// hand-rolling a ZIP+XML container from memory with no compiler to catch
// mistakes is a lot of risk for something ransomware doesn't check
// anyway. The one exception is .pdf: the PDF format is simple enough to
// generate a genuinely valid minimal file directly (see
// `render_minimal_pdf` below), so backup-manifest decoys are real,
// openable PDFs — a nice bit of extra realism at low risk.
//
// If byte-valid OOXML ever matters (e.g. for a live demo where a viewer
// double-clicks a decoy in front of you), swapping in the `zip` crate to
// build a minimal Content_Types.xml + document.xml package is a contained
// follow-up localized entirely to this file.

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateKind {
    PayrollSpreadsheet,
    FinancialForecast,
    Credentials,
    ContractDocument,
    BackupManifest,
    MeetingNotes,
    InvoiceSheet,
}

impl TemplateKind {
    pub const ALL: &'static [TemplateKind] = &[
        TemplateKind::PayrollSpreadsheet,
        TemplateKind::FinancialForecast,
        TemplateKind::Credentials,
        TemplateKind::ContractDocument,
        TemplateKind::BackupManifest,
        TemplateKind::MeetingNotes,
        TemplateKind::InvoiceSheet,
    ];

    pub fn tag(&self) -> &'static str {
        match self {
            TemplateKind::PayrollSpreadsheet => "payroll_spreadsheet",
            TemplateKind::FinancialForecast => "financial_forecast",
            TemplateKind::Credentials => "credentials",
            TemplateKind::ContractDocument => "contract_document",
            TemplateKind::BackupManifest => "backup_manifest",
            TemplateKind::MeetingNotes => "meeting_notes",
            TemplateKind::InvoiceSheet => "invoice_sheet",
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            TemplateKind::PayrollSpreadsheet => "xlsx",
            TemplateKind::FinancialForecast => "xlsx",
            TemplateKind::Credentials => "txt",
            TemplateKind::ContractDocument => "docx",
            TemplateKind::BackupManifest => "pdf",
            TemplateKind::MeetingNotes => "docx",
            TemplateKind::InvoiceSheet => "csv",
        }
    }
}

// --- tiny self-contained PRNG -----------------------------------------
//
// Not cryptographic, doesn't need to be — this only picks which template
// and which filler words to use, so decoys aren't all byte-identical.
// Implemented in-house (xorshift64*) rather than adding the `rand` crate:
// one less dependency whose exact API this sandbox can't verify compiles.

pub struct SimpleRng(u64);

impl SimpleRng {
    pub fn seeded() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15);
        SimpleRng(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn range(&mut self, low: u64, high: u64) -> u64 {
        if high <= low {
            return low;
        }
        low + self.next_u64() % (high - low)
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.range(0, items.len() as u64) as usize]
    }
}

// --- naming ------------------------------------------------------------
//
// Deliberately ordinary — per the doc's "Avoiding Detection" section,
// explicitly avoiding patterns like "AAAA_SECRET.xlsx" or "Honey1.docx".

const SURNAMES: &[&str] = &["Whitfield", "Nakamura", "Alvarez", "Kowalski", "Osei", "Larsen", "Reyes", "Chowdhury"];
const QUARTERS: &[&str] = &["Q1", "Q2", "Q3", "Q4"];
const YEARS: &[&str] = &["2024", "2025", "2026"];

fn generate_filename(kind: TemplateKind, rng: &mut SimpleRng) -> String {
    let ext = kind.extension();
    match kind {
        TemplateKind::PayrollSpreadsheet => {
            format!("Payroll_{}_{}.{}", rng.pick(YEARS), rng.pick(QUARTERS), ext)
        }
        TemplateKind::FinancialForecast => {
            format!("Financial_Forecast_{}.{}", rng.pick(YEARS), ext)
        }
        TemplateKind::Credentials => "VPN_Credentials.".to_string() + ext,
        TemplateKind::ContractDocument => {
            format!("{}_Contract_{}.{}", rng.pick(SURNAMES), rng.pick(YEARS), ext)
        }
        TemplateKind::BackupManifest => {
            format!("Backup_Manifest_{}.{}", rng.pick(YEARS), ext)
        }
        TemplateKind::MeetingNotes => {
            format!("Executive_Meeting_Notes_{}.{}", rng.pick(YEARS), ext)
        }
        TemplateKind::InvoiceSheet => {
            format!("Vendor_Invoices_{}_{}.{}", rng.pick(QUARTERS), rng.pick(YEARS), ext)
        }
    }
}

// --- content -------------------------------------------------------

fn generate_content(kind: TemplateKind, rng: &mut SimpleRng) -> Vec<u8> {
    match kind {
        TemplateKind::PayrollSpreadsheet => {
            let mut s = String::from("Employee,Department,Salary,Tax,Benefits\n");
            let departments = ["Engineering", "Sales", "Finance", "Operations", "Support"];
            for surname in SURNAMES.iter().take(6) {
                let salary = rng.range(58_000, 145_000);
                let tax = salary * 22 / 100;
                let benefits = rng.range(4_000, 12_000);
                s.push_str(&format!(
                    "{},{},{},{},{}\n",
                    surname,
                    rng.pick(&departments),
                    salary,
                    tax,
                    benefits
                ));
            }
            s.into_bytes()
        }

        TemplateKind::FinancialForecast => {
            let mut s = String::from("Quarter,Revenue,Expenses,Projected Growth\n");
            for q in QUARTERS {
                let revenue = rng.range(800_000, 4_200_000);
                let expenses = revenue * rng.range(55, 80) / 100;
                let growth = rng.range(1, 14);
                s.push_str(&format!("{q},{revenue},{expenses},{growth}%\n"));
            }
            s.into_bytes()
        }

        TemplateKind::Credentials => {
            // Deliberately placeholder-looking values — this is bait, not
            // a real secret, and shouldn't double as one.
            format!(
                "VPN Server: vpn.internal.example.corp\n\
                 Username: svc-backup-{:04}\n\
                 Password: [REDACTED - see password manager]\n\
                 Notes: Rotate quarterly. Contact IT for access.\n",
                rng.range(1000, 9999)
            )
            .into_bytes()
        }

        TemplateKind::ContractDocument => {
            format!(
                "EMPLOYMENT AGREEMENT\n\n\
                 This agreement is entered into between the Company and {}, \
                 effective as of {}.\n\n\
                 1. Position and Duties\n\
                 The employee agrees to perform duties as assigned by management.\n\n\
                 2. Compensation\n\
                 Compensation shall be paid in accordance with the Company's standard \
                 payroll schedule.\n\n\
                 3. Confidentiality\n\
                 The employee agrees to maintain confidentiality of proprietary \
                 information during and after employment.\n",
                rng.pick(SURNAMES),
                rng.pick(YEARS)
            )
            .into_bytes()
        }

        TemplateKind::MeetingNotes => {
            format!(
                "EXECUTIVE MEETING NOTES\n\
                 Date: {} \n\
                 Attendees: Leadership Team\n\n\
                 1. Reviewed quarterly performance against targets.\n\
                 2. Discussed budget allocation for upcoming initiatives.\n\
                 3. Approved headcount plan for next quarter.\n\
                 4. Action items assigned to department leads.\n",
                rng.pick(YEARS)
            )
            .into_bytes()
        }

        TemplateKind::InvoiceSheet => {
            let mut s = String::from("Invoice,Amount,Status,Due Date\n");
            for i in 0..6 {
                let amount = rng.range(340, 18_500);
                let status = if rng.range(0, 4) == 0 { "Paid" } else { "Pending" };
                s.push_str(&format!("INV-{:05},{amount},{status},{}-{:02}-01\n", 10000 + i, rng.pick(YEARS), rng.range(1, 12)));
            }
            s.into_bytes()
        }

        TemplateKind::BackupManifest => {
            let lines = vec![
                "GasLight Backup Manifest".to_string(),
                format!("Generated: {}", rng.pick(YEARS)),
                "".to_string(),
                "Volume: D:\\Backups\\Nightly".to_string(),
                "Retention: 90 days".to_string(),
                "Encryption: AES-256 (managed key)".to_string(),
                "".to_string(),
                "Last successful run: completed without errors.".to_string(),
            ];
            render_minimal_pdf("Backup Manifest", &lines)
        }
    }
}

pub fn generate(kind: TemplateKind, rng: &mut SimpleRng) -> (String, Vec<u8>) {
    let filename = generate_filename(kind, rng);
    let content = generate_content(kind, rng);
    (filename, content)
}

// --- minimal valid PDF writer --------------------------------------
//
// Hand-written rather than using a crate: the PDF object/xref format is
// simple and has been stable for decades, and byte offsets are computed
// programmatically from the buffer's actual length as it's built (not
// memorized/guessed), which is the main source of bugs in hand-rolled PDF
// generators.

fn escape_pdf_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out
}

fn render_minimal_pdf(title: &str, lines: &[String]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut offsets: Vec<usize> = Vec::with_capacity(6);

    buf.extend_from_slice(b"%PDF-1.4\n");

    // --- object 1: catalog ---
    offsets.push(buf.len());
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    // --- object 2: pages ---
    offsets.push(buf.len());
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    // --- object 3: page ---
    offsets.push(buf.len());
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> \
          /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n",
    );

    // --- object 4: font ---
    offsets.push(buf.len());
    buf.extend_from_slice(b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");

    // --- object 5: content stream ---
    let mut stream = String::new();
    stream.push_str("BT /F1 16 Tf 72 740 Td (");
    stream.push_str(&escape_pdf_text(title));
    stream.push_str(") Tj\n");
    stream.push_str("/F1 11 Tf 0 -32 Td\n");
    for line in lines {
        stream.push_str("(");
        stream.push_str(&escape_pdf_text(line));
        stream.push_str(") Tj 0 -16 Td\n");
    }
    stream.push_str("ET");

    offsets.push(buf.len());
    buf.extend_from_slice(format!("5 0 obj\n<< /Length {} >>\nstream\n", stream.len()).as_bytes());
    buf.extend_from_slice(stream.as_bytes());
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    // --- xref table ---
    let xref_offset = buf.len();
    buf.extend_from_slice(b"xref\n0 6\n");
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        buf.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }

    // --- trailer ---
    buf.extend_from_slice(b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n");
    buf.extend_from_slice(format!("{xref_offset}\n").as_bytes());
    buf.extend_from_slice(b"%%EOF");

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_produces_varying_values() {
        let mut rng = SimpleRng::seeded();
        let a = rng.next_u64();
        let b = rng.next_u64();
        assert_ne!(a, b);
    }

    #[test]
    fn every_template_kind_produces_nonempty_name_and_content() {
        let mut rng = SimpleRng::seeded();
        for kind in TemplateKind::ALL {
            let (name, content) = generate(*kind, &mut rng);
            assert!(!name.is_empty());
            assert!(name.ends_with(kind.extension()));
            assert!(!content.is_empty());
        }
    }

    #[test]
    fn generated_pdf_has_a_valid_header_and_eof_marker() {
        let mut rng = SimpleRng::seeded();
        let (_, content) = generate(TemplateKind::BackupManifest, &mut rng);
        assert!(content.starts_with(b"%PDF-1.4"));
        assert!(content.ends_with(b"%%EOF"));
    }

    #[test]
    fn pdf_text_escaping_handles_parentheses_and_backslashes() {
        let escaped = escape_pdf_text("Value (in dollars) \\ note");
        assert_eq!(escaped, "Value \\(in dollars\\) \\\\ note");
    }
}
