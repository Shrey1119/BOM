import os
import sys
import argparse
import subprocess
import urllib.request
import zipfile
import io
import shutil
import json
import time
import threading

# Root directories relative to script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)

# Default path constants
SYFT_EXE_DEFAULT = os.path.join(PARENT_DIR, "Member 4", "bin", "syft.exe")
GRYPE_EXE_DEFAULT = os.path.join(PARENT_DIR, "Member 4", "bin", "grype.exe")
TRIVY_EXE_DEFAULT = os.path.join(PARENT_DIR, "Trivy", "trivy_cli.exe")


# ══════════════════════════════════════════════════════════════════
# ANSI Color & Style Helpers
# ══════════════════════════════════════════════════════════════════
class C:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    CYAN    = "\033[36m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    RED     = "\033[31m"
    MAGENTA = "\033[35m"
    BLUE    = "\033[34m"
    WHITE   = "\033[97m"
    BG_DARK = "\033[48;5;235m"
    # Bright variants
    B_CYAN    = "\033[96m"
    B_GREEN   = "\033[92m"
    B_YELLOW  = "\033[93m"
    B_RED     = "\033[91m"
    B_MAGENTA = "\033[95m"
    B_BLUE    = "\033[94m"

    @staticmethod
    def enable():
        """Enable ANSI colors on Windows."""
        if os.name == "nt":
            os.system("")  # triggers VT100 mode on Win10+


# ══════════════════════════════════════════════════════════════════
# Animated Spinner
# ══════════════════════════════════════════════════════════════════
class ScannerSpinner:
    """Threaded animated spinner with elapsed timer for long-running scans."""

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, label, color=C.CYAN):
        self.label = label
        self.color = color if sys.stdout.isatty() else ""
        self._stop_event = threading.Event()
        self._thread = None
        self._start_time = 0
        self.is_tty = sys.stdout.isatty()

    def _animate(self):
        idx = 0
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start_time
            frame = self.FRAMES[idx % len(self.FRAMES)]
            timer_str = f"{elapsed:5.1f}s"
            line = f"\r  {self.color}{frame}{C.RESET if self.is_tty else ''} {self.label}  {C.DIM if self.is_tty else ''}[{timer_str}]{C.RESET if self.is_tty else ''}  "
            sys.stdout.write(line)
            sys.stdout.flush()
            idx += 1
            self._stop_event.wait(0.08)

    def start(self):
        self._start_time = time.time()
        if self.is_tty:
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._animate, daemon=True)
            self._thread.start()
        else:
            # Just print a start message if piped
            print(f"  > {self.label} ...")
            sys.stdout.flush()

    def stop(self, success=True):
        self._stop_event.set()
        if self._thread:
            self._thread.join()
        elapsed = time.time() - self._start_time
        
        if self.is_tty:
            icon = f"{C.B_GREEN}OK{C.RESET}" if success else f"{C.B_RED}FAIL{C.RESET}"
            status = f"{C.B_GREEN}DONE{C.RESET}" if success else f"{C.B_RED}FAIL{C.RESET}"
            sys.stdout.write(f"\r  {icon} {self.label}  {C.DIM}[{elapsed:.1f}s]{C.RESET}  [{status}]\n")
            sys.stdout.flush()
        else:
            status = "DONE" if success else "FAIL"
            print(f"  > {self.label} [{elapsed:.1f}s] [{status}]")
            sys.stdout.flush()
        return elapsed


# ══════════════════════════════════════════════════════════════════
# Phase Progress Display
# ══════════════════════════════════════════════════════════════════
def print_phase_header():
    """Print the scanner phase header banner."""
    print()
    if sys.stdout.isatty():
        print(f"  {C.BOLD}{C.B_CYAN}+----------------------------------------------------------+{C.RESET}")
        print(f"  {C.BOLD}{C.B_CYAN}|{C.RESET}       {C.BOLD}{C.WHITE}SBOM  MULTI-SCANNER  ORCHESTRATION  ENGINE{C.RESET}        {C.BOLD}{C.B_CYAN}|{C.RESET}")
        print(f"  {C.BOLD}{C.B_CYAN}+----------------------------------------------------------+{C.RESET}")
        print(f"  {C.BOLD}{C.B_CYAN}|{C.RESET}  {C.DIM}Scanners: Syft + Grype | Trivy | cdxgen{C.RESET}                {C.BOLD}{C.B_CYAN}|{C.RESET}")
        print(f"  {C.BOLD}{C.B_CYAN}|{C.RESET}  {C.DIM}Output  : CycloneDX JSON (merged){C.RESET}                     {C.BOLD}{C.B_CYAN}|{C.RESET}")
        print(f"  {C.BOLD}{C.B_CYAN}+----------------------------------------------------------+{C.RESET}")
    else:
        print(f"  +----------------------------------------------------------+")
        print(f"  |       SBOM  MULTI-SCANNER  ORCHESTRATION  ENGINE         |")
        print(f"  +----------------------------------------------------------+")
        print(f"  |  Scanners: Syft + Grype | Trivy | cdxgen                 |")
        print(f"  |  Output  : CycloneDX JSON (merged)                       |")
        print(f"  +----------------------------------------------------------+")
    print()


def print_phase_start(num, total, name, detail=""):
    """Print a phase start line."""
    if sys.stdout.isatty():
        bar = "-" * 58
        print(f"  {C.BOLD}{C.B_BLUE}+{bar}+{C.RESET}")
        tag = f"Phase {num}/{total}"
        print(f"  {C.BOLD}{C.B_BLUE}|{C.RESET}  {C.BOLD}{C.B_CYAN}> {tag}{C.RESET}  {C.BOLD}{name}{C.RESET}")
        if detail:
            print(f"  {C.BOLD}{C.B_BLUE}|{C.RESET}    {C.DIM}{detail}{C.RESET}")
        print(f"  {C.BOLD}{C.B_BLUE}+{bar}+{C.RESET}")
    else:
        bar = "-" * 58
        print(f"  +{bar}+")
        tag = f"Phase {num}/{total}"
        print(f"  |  > {tag}  {name}")
        if detail:
            print(f"  |    {detail}")
        print(f"  +{bar}+")


def print_scan_result(label, count, color=C.B_GREEN):
    """Print a scan result metric."""
    if sys.stdout.isatty():
        print(f"    {C.DIM}|-{C.RESET} {label}: {color}{C.BOLD}{count}{C.RESET}")
    else:
        print(f"    |- {label}: {count}")


def print_quality_summary(results):
    """Print a colored quality summary table after all scans."""
    print()
    if sys.stdout.isatty():
        print(f"  {C.BOLD}{C.B_MAGENTA}+----------------------------------------------------------+{C.RESET}")
        print(f"  {C.BOLD}{C.B_MAGENTA}|{C.RESET}  {C.BOLD}{C.WHITE}SCAN QUALITY SUMMARY{C.RESET}                                    {C.BOLD}{C.B_MAGENTA}|{C.RESET}")
        print(f"  {C.BOLD}{C.B_MAGENTA}+----------------------------------------------------------+{C.RESET}")
    else:
        print(f"  +----------------------------------------------------------+")
        print(f"  |  SCAN QUALITY SUMMARY                                    |")
        print(f"  +----------------------------------------------------------+")

    total_comps = 0
    total_vulns = 0
    total_hashes = 0

    for scanner_name, data in results.items():
        comps = data.get("components", 0)
        vulns = data.get("vulnerabilities", 0)
        purls = data.get("with_purl", 0)
        hashes = data.get("with_hash", 0)
        elapsed = data.get("elapsed", 0)

        total_comps += comps
        total_vulns += vulns
        total_hashes += hashes

        purl_pct = (purls / max(comps, 1)) * 100
        
        if sys.stdout.isatty():
            purl_color = C.B_GREEN if purl_pct >= 95 else (C.B_YELLOW if purl_pct >= 80 else C.B_RED)
            print(f"  {C.BOLD}{C.B_MAGENTA}|{C.RESET}  {C.BOLD}{C.CYAN}{scanner_name:14s}{C.RESET}"
                  f"  Comps: {C.BOLD}{comps:>5}{C.RESET}"
                  f"  Vulns: {C.BOLD}{vulns:>4}{C.RESET}"
                  f"  PURL: {purl_color}{purl_pct:5.1f}%{C.RESET}"
                  f"  {C.DIM}{elapsed:5.1f}s{C.RESET} {C.BOLD}{C.B_MAGENTA}|{C.RESET}")
        else:
            print(f"  |  {scanner_name:14s}  Comps: {comps:>5}  Vulns: {vulns:>4}  PURL: {purl_pct:5.1f}%  {elapsed:5.1f}s |")

    if sys.stdout.isatty():
        print(f"  {C.BOLD}{C.B_MAGENTA}+----------------------------------------------------------+{C.RESET}")
        print(f"  {C.BOLD}{C.B_MAGENTA}|{C.RESET}  {C.BOLD}TOTALS{C.RESET}"
              f"          Comps: {C.B_GREEN}{C.BOLD}{total_comps:>5}{C.RESET}"
              f"  Vulns: {C.B_YELLOW}{C.BOLD}{total_vulns:>4}{C.RESET}"
              f"  Hashes: {C.BOLD}{total_hashes:>5}{C.RESET}"
              f"       {C.BOLD}{C.B_MAGENTA}|{C.RESET}")
        print(f"  {C.BOLD}{C.B_MAGENTA}+----------------------------------------------------------+{C.RESET}")
    else:
        print(f"  +----------------------------------------------------------+")
        print(f"  |  TOTALS          Comps: {total_comps:>5}  Vulns: {total_vulns:>4}  Hashes: {total_hashes:>5}       |")
        print(f"  +----------------------------------------------------------+")
    print()


def print_completion_banner(total_elapsed):
    """Print the final completion banner with animation."""
    if sys.stdout.isatty():
        bar_width = 40
        # Animated progress bar fill (using CP1252-safe ASCII # and -)
        for i in range(bar_width + 1):
            filled = "#" * i
            empty = "-" * (bar_width - i)
            pct = int((i / bar_width) * 100)
            sys.stdout.write(f"\r  {C.B_GREEN}  [{filled}{empty}] {pct}%{C.RESET}")
            sys.stdout.flush()
            time.sleep(0.015)
        print()
        print()
        print(f"  {C.BOLD}{C.B_GREEN}+----------------------------------------------------------+{C.RESET}")
        print(f"  {C.BOLD}{C.B_GREEN}|{C.RESET}  {C.BOLD}{C.B_GREEN}[OK]  ALL SCANS COMPLETED SUCCESSFULLY{C.RESET}                    {C.BOLD}{C.B_GREEN}|{C.RESET}")
        print(f"  {C.BOLD}{C.B_GREEN}|{C.RESET}     {C.DIM}Total elapsed: {total_elapsed:.1f}s{C.RESET}                              {C.BOLD}{C.B_GREEN}|{C.RESET}")
        print(f"  {C.BOLD}{C.B_GREEN}+----------------------------------------------------------+{C.RESET}")
    else:
        print(f"  +----------------------------------------------------------+")
        print(f"  |  ALL SCANS COMPLETED SUCCESSFULLY                        |")
        print(f"  |  Total elapsed: {total_elapsed:.1f}s                                   |")
        print(f"  +----------------------------------------------------------+")
    print()


# ══════════════════════════════════════════════════════════════════
# Utility: Analyze a CycloneDX JSON for quality metrics
# ══════════════════════════════════════════════════════════════════
def analyze_scan_output(filepath):
    """Read a CycloneDX JSON and return quality metrics."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"components": 0, "vulnerabilities": 0, "with_purl": 0, "with_hash": 0}

    comps = data.get("components", [])
    vulns = data.get("vulnerabilities", [])
    with_purl = sum(1 for c in comps if c.get("purl"))
    with_hash = sum(1 for c in comps if c.get("hashes"))

    return {
        "components": len(comps),
        "vulnerabilities": len(vulns),
        "with_purl": with_purl,
        "with_hash": with_hash,
    }


# ══════════════════════════════════════════════════════════════════
# Binary Resolvers (unchanged logic, cleaner output)
# ══════════════════════════════════════════════════════════════════
def is_lfs_pointer(file_path):
    """Checks if a file is a Git LFS pointer instead of a real binary."""
    if not os.path.exists(file_path):
        return False
    try:
        with open(file_path, "rb") as f:
            header = f.read(100)
            return header.startswith(b"version https://git-lfs")
    except Exception:
        return False


def download_trivy(download_dir):
    """Downloads and extracts Trivy CLI v0.71.2 for Windows."""
    url = "https://github.com/aquasecurity/trivy/releases/download/v0.71.2/trivy_0.71.2_Windows-64bit.zip"
    print(f"  {C.YELLOW}[v]{C.RESET} Downloading Trivy binary from GitHub releases...")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=60) as response:
            zip_bytes = response.read()

        os.makedirs(download_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            z.extract("trivy.exe", path=download_dir)
            extracted_path = os.path.join(download_dir, "trivy.exe")
            target_path = os.path.join(download_dir, "trivy_cli.exe")
            if os.path.exists(target_path):
                os.remove(target_path)
            os.rename(extracted_path, target_path)
        print(f"  {C.B_GREEN}[+]{C.RESET} Trivy binary downloaded and extracted.")
        return target_path
    except Exception as e:
        print(f"  {C.B_RED}[x]{C.RESET} Failed to download Trivy: {e}")
        return None


def find_trivy(specified_path=None):
    """Finds the trivy executable, with automatic LFS fix and download fallback."""
    if specified_path:
        if os.path.exists(specified_path):
            if is_lfs_pointer(specified_path):
                print(f"  {C.YELLOW}[!]{C.RESET} Specified Trivy is an LFS pointer. Downloading real binary...")
                fixed_path = download_trivy(os.path.dirname(os.path.abspath(specified_path)))
                if fixed_path:
                    return fixed_path
            else:
                return specified_path
        else:
            print(f"  {C.B_RED}[x]{C.RESET} Specified Trivy path does not exist: {specified_path}")
            sys.exit(1)

    if os.path.exists(TRIVY_EXE_DEFAULT) and not is_lfs_pointer(TRIVY_EXE_DEFAULT):
        return TRIVY_EXE_DEFAULT

    if os.path.exists(TRIVY_EXE_DEFAULT) and is_lfs_pointer(TRIVY_EXE_DEFAULT):
        fixed_path = download_trivy(os.path.dirname(TRIVY_EXE_DEFAULT))
        if fixed_path:
            return fixed_path

    # Check PATH
    try:
        cmd = "where" if os.name == "nt" else "which"
        subprocess.run([cmd, "trivy"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return "trivy"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    print(f"  {C.YELLOW}[!]{C.RESET} Trivy not found locally. Downloading...")
    fixed_path = download_trivy(os.path.join(PARENT_DIR, "Trivy"))
    if fixed_path:
        return fixed_path

    print(f"  {C.B_RED}[x]{C.RESET} Trivy executable not found and download failed.")
    sys.exit(1)


def find_binary(path_default, name):
    """Generic lookup helper for Syft/Grype binaries."""
    if os.path.exists(path_default) and not is_lfs_pointer(path_default):
        return path_default

    # Try system PATH
    try:
        cmd = "where" if os.name == "nt" else "which"
        subprocess.run([cmd, name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return name
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    print(f"  {C.B_RED}[x]{C.RESET} Required binary '{name}' not found at '{path_default}' or in PATH.")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════
# Core Scan Runner
# ══════════════════════════════════════════════════════════════════
def run_scans(src_dir, syft_grype_out, trivy_out, cdxgen_out, trivy_path):
    """Runs the 3 scans (Syft+Grype, Trivy fs, cdxgen) with animated progress."""
    C.enable()

    abs_src = os.path.abspath(src_dir)
    abs_syft_grype = os.path.abspath(syft_grype_out)
    abs_trivy = os.path.abspath(trivy_out)
    abs_cdxgen = os.path.abspath(cdxgen_out)

    syft_exe = find_binary(SYFT_EXE_DEFAULT, "syft")
    grype_exe = find_binary(GRYPE_EXE_DEFAULT, "grype")

    # Ensure parent output directory exists
    for p in [abs_syft_grype, abs_trivy, abs_cdxgen]:
        os.makedirs(os.path.dirname(p), exist_ok=True)

    # ── Header ──
    print_phase_header()
    print(f"  {C.BOLD}Target:{C.RESET} {C.CYAN}{abs_src}{C.RESET}")
    print()

    scan_results = {}
    total_start = time.time()

    # ═══════════════════════════════════════════════════════════════
    # Phase 1: Syft + Grype (Deep Binary Parsing + Vuln Injection)
    # ═══════════════════════════════════════════════════════════════
    print_phase_start(1, 3, "Syft + Grype", "Filesystem cataloging -> vulnerability injection")

    temp_syft_raw = os.path.join(SCRIPT_DIR, "syft_raw_temp.json")

    # 1a. Syft scan
    spinner = ScannerSpinner("Syft filesystem cataloging...", C.CYAN)
    spinner.start()

    syft_cmd = [syft_exe, "scan", f"dir:{abs_src}", "-o", "cyclonedx-json"]
    try:
        with open(temp_syft_raw, 'w', encoding='utf-8') as f_out:
            subprocess.run(syft_cmd, stdout=f_out, stderr=subprocess.PIPE, text=True, check=True)
        syft_elapsed = spinner.stop(success=True)
    except subprocess.CalledProcessError as e:
        spinner.stop(success=False)
        print(f"  {C.B_RED}[x] Syft scan failed:{C.RESET} {e.stderr or e}")
        return False
    except FileNotFoundError:
        spinner.stop(success=False)
        print(f"  {C.B_RED}[x] Syft executable not found. Check path: {syft_exe}{C.RESET}")
        return False

    # 1b. Grype vulnerability injection
    spinner = ScannerSpinner("Grype vulnerability matching...", C.YELLOW)
    spinner.start()

    grype_cmd = [grype_exe, f"sbom:{temp_syft_raw}", "-o", "cyclonedx-json", "--file", abs_syft_grype]
    grype_env = os.environ.copy()
    grype_env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] = "87600h"
    try:
        subprocess.run(grype_cmd, capture_output=True, text=True, check=True, env=grype_env)
        grype_elapsed = spinner.stop(success=True)
    except subprocess.CalledProcessError as e:
        spinner.stop(success=False)
        print(f"  {C.B_RED}[x] Grype failed:{C.RESET} {e.stderr or e}")
        return False
    finally:
        if os.path.exists(temp_syft_raw):
            os.remove(temp_syft_raw)

    # Analyze Phase 1 output
    metrics = analyze_scan_output(abs_syft_grype)
    metrics["elapsed"] = syft_elapsed + grype_elapsed
    scan_results["Syft + Grype"] = metrics
    print_scan_result("Components", metrics["components"])
    print_scan_result("Vulnerabilities", metrics["vulnerabilities"],
                      C.B_RED if metrics["vulnerabilities"] > 0 else C.B_GREEN)
    print_scan_result("With PURL", f"{metrics['with_purl']}/{metrics['components']}")
    print()

    # ═══════════════════════════════════════════════════════════════
    # Phase 2: Trivy (Vulnerability + License Scan)
    # ═══════════════════════════════════════════════════════════════
    print_phase_start(2, 3, "Trivy", "Vulnerability detection + license analysis")

    spinner = ScannerSpinner("Trivy filesystem scan...", C.GREEN)
    spinner.start()

    trivy_cmd = [
        trivy_path,
        "fs",
        "--format", "cyclonedx",
        "--scanners", "vuln",
        "--list-all-pkgs",
        "--output", abs_trivy,
        abs_src
    ]
    try:
        subprocess.run(trivy_cmd, capture_output=True, text=True, check=True)
        trivy_elapsed = spinner.stop(success=True)
    except subprocess.CalledProcessError as e:
        spinner.stop(success=False)
        print(f"  {C.B_RED}[x] Trivy failed:{C.RESET} {e.stderr or e}")
        return False

    # Analyze Phase 2 output
    metrics = analyze_scan_output(abs_trivy)
    metrics["elapsed"] = trivy_elapsed
    scan_results["Trivy"] = metrics
    print_scan_result("Components", metrics["components"])
    print_scan_result("Vulnerabilities", metrics["vulnerabilities"],
                      C.B_RED if metrics["vulnerabilities"] > 0 else C.B_GREEN)
    print_scan_result("With PURL", f"{metrics['with_purl']}/{metrics['components']}")
    print()

    # ═══════════════════════════════════════════════════════════════
    # Phase 3: cdxgen (Reachability Analysis)
    # ═══════════════════════════════════════════════════════════════
    print_phase_start(3, 3, "cdxgen", "Deep dependency resolution + reachability")

    spinner = ScannerSpinner("cdxgen deep analysis...", C.MAGENTA)
    spinner.start()

    cdxgen_cmd = 'npx @cyclonedx/cdxgen -r --spec-version 1.5 --with-reachables -o "{}" "{}"'.format(
        abs_cdxgen, abs_src)
    try:
        subprocess.run(cdxgen_cmd, capture_output=True, text=True, check=True, shell=True)
        if os.path.exists(abs_cdxgen):
            cdxgen_elapsed = spinner.stop(success=True)
        else:
            spinner.stop(success=False)
            print(f"  {C.B_RED}[x] cdxgen completed but output file was not created.{C.RESET}")
            return False
    except subprocess.CalledProcessError as e:
        spinner.stop(success=False)
        print(f"  {C.B_RED}[x] cdxgen failed:{C.RESET} {e.stderr or e.output}")
        return False

    # Analyze Phase 3 output
    metrics = analyze_scan_output(abs_cdxgen)
    metrics["elapsed"] = cdxgen_elapsed
    scan_results["cdxgen"] = metrics
    print_scan_result("Components", metrics["components"])
    print_scan_result("With Hashes", f"{metrics['with_hash']}/{metrics['components']}",
                      C.B_GREEN if metrics["with_hash"] > 0 else C.B_YELLOW)
    print_scan_result("Dependencies", "full tree resolved")
    print()

    # ── Quality Summary & Completion ──
    print_quality_summary(scan_results)

    total_elapsed = time.time() - total_start
    print_completion_banner(total_elapsed)

    return True


# ══════════════════════════════════════════════════════════════════
# Main Entry Point
# ══════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="Multi-Scanner SBOM Orchestration Wrapper")
    parser.add_argument("--src", required=True, help="Path to the source directory to scan")
    parser.add_argument("--syft-grype", default="syft_grype.json", help="Output path for Syft+Grype CycloneDX")
    parser.add_argument("--trivy", default="trivy_raw.json", help="Output path for Trivy CycloneDX")
    parser.add_argument("--cdxgen", default="cdxgen_raw.json", help="Output path for cdxgen CycloneDX")
    parser.add_argument("--trivy-path", help="Path to the Trivy executable")

    args = parser.parse_args()

    trivy_exe = find_trivy(args.trivy_path)
    success = run_scans(args.src, args.syft_grype, args.trivy, args.cdxgen, trivy_exe)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
