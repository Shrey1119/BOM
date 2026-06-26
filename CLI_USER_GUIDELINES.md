# Windows Command Line (CMD) Execution Guidelines

This guide details how to open `cmd.exe`, configure your environment, and execute the automated SBOM generation pipeline or individual role scripts.

---

## Step 1: Open the Command Prompt (`cmd.exe`)

1. Press the **Windows Key** on your keyboard or click the Start Menu.
2. Type **`cmd`** or **`Command Prompt`**.
3. Press **Enter** to open the terminal window.

---

## Step 2: Navigate to the Project Directory

Since the project resides on drive **`D:`**, you must switch drives first before changing directories. Run the following commands in the prompt:

```cmd
:: 1. Switch from the default C: drive to the D: drive
d:

:: 2. Navigate to the project directory (use quotes since path contains spaces)
cd "d:\College Work\Internship\BOM"
```

You should see your prompt change to:
`D:\College Work\Internship\BOM>`

---

## Step 3: Verify Python Installation

Verify that Python is available in your command line environment:

```cmd
python --version
```
*Expected Output:* `Python 3.10.x` or higher.

---

## Step 4: Configure the Encryption Passphrase (Optional)

If you wish to cryptographically encrypt the restricted files (vulnerabilities, private keys, enriched SBOM) using AES-256-GCM during the run:

```cmd
:: Set the encryption key environment variable
set SBOM_ENC_KEY=YourSuperSecretKey123!
```

*Note: This variable will persist only for the duration of this specific Command Prompt window session.*

---

## Step 5: Run the Automated Pipeline

You can run the automated pipeline in two ways:

### **Method A: Standalone Executable (Double-Click or CMD)**
Run the compiled `run_pipeline.exe` located in the root folder:
1. Double-click **`run_pipeline.exe`** directly from Windows Explorer, or
2. From the command prompt, execute:
   ```cmd
   run_pipeline.exe
   ```

This will launch the interactive console interface providing options for **Full Scan**, **Quick Scan**, **Excel Export**, and **Cyclone DX Export**.

### **Method B: Python Script**
If you prefer running via Python, execute:
```cmd
python run_pipeline.py
```

---

## Step 6: Running Individual Role Scripts Manually

If you prefer to run the scripts manually to simulate each team member's tasks, execute the following commands in order:

### **Task A: Run the Scanner (Team Member 2)**
Run the filesystem vulnerability scanner using the local Trivy binary:
```cmd
python "Member 2/sbom_scanner.py" --src mock_project --output sbom_raw.json --trivy-path "Member 2/trivy.exe"
```

### **Task B: Enrich raw SBOM metadata (Team Member 3)**
Fetch missing component metadata and format package PURLs:
```cmd
python "Member 3/enricher.py" sbom_raw.json sbom_enriched.json
```

### **Task C: Validate Enrichment Compliance (Team Member 3)**
Assert that all 21 client attributes are successfully populated:
```cmd
python "Member 3/validator.py" sbom_enriched.json
```

### **Task D: Split & Sign SBOM (Team Member 2)**
Separate the enriched SBOM into Public/Private variants and generate signature files:
```cmd
python "Member 2/sbom_distributor.py" --sbom sbom_enriched.json --keys-dir "Member 2/keys" --output-dir sbom_output
```

### **Task E: Generate VEX & CSAF Advisories (Team Member 1)**
Compile vulnerability classifications and vendor advisories:
```cmd
python sbom_toolsuite/vex_csaf_generator.py
```

### **Task F: Compile Internal Component Map (Team Member 1)**
Generate the internal governance component mapping:
```cmd
python sbom_toolsuite/build_internal_map.py
```

### **Task G: Render HTML Report (Team Member 2)**
Export a human-readable vulnerability report in HTML format:
```cmd
"Member 2/trivy.exe" fs --format template --template "@Member 2/contrib/html.tpl" --output sbom_output/report.html mock_project
```
