param(
    [string]$OutputDir = "output\pdf",
    [string]$ChromePath = "",
    [string]$PandocPath = "pandoc"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$PaperDir = Join-Path $RepoRoot "paper_lncs"
$OutDir = Join-Path $RepoRoot $OutputDir
$HtmlPath = Join-Path $OutDir "catad_submission_preview.html"
$PdfPath = Join-Path $OutDir "catad_submission_preview.pdf"
$PandocLogPath = Join-Path $OutDir "catad_submission_preview_pandoc.log"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function HtmlEncode {
    param([string]$Text)
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Clean-LatexCell {
    param([string]$Text)
    $s = $Text.Trim()
    $s = $s -replace "\\\\\s*$", ""
    $s = $s -replace "\\%", "%"
    $s = $s -replace "\\&", "&"
    $s = $s -replace "\$\\checkmark\$", "Yes"
    $s = $s -replace "\\checkmark", "Yes"
    $s = $s -replace "\$", ""
    $s = $s -replace "\\mathrm\{([^}]*)\}", '$1'
    $s = $s -replace "\\textbf\{([^}]*)\}", '$1'
    $s = $s -replace "\\emph\{([^}]*)\}", '$1'
    $s = $s -replace "~", " "
    $s = $s -replace "\s+", " "
    return $s.Trim()
}

function Convert-LatexTableToHtml {
    param(
        [string]$Path,
        [string]$CssClass
    )

    $tex = Get-Content -LiteralPath $Path -Raw
    $caption = [regex]::Match($tex, "\\caption\{([^}]*)\}").Groups[1].Value
    $caption = Clean-LatexCell $caption

    $match = [regex]::Match($tex, "(?s)\\toprule\s*(.*?)\\midrule\s*(.*?)\\bottomrule")
    if (-not $match.Success) {
        throw "Could not parse LaTeX table: $Path"
    }

    $headerLine = (($match.Groups[1].Value -split "\r?\n") | Where-Object { $_ -match "&" } | Select-Object -First 1)
    $rowLines = (($match.Groups[2].Value -split "\r?\n") | Where-Object { $_ -match "&" })

    $html = New-Object System.Text.StringBuilder
    [void]$html.AppendLine("<div class=""$CssClass"">")
    [void]$html.AppendLine("<div class=""table-caption"">$(HtmlEncode $caption)</div>")
    [void]$html.AppendLine("<table>")
    [void]$html.AppendLine("<thead><tr>")
    foreach ($cell in ($headerLine -split "\s*&\s*")) {
        [void]$html.AppendLine("<th>$(HtmlEncode (Clean-LatexCell $cell))</th>")
    }
    [void]$html.AppendLine("</tr></thead>")
    [void]$html.AppendLine("<tbody>")
    foreach ($line in $rowLines) {
        [void]$html.AppendLine("<tr>")
        foreach ($cell in ($line -split "\s*&\s*")) {
            [void]$html.AppendLine("<td>$(HtmlEncode (Clean-LatexCell $cell))</td>")
        }
        [void]$html.AppendLine("</tr>")
    }
    [void]$html.AppendLine("</tbody>")
    [void]$html.AppendLine("</table>")

    $foot = [regex]::Match($tex, "(?s)\\footnotesize\s+(.*?)\\end\{minipage\}")
    if ($foot.Success) {
        [void]$html.AppendLine("<p class=""table-note"">$(HtmlEncode (Clean-LatexCell $foot.Groups[1].Value))</p>")
    }
    [void]$html.AppendLine("</div>")
    return $html.ToString()
}

function Find-Chrome {
    param([string]$ExplicitPath)
    if ($ExplicitPath -and (Test-Path -LiteralPath $ExplicitPath)) {
        return $ExplicitPath
    }
    $candidates = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    throw "Could not find Chrome or Edge. Pass -ChromePath explicitly."
}

Push-Location $PaperDir
try {
    Remove-Item -LiteralPath $PandocLogPath -ErrorAction SilentlyContinue
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $PandocPath "main.tex" `
        "--from" "latex" `
        "--to" "html5" `
        "--standalone" `
        "--bibliography" "references.bib" `
        "--citeproc" `
        "--resource-path=.;..;..\figures;..\outputs\tables;..\outputs\publication_benchmark" `
        "-o" $HtmlPath 2> $PandocLogPath
    $pandocExitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousErrorActionPreference
    if ($pandocExitCode -ne 0) {
        if (Test-Path -LiteralPath $PandocLogPath) {
            Get-Content -LiteralPath $PandocLogPath
        }
        throw "Pandoc failed with exit code $pandocExitCode"
    }
    if ((Test-Path -LiteralPath $PandocLogPath) -and ((Get-Item -LiteralPath $PandocLogPath).Length -gt 0)) {
        $pandocLog = Get-Content -Raw -LiteralPath $PandocLogPath
        if ($pandocLog.IndexOf("[WARNING]", [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Get-Content -LiteralPath $PandocLogPath
            throw "Pandoc completed with warnings; fix the manuscript source before building the preview PDF"
        }
    }
}
finally {
    if ($previousErrorActionPreference) {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    Pop-Location
}

$htmlText = Get-Content -LiteralPath $HtmlPath -Raw -Encoding UTF8

$printCss = @"

    @page {
      size: A4;
      margin: 16mm 15mm 17mm 15mm;
    }
    body {
      max-width: none;
      width: auto;
      padding: 0;
      margin: 0 auto;
      font-family: "Times New Roman", Times, serif;
      font-size: 10pt;
      line-height: 1.24;
      color: #111;
      background: white;
    }
    header {
      margin-bottom: 1.4em;
      text-align: center;
    }
    h1.title {
      font-size: 17pt;
      line-height: 1.12;
      margin: 0 0 0.7em 0;
    }
    p.author, p.date {
      margin: 0.15em 0;
      font-size: 10pt;
    }
    div.abstract {
      margin: 1.2em 10mm 1.4em 10mm;
      font-size: 9pt;
      text-align: justify;
    }
    h1 {
      font-size: 13pt;
      margin: 1.05em 0 0.35em 0;
      page-break-after: avoid;
    }
    h2 {
      font-size: 11pt;
      margin: 0.8em 0 0.25em 0;
      page-break-after: avoid;
    }
    h3, h4 {
      font-size: 10pt;
      margin: 0.55em 0 0.2em 0;
      page-break-after: avoid;
    }
    p {
      margin: 0.36em 0;
      text-align: justify;
    }
    ul {
      margin: 0.35em 0 0.5em 1.3em;
      padding-left: 1em;
    }
    li {
      margin: 0.2em 0;
    }
    table {
      display: table;
      width: 100%;
      border-collapse: collapse;
      margin: 0.35em 0 0.25em 0;
      font-size: 8.1pt;
      page-break-inside: avoid;
    }
    th, td {
      padding: 2.5px 4px;
      vertical-align: top;
      border: 0;
    }
    th {
      border-top: 1px solid #111;
      border-bottom: 0.7px solid #111;
      font-weight: 700;
    }
    tbody tr:last-child td {
      border-bottom: 1px solid #111;
    }
    .wide-table {
      margin: 0.85em 0 1.1em 0;
      page-break-inside: avoid;
    }
    .wide-table table {
      font-size: 7.2pt;
    }
    .table-caption {
      text-align: center;
      font-weight: 700;
      margin: 0.6em 0 0.25em 0;
      page-break-after: avoid;
    }
    .table-note {
      font-size: 7.7pt;
      margin: 0.2em 0 0.6em 0;
      text-align: left;
    }
    figure {
      margin: 0.75em 0 0.9em 0;
      text-align: center;
      page-break-inside: avoid;
    }
    figcaption {
      font-size: 8.6pt;
      margin-top: 0.3em;
      text-align: justify;
    }
    .display-equation {
      margin: 0.55em auto 0.65em auto;
      text-align: center;
      font-size: 9.4pt;
      line-height: 1.35;
      page-break-inside: avoid;
    }
    img.paper-figure {
      max-width: 98%;
      height: auto;
    }
    #refs {
      font-size: 8.6pt;
    }
    .csl-entry {
      margin-bottom: 0.24em;
    }
"@

$htmlText = $htmlText -replace "</style>", "$printCss`r`n  </style>"
$physEq = '<div class="display-equation">min<sub>x''</sub> L<sub>CE</sub>(f<sub>&theta;</sub>(x''), y<sub>t</sub> = 0) + &lambda;<sub>phys</sub> R<sub>phys</sub>(x''), &nbsp; ||x'' - x||<sub>&infin;</sub> &le; &epsilon;.</div>'
$catEq = '<div class="display-equation">L<sub>CAT</sub> = L<sub>CE</sub>(f<sub>&theta;</sub>(x), y) + &lambda;<sub>adv</sub>L<sub>CE</sub>(f<sub>&theta;</sub>(x<sub>adv</sub>), y)<br/>+ &lambda;<sub>out</sub> KL(p<sub>&theta;</sub>(x) || p<sub>&theta;</sub>(x<sub>adv</sub>)) + &lambda;<sub>rep</sub> ||h<sub>&theta;</sub>(x) - h<sub>&theta;</sub>(x<sub>adv</sub>)||<sub>2</sub><sup>2</sup>.</div>'
$htmlText = [regex]::Replace(
    $htmlText,
    '(?s)<span\s+class="math display">min<sub><em>x</em>.*?</span>',
    $physEq,
    1
)
$htmlText = [regex]::Replace(
    $htmlText,
    '(?s)<span class="math display">\$\$\\begin\{aligned\}.*?\\end\{aligned\}\$\$</span>',
    $catEq,
    1
)
$htmlText = $htmlText -replace '<div id="refs"', '<h1 id="references">References</h1><div id="refs"'
$htmlText = $htmlText -replace '<embed src="fig_main_robustness\.pdf"[^>]*/>', '<img class="paper-figure" src="../../figures/fig_main_robustness.png" alt="Robustness comparison" />'
$htmlText = $htmlText -replace '<embed src="fig_physical_valid_asr\.pdf"[^>]*/>', '<img class="paper-figure" src="../../figures/fig_physical_valid_asr.png" alt="Physical valid ASR" />'
$htmlText = $htmlText -replace '<embed src="fig_epsilon_sensitivity\.pdf"[^>]*/>', '<img class="paper-figure" src="../../figures/fig_epsilon_sensitivity.png" alt="Epsilon sensitivity" />'

# Pandoc preserves some LaTeX \ref targets as literal ``[label]`` text when
# their labels live inside imported table fragments.  This manuscript has a
# fixed, verified table/figure order, so replace only the known unresolved
# anchors used by the preview; the formal LaTeX build remains authoritative.
$previewReferenceNumbers = @{
    "tab:positioning" = "1"
    "tab:literature_detection" = "7"
    "tab:robustness_summary" = "8"
    "tab:physical_feasibility" = "9"
    "tab:ablation" = "10"
    "fig:physical_valid_asr" = "2"
}
foreach ($label in $previewReferenceNumbers.Keys) {
    $escaped = [regex]::Escape($label)
    $pattern = '(?s)<a\s+href="#' + $escaped + '"[^>]*>\[' + $escaped + '\]</a>'
    $htmlText = [regex]::Replace($htmlText, $pattern, $previewReferenceNumbers[$label])
}

$aggregateTable = Convert-LatexTableToHtml `
    -Path (Join-Path $RepoRoot "outputs\tables\table_multiseed_summary.tex") `
    -CssClass "wide-table"
$pairedTable = Convert-LatexTableToHtml `
    -Path (Join-Path $RepoRoot "outputs\tables\table_paired_multiseed_comparison.tex") `
    -CssClass "wide-table"
$multiSeedBlock = "$aggregateTable`r`n$pairedTable"
$marker = '<h1 id="sec:main_results">Main Robustness Results</h1>'
if ($htmlText.Contains($marker)) {
    $htmlText = $htmlText.Replace($marker, "$marker`r`n$multiSeedBlock")
}
else {
    throw "Could not locate Main Robustness Results marker in generated HTML."
}

Set-Content -LiteralPath $HtmlPath -Value $htmlText -Encoding UTF8

$Chrome = Find-Chrome $ChromePath
$HtmlUri = (New-Object System.Uri((Resolve-Path -LiteralPath $HtmlPath).Path)).AbsoluteUri

Remove-Item -LiteralPath $PdfPath -Force -ErrorAction SilentlyContinue
$buildStart = Get-Date
$chromeOutput = & $Chrome `
    "--headless=new" `
    "--disable-gpu" `
    "--allow-file-access-from-files" `
    "--no-pdf-header-footer" `
    "--print-to-pdf=$PdfPath" `
    $HtmlUri 2>&1
if ($LASTEXITCODE -ne 0) {
    $chromeOutput | ForEach-Object { Write-Host $_ }
    throw "Chrome PDF generation failed with exit code $LASTEXITCODE"
}

$deadline = (Get-Date).AddSeconds(20)
while (-not (Test-Path -LiteralPath $PdfPath)) {
    if ((Get-Date) -gt $deadline) {
        throw "Chrome completed but did not create PDF: $PdfPath"
    }
    Start-Sleep -Milliseconds 250
}

$lastLength = -1
$stableReads = 0
while ($stableReads -lt 2) {
    if ((Get-Date) -gt $deadline) {
        throw "Chrome PDF output did not stabilize: $PdfPath"
    }
    $candidate = Get-Item -LiteralPath $PdfPath
    if ($candidate.LastWriteTime -lt $buildStart.AddSeconds(-1)) {
        throw "Chrome PDF output timestamp predates this build: $PdfPath"
    }
    if ($candidate.Length -lt 100000) {
        Start-Sleep -Milliseconds 250
        continue
    }
    if ($candidate.Length -eq $lastLength) {
        $stableReads += 1
    }
    else {
        $stableReads = 0
        $lastLength = $candidate.Length
    }
    Start-Sleep -Milliseconds 250
}

$pdfItem = Get-Item -LiteralPath $PdfPath
Write-Output "html=$HtmlPath"
Write-Output "pdf=$PdfPath"
Write-Output "pdf_bytes=$($pdfItem.Length)"
