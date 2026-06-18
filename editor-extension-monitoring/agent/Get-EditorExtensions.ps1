# Get-EditorExtensions.ps1
# Enumerates installed VS Code (family) and Visual Studio extensions across ALL user
# profiles and writes ONE compact JSON object per extension to stdout.
# Run by the Wazuh agent (SYSTEM) via a <log_format>command</log_format> localfile in the
# 'dev' group agent.conf. Output is parsed by the editor-extensions decoder (JSON_Decoder).
#
# Fields: integration, editor, user, extension_id, extension_name, publisher, version,
#         display_name, path, host
#
# Notes / scope:
#  - Per-user only (C:\Users\*). Machine-wide Visual Studio extensions (Common7\IDE\Extensions)
#    are intentionally excluded (mostly Microsoft built-ins). Add later via vswhere if needed.
#  - WSL/devcontainer extensions inside distros are not visible to the host SYSTEM account.

$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$hostName = $env:COMPUTERNAME
$skip = @('Default','Default User','Public','All Users','defaultuser0')

function Emit($o) { $o | ConvertTo-Json -Compress -Depth 5 }

function Get-UserDirs {
    Get-ChildItem 'C:\Users' -Directory -Force |
        Where-Object { $skip -notcontains $_.Name -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }
}

# ---------- VS Code family ----------
$vscodeRoots = @(
    @{ editor = 'vscode';          sub = '.vscode\extensions' },
    @{ editor = 'vscode-insiders'; sub = '.vscode-insiders\extensions' },
    @{ editor = 'vscode-server';   sub = '.vscode-server\extensions' }
)

foreach ($u in Get-UserDirs) {
    foreach ($r in $vscodeRoots) {
        $extDir = Join-Path $u.FullName $r.sub
        if (-not (Test-Path $extDir)) { continue }
        Get-ChildItem $extDir -Directory -Force | ForEach-Object {
            $folder = $_
            $name = $null; $publisher = $null; $version = $null; $display = $null
            $pkg = Join-Path $folder.FullName 'package.json'
            if (Test-Path $pkg) {
                try {
                    $j = Get-Content $pkg -Raw -Encoding UTF8 | ConvertFrom-Json
                    $name = $j.name; $publisher = $j.publisher; $version = $j.version; $display = $j.displayName
                } catch {}
            }
            # fallback: parse the folder name "publisher.name-version"
            if (-not $publisher -or -not $name) {
                if ($folder.Name -match '^(.+?)\.(.+)-(\d+\.\d+\.\d+.*)$') {
                    $publisher = $matches[1]; $name = $matches[2]
                    if (-not $version) { $version = $matches[3] }
                }
            }
            $extid = if ($publisher -and $name) { ("$publisher.$name").ToLower() } else { $folder.Name.ToLower() }
            Emit ([ordered]@{
                integration    = 'editor-extensions'
                editor         = $r.editor
                user           = $u.Name
                extension_id   = $extid
                extension_name = $name
                publisher      = $publisher
                version        = $version
                display_name   = $display
                path           = $folder.FullName
                host           = $hostName
            })
        }
    }
}

# ---------- Visual Studio (per-user VSIX) ----------
foreach ($u in Get-UserDirs) {
    $vsRoot = Join-Path $u.FullName 'AppData\Local\Microsoft\VisualStudio'
    if (-not (Test-Path $vsRoot)) { continue }
    Get-ChildItem $vsRoot -Directory -Force | ForEach-Object {        # version dirs e.g. 17.0_<hash>
        $extRoot = Join-Path $_.FullName 'Extensions'
        if (-not (Test-Path $extRoot)) { return }
        Get-ChildItem $extRoot -Recurse -Filter 'extension.vsixmanifest' -File -Force | ForEach-Object {
            $man = $_
            try {
                [xml]$x = Get-Content $man.FullName -Raw
                $idn = $x.PackageManifest.Metadata.Identity
                $dn  = $x.PackageManifest.Metadata.DisplayName
                if ($idn) {
                    Emit ([ordered]@{
                        integration    = 'editor-extensions'
                        editor         = 'visualstudio'
                        user           = $u.Name
                        extension_id   = $idn.Id
                        extension_name = $dn
                        publisher      = $idn.Publisher
                        version        = $idn.Version
                        display_name   = $dn
                        path           = $man.DirectoryName
                        host           = $hostName
                    })
                }
            } catch {}
        }
    }
}
