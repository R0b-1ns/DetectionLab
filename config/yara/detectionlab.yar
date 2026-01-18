rule DetectionLab_BaseRule
{
  meta:
    author = "DetectionLab"
    description = "Base YARA rule placeholder for the lab"
    date = "2026-01-01"
  strings:
    $a = "DETECTIONLAB"
  condition:
    $a
}

rule PHP_WebShell_Generic
{
  strings:
    $a = "eval("
    $b = "base64_decode"
    $c = "shell_exec"
    $d = "passthru"
  condition:
    any of them
}
