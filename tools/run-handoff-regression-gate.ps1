param(
    [string]$JavaHome = $env:JAVA_HOME,
    [string]$Python = '',
    [switch]$Targeted
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$outDirectory = Join-Path $projectRoot 'build\handoff-regression'
New-Item -ItemType Directory -Force -Path $outDirectory | Out-Null
$logPath = Join-Path $outDirectory 'gate.log'
$resultPath = Join-Path $outDirectory 'result.json'
$started = [DateTimeOffset]::Now.ToString('o')
@{ state = 'running'; started = $started } | ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
try {
    if (!$JavaHome) { throw 'Specify -JavaHome or set JAVA_HOME to a JDK 17+.' }
    $env:JAVA_HOME = $JavaHome
    if (!$Python) { $Python = Join-Path $projectRoot 'build\handoff-test-runtime\python\python.exe' }
    if (!(Test-Path -LiteralPath $Python)) { throw 'Specify -Python with a working Python 3 interpreter.' }
    # unittest writes its normal progress to stderr, including on success (Windows PowerShell 5).
    $ErrorActionPreference = 'Continue'
    & $Python tools/test-handoff-regressions.py *> $logPath
    $pythonExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($pythonExit -ne 0) { throw "Worker regressions failed (exit $pythonExit)." }
    $tasks = @(':core:ssh:test', ':app:testDebugUnitTest', ':app:assembleDebug', ':app:assembleDebugAndroidTest')
    if (!$Targeted) {
        $tasks += @(':core:data:testDebugUnitTest', ':core:domain:test', ':core:model:test',
            ':core:runtime-android:testDebugUnitTest', ':core:runtime:test', ':core:scanner-android:testDebugUnitTest',
            ':core:scanner:test', ':core:secrets:testDebugUnitTest', ':core:site:test', ':core:webpanel:test')
    }
    $ErrorActionPreference = 'Continue'
    & .\gradlew.bat --offline --console=plain --continue @tasks *>> $logPath
    $gradleExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    @{ state = $(if ($gradleExit -eq 0) { 'passed' } else { 'failed' }); started = $started;
       completed = [DateTimeOffset]::Now.ToString('o'); gradleExitCode = $gradleExit } |
        ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit $gradleExit
} catch {
    $_ | Out-String | Add-Content -LiteralPath $logPath
    @{ state = 'failed'; started = $started; error = $_.Exception.Message;
       completed = [DateTimeOffset]::Now.ToString('o') } | ConvertTo-Json |
        Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}
