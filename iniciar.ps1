$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectDir

# Confirme que esta pasta contém a edição financeira nova, e não arquivos da versão antiga do comparador.
$requiredFiles = @('server.js', 'package.json', 'src\db.js', 'migrations\001_initial.sql', 'public\index.html', 'INICIAR_OVBECK.bat')
foreach ($relativeFile in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $projectDir $relativeFile) -PathType Leaf)) {
        Write-Host "Falta o arquivo obrigatório: $relativeFile" -ForegroundColor Red
        Write-Host 'A extração pode estar incompleta. Baixe o ZIP mais recente da OVBECK e extraia para uma NOVA pasta.' -ForegroundColor Yellow
        exit 1
    }
}
$serverSource = Get-Content -LiteralPath (Join-Path $projectDir 'server.js') -Raw -ErrorAction Stop
if ($serverSource -notmatch "application:\s*'OVBECK'" -or $serverSource -notmatch "require\('./src/db'\)") {
    Write-Host 'Esta pasta contém uma versão antiga ou incorreta do OVBECK.' -ForegroundColor Red
    Write-Host 'O erro anterior mostrava data/store.json e dizia que os dados não eram multiusuário: isso identifica o servidor antigo.' -ForegroundColor Yellow
    Write-Host 'Não basta trocar o iniciar.ps1. Extraia o ZIP mais recente da OVBECK para uma NOVA pasta e execute o .bat que está dentro dela.' -ForegroundColor Yellow
    exit 1
}
$projectPackage = Get-Content -LiteralPath (Join-Path $projectDir 'package.json') -Raw | ConvertFrom-Json
if ($projectPackage.name -ne 'ovbeck-financas') {
    Write-Host 'O package.json não pertence à edição financeira esperada. Extraia o ZIP em uma pasta nova.' -ForegroundColor Red
    exit 1
}

$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    Write-Host 'Node.js 22.16.0 ou mais recente não foi encontrado.' -ForegroundColor Red
    Write-Host 'Instale em https://nodejs.org/ e abra este arquivo novamente.' -ForegroundColor Yellow
    exit 1
}
$nodeVersion = [version]((node --version).TrimStart('v').Split('-')[0])
if ($nodeVersion.Major -lt 22 -or ($nodeVersion.Major -eq 22 -and $nodeVersion.Minor -lt 16)) {
    Write-Host "Versão encontrada: $nodeVersion. Este projeto exige Node.js 22.16.0 ou mais recente." -ForegroundColor Red
    Write-Host 'Atualize pelo site https://nodejs.org/.' -ForegroundColor Yellow
    exit 1
}

# Sharp processa e valida fotos de perfil no servidor. Instala a dependência declarada
# apenas quando estiver ausente; não reinstala em cada inicialização.
$sharpPackage = Join-Path $projectDir 'node_modules\sharp\package.json'
if (-not (Test-Path -LiteralPath $sharpPackage -PathType Leaf)) {
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        Write-Host 'O npm não foi encontrado. Reinstale Node.js 22.16.0 ou mais recente com o npm incluído.' -ForegroundColor Red
        exit 1
    }
    Write-Host 'Preparando a dependência de processamento seguro de imagens (sharp)...' -ForegroundColor Cyan
    npm install --no-audit --no-fund
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $sharpPackage -PathType Leaf)) {
        Write-Host 'Não foi possível instalar a dependência sharp. Verifique a conexão com a internet e execute npm install nesta pasta.' -ForegroundColor Red
        exit 1
    }
}

function Test-OVBECKHealth([int]$CandidatePort) {
    try {
        $response = Invoke-RestMethod -Uri "http://127.0.0.1:$CandidatePort/api/health" -TimeoutSec 1
        return ($response.application -eq 'OVBECK' -and $response.ok -eq $true)
    } catch { return $false }
}
function Test-PortListening([int]$CandidatePort) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect('127.0.0.1', $CandidatePort, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(500)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch { return $false }
    finally { $client.Dispose() }
}

# Se a aplicação já estiver aberta na porta padrão, apenas abre o navegador.
if (Test-OVBECKHealth 4173) {
    Write-Host 'O OVBECK já está em execução na porta 4173.' -ForegroundColor Green
    Start-Process 'http://127.0.0.1:4173/'
    exit 0
}

# Não tenta iniciar sobre uma porta ocupada. Escolhe uma porta livre e verifica o health check antes de abrir o navegador.
$port = $null
for ($candidate = 4173; $candidate -le 4180; $candidate++) {
    if (-not (Test-PortListening $candidate)) { $port = $candidate; break }
}
if (-not $port) {
    Write-Host 'As portas locais 4173 a 4180 já estão ocupadas.' -ForegroundColor Red
    Write-Host 'Feche outra instância do OVBECK ou encerre o programa que utiliza essas portas.' -ForegroundColor Yellow
    exit 1
}

# Grave a saída real do Node para que a causa não fique escondida atrás da mensagem genérica do inicializador.
$logDir = Join-Path $projectDir 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$serverLog = Join-Path $logDir 'server-startup.log'
try { Remove-Item -LiteralPath $serverLog -Force -ErrorAction SilentlyContinue } catch { }

# Aspas explícitas em variáveis de ambiente evitam que espaços no caminho ou na linha de comando mudem os valores.
$command = "title OVBECK - servidor & cd /d `"$projectDir`" && echo Inicializando OVBECK... && set `"PORT=$port`" && set `"HOST=127.0.0.1`" && node server.js 1> `"$serverLog`" 2>&1"
$serverProcess = Start-Process -FilePath $env:ComSpec -ArgumentList @('/d', '/k', $command) -PassThru
$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    Start-Sleep -Milliseconds 400
    if (Test-OVBECKHealth $port) { $ready = $true; break }
    if ($serverProcess.HasExited) { break }
}
if (-not $ready) {
    Write-Host 'O servidor não confirmou que iniciou; o navegador não será aberto.' -ForegroundColor Red
    Write-Host "Porta verificada: $port. Versão do Node: $((node --version).Trim())." -ForegroundColor Yellow
    Write-Host 'Mensagem real de inicialização (se disponível):' -ForegroundColor Yellow
    if (Test-Path -LiteralPath $serverLog) {
        $logLines = @(Get-Content -LiteralPath $serverLog -Tail 35 -ErrorAction SilentlyContinue)
        if ($logLines.Count -gt 0) { $logLines | ForEach-Object { Write-Host $_ -ForegroundColor DarkYellow } }
        else { Write-Host 'O log foi criado, mas está vazio. Isso pode indicar que a falha ocorreu antes de o Node executar.' -ForegroundColor Yellow }
    } else {
        Write-Host 'O log ainda não foi criado. Verifique se a pasta extraída contém server.js e src\db.js.' -ForegroundColor Yellow
    }
    Write-Host "Log completo: $serverLog" -ForegroundColor Cyan
    Write-Host 'Se precisar de suporte, envie o conteúdo desse arquivo ou uma foto desta janela.' -ForegroundColor Cyan
    exit 1
}
$url = "http://127.0.0.1:$port/"
Write-Host "OVBECK está respondendo em $url" -ForegroundColor Green
if (Test-Path -LiteralPath $serverLog) {
    Get-Content -LiteralPath $serverLog -Tail 3 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
}
Write-Host 'Mantenha a janela “OVBECK - servidor” aberta. Para encerrar, volte nela e pressione Ctrl+C.' -ForegroundColor Cyan
Start-Process $url
try { Wait-Process -Id $serverProcess.Id } catch { }
