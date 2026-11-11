$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$resetScript = Join-Path $projectRoot 'scripts\reset-admin-password.js'
$databasePath = $null
$plainPassword = $null
$confirmPassword = $null
$securePassword = $null
$secureConfirmation = $null
$exitCode = 1

function Convert-SecureStringToPlainText([System.Security.SecureString]$Value) {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

try {
    Set-Location -LiteralPath $projectRoot

    foreach ($required in @('package.json', 'src\db.js', 'migrations', 'scripts\reset-admin-password.js')) {
        if (-not (Test-Path -LiteralPath (Join-Path $projectRoot $required))) {
            throw "Não encontrei '$required'. Extraia os arquivos deste pacote diretamente na pasta principal do OVBECK."
        }
    }

    if ($env:DATABASE_PATH) {
        if ([IO.Path]::IsPathRooted($env:DATABASE_PATH)) {
            $databasePath = $env:DATABASE_PATH
        } else {
            $databasePath = Join-Path $projectRoot $env:DATABASE_PATH
        }
    } elseif ($env:COMPARATUDO_DATA_DIR) {
        $dataDirectory = if ([IO.Path]::IsPathRooted($env:COMPARATUDO_DATA_DIR)) {
            $env:COMPARATUDO_DATA_DIR
        } else {
            Join-Path $projectRoot $env:COMPARATUDO_DATA_DIR
        }
        $databasePath = Join-Path $dataDirectory 'finance.sqlite'
    } else {
        $databasePath = Join-Path $projectRoot 'data\finance.sqlite'
    }

    if (-not (Test-Path -LiteralPath $databasePath -PathType Leaf)) {
        throw "Não encontrei o banco de dados esperado: $databasePath`nPor segurança, parei sem criar um banco novo. Confira se está na pasta correta do OVBECK ou se usa DATABASE_PATH personalizado."
    }

    $nodeCommand = Get-Command 'node.exe' -ErrorAction SilentlyContinue
    if (-not $nodeCommand) { $nodeCommand = Get-Command 'node' -ErrorAction SilentlyContinue }
    if (-not $nodeCommand) { throw 'Node.js não foi encontrado. Instale o Node.js 22.16.0 ou mais recente.' }

    $nodeVersionText = (& $nodeCommand.Source --version | Out-String).Trim()
    if ($nodeVersionText -notmatch '^v(\d+)\.(\d+)\.(\d+)') {
        throw 'Não consegui identificar a versão do Node.js.'
    }
    $nodeMajor = [int]$Matches[1]
    $nodeMinor = [int]$Matches[2]
    if (($nodeMajor -lt 22) -or (($nodeMajor -eq 22) -and ($nodeMinor -lt 16))) {
        throw "Node.js $nodeVersionText encontrado. Este projeto exige Node.js 22.16.0 ou mais recente."
    }

    Write-Host ''
    Write-Host 'RECUPERAÇÃO DO ADMINISTRADOR — OVBECK' -ForegroundColor Green
    Write-Host "Banco que será usado: $databasePath"
    Write-Host 'O servidor OVBECK precisa estar encerrado (Ctrl+C).'
    Write-Host 'A redefinição não apaga clientes, despesas ou histórico.'
    Write-Host ''

    $emailInput = Read-Host 'E-mail do administrador'
    $adminEmail = $emailInput.Trim()
    if ($adminEmail -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]+$') { throw 'O formato do e-mail informado não é válido.' }

    $securePassword = Read-Host 'Digite a NOVA senha (12+ caracteres, maiúscula, minúscula, número e símbolo)' -AsSecureString
    $plainPassword = Convert-SecureStringToPlainText $securePassword
    if ($plainPassword.Length -lt 12 -or $plainPassword.Length -gt 128 -or
        $plainPassword -cnotmatch '[a-z]' -or $plainPassword -cnotmatch '[A-Z]' -or
        $plainPassword -notmatch '\d' -or $plainPassword -notmatch '[^A-Za-z0-9]') {
        throw 'A senha precisa ter de 12 a 128 caracteres e conter letra minúscula, maiúscula, número e símbolo.'
    }

    $secureConfirmation = Read-Host 'Digite a mesma senha novamente para confirmar' -AsSecureString
    $confirmPassword = Convert-SecureStringToPlainText $secureConfirmation
    if ($plainPassword -cne $confirmPassword) { throw 'As senhas não coincidem. Nenhuma alteração foi feita.' }

    $env:ADMIN_EMAIL = $adminEmail
    $env:ADMIN_RESET_PASSWORD = $plainPassword

    Write-Host ''
    Write-Host 'Executando a recuperação no banco existente...' -ForegroundColor Cyan
    & $nodeCommand.Source $resetScript
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw 'O programa de recuperação informou uma falha. Leia a mensagem acima.' }

    Write-Host ''
    Write-Host 'Recuperação concluída. No próximo login será obrigatório trocar a senha.' -ForegroundColor Green
}
catch {
    Write-Host ''
    Write-Host "ERRO: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
finally {
    Remove-Item Env:ADMIN_RESET_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:ADMIN_EMAIL -ErrorAction SilentlyContinue
    $plainPassword = $null
    $confirmPassword = $null
    if ($securePassword) { $securePassword.Dispose() }
    if ($secureConfirmation) { $secureConfirmation.Dispose() }
}

Write-Host ''
if ($exitCode -eq 0) {
    Write-Host 'Agora inicie o OVBECK com npm.cmd start.' -ForegroundColor Green
} else {
    Write-Host 'Nenhuma confirmação de sucesso foi registrada. Confira o erro acima.' -ForegroundColor Yellow
}
exit $exitCode
