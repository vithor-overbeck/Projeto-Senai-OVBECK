$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectDir

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host 'Node.js 22.16.0 ou mais recente não foi encontrado. Instale em https://nodejs.org/.' -ForegroundColor Red
    exit 1
}
$nodeVersion = [version]((node --version).TrimStart('v').Split('-')[0])
if ($nodeVersion.Major -lt 22 -or ($nodeVersion.Major -eq 22 -and $nodeVersion.Minor -lt 16)) {
    Write-Host "Versão encontrada: $nodeVersion. Requisito mínimo: Node.js 22.16.0." -ForegroundColor Red
    exit 1
}
Write-Host 'Verificando sintaxe e executando testes automatizados nativos...' -ForegroundColor Cyan
npm run verify
if ($LASTEXITCODE -ne 0) {
    Write-Host 'A verificação encontrou uma falha. Copie a saída acima para análise.' -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host 'Verificação concluída sem falhas.' -ForegroundColor Green
