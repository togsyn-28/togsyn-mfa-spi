<#
  Recreates the local Keycloak container with the MFA settings.
  Data survives (named volume keycloak_data). The SPI JAR is copied from the Gradle build folder
  into a host folder that is mounted into the container, so rebuilding = run this script again.

  Usage (PowerShell):
    .\kc-run.ps1                 # normal mode (stores passkeys)
    .\kc-run.ps1 -DryRun         # milestone 3: validate passkeys but do not store them
    .\kc-run.ps1 -ReauthSeconds 300   # require a password login within the last 5 minutes
    .\kc-run.ps1 -LoginOrigins "http://localhost:3000"   # let EduTecJob's origin sign in with a passkey
#>
param(
  [switch]$DryRun,
  [string]$SpiProject = "C:\Projects\Java Backend\spi\togsyn-mfa-spi",
  [string]$ProvidersDir = "C:\kc\providers",
  [string]$Image = "keycloak-mfa:backup",
  [string]$PlatformOrigins = "http://localhost:5173",
  [string]$LoginOrigins = "",
  [int]$ReauthSeconds = 0
)

New-Item -ItemType Directory -Force -Path $ProvidersDir | Out-Null

$jar = Get-ChildItem "$SpiProject\build\libs\*.jar" |
  Where-Object { $_.Name -notlike "*-plain.jar" } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $jar) { Write-Error "No JAR found in $SpiProject\build\libs. Build the SPI first."; exit 1 }

Get-ChildItem $ProvidersDir -Filter *.jar | Remove-Item -Force
Copy-Item $jar.FullName $ProvidersDir
Write-Host "Using $($jar.Name)"

docker rm -f keycloak | Out-Null

$dry = if ($DryRun) { "true" } else { "false" }
docker run -d --name keycloak -p 8084:8080 `
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin `
  -e MFA_ALLOWED_CLIENTS=web-app `
  -e "MFA_PLATFORM_ORIGINS=$PlatformOrigins" `
  -e "MFA_LOGIN_ORIGINS=$LoginOrigins" `
  -e "MFA_REAUTH_MAX_AGE_SECONDS=$ReauthSeconds" `
  -e "MFA_PASSKEY_DRY_RUN=$dry" `
  -v keycloak_data:/opt/keycloak/data `
  -v "${ProvidersDir}:/opt/keycloak/providers" `
  $Image start-dev

if ($LASTEXITCODE -ne 0) { Write-Error "docker run failed"; exit 1 }
Write-Host "Started. Dry run: $dry. Re-auth window: $ReauthSeconds s. Logs: docker logs keycloak --tail 40"
