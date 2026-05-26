param(
    [Parameter(Mandatory = $true)]
    [string]$ApimUrl,

    [Parameter(Mandatory = $true)]
    [string]$AadClientId,

    [string]$FrontendUrl,
    [string]$ApimSubscriptionKey,
    [ValidateSet("data-analyst", "web-researcher")]
    [string]$AgentType = "data-analyst",
    [string]$Task = "Write a short markdown summary of this environment and stop when complete.",
    [int]$PollAttempts = 24,
    [int]$PollIntervalSeconds = 5,
    [int]$SseTimeoutSeconds = 20,
    [switch]$AllowHealthOnlyFallback
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-AccessToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId
    )

    $attempts = @(
        @("--scope", "api://$ClientId/.default"),
        @("--scope", "api://$ClientId/access_as_user"),
        @("--resource", "api://$ClientId")
    )

    foreach ($attempt in $attempts) {
        try {
            $token = az account get-access-token $attempt[0] $attempt[1] --query accessToken -o tsv 2>$null
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($token)) {
                return $token.Trim()
            }
        } catch {
        }
    }

    throw "Failed to acquire an access token for api://$ClientId. If this is a delegated-user smoke test, run 'az login --scope api://$ClientId/.default' first."
}

function Test-FrontendReachability {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $response = Invoke-WebRequest -Uri $Uri -Method Head -MaximumRedirection 10 -SkipHttpErrorCheck
    $statusCode = [int]$response.StatusCode
    $finalHost = $null

    if ($response.BaseResponse -and $response.BaseResponse.RequestMessage -and $response.BaseResponse.RequestMessage.RequestUri) {
        $finalHost = $response.BaseResponse.RequestMessage.RequestUri.Host
    }

    if (@(200, 302) -contains $statusCode) {
        return [pscustomobject]@{
            StatusCode = $statusCode
            FinalHost = $finalHost
        }
    }

    throw "Frontend smoke test failed with HTTP $statusCode."
}

function Invoke-JsonRequest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [hashtable]$Headers,
        [object]$Body,
        [int[]]$ExpectedStatusCodes = @(200)
    )

    $requestParams = @{
        Method = $Method
        Uri = $Uri
        Headers = $Headers
        SkipHttpErrorCheck = $true
    }

    if ($null -ne $Body) {
        $requestParams["ContentType"] = "application/json"
        $requestParams["Body"] = ($Body | ConvertTo-Json -Depth 10 -Compress)
    }

    $response = Invoke-WebRequest @requestParams
    if ($ExpectedStatusCodes -notcontains [int]$response.StatusCode) {
        throw "Unexpected status code $($response.StatusCode) for $Method $Uri. Body: $($response.Content)"
    }

    $json = $null
    if (-not [string]::IsNullOrWhiteSpace($response.Content)) {
        $json = $response.Content | ConvertFrom-Json
    }

    return [pscustomobject]@{
        StatusCode = [int]$response.StatusCode
        Json = $json
        Content = $response.Content
    }
}

function Test-SseConnection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [int]$TimeoutSeconds = 20
    )

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $client = [System.Net.Http.HttpClient]::new($handler)
    try {
        $request = [System.Net.Http.HttpRequestMessage]::new(
            [System.Net.Http.HttpMethod]::Get,
            $Uri
        )
        foreach ($pair in $Headers.GetEnumerator()) {
            [void]$request.Headers.TryAddWithoutValidation($pair.Key, [string]$pair.Value)
        }

        $response = $client.SendAsync(
            $request,
            [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
        ).GetAwaiter().GetResult()

        if (-not $response.IsSuccessStatusCode) {
            throw "SSE endpoint returned HTTP $([int]$response.StatusCode)."
        }

        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $reader = [System.IO.StreamReader]::new($stream)
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

        while ((Get-Date) -lt $deadline) {
            $lineTask = $reader.ReadLineAsync()
            if (-not $lineTask.Wait(1000)) {
                continue
            }

            $line = $lineTask.Result
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            if ($line.StartsWith("data:")) {
                $payload = $line.Substring(5).Trim()
                if (-not [string]::IsNullOrWhiteSpace($payload)) {
                    return $payload | ConvertFrom-Json
                }
            }
        }

        throw "Timed out waiting for SSE data from $Uri."
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

$null = az account show 2> $null
if ($LASTEXITCODE -ne 0) {
    throw "Azure CLI is not authenticated. Run 'az login' first."
}

$baseUrl = $ApimUrl.TrimEnd("/")
$sandboxUrl = "$baseUrl/sandbox"

$apimHeaders = @{}
if (-not [string]::IsNullOrWhiteSpace($ApimSubscriptionKey)) {
    $apimHeaders["Ocp-Apim-Subscription-Key"] = $ApimSubscriptionKey
}

if ($FrontendUrl) {
    $frontendResponse = Test-FrontendReachability -Uri $FrontendUrl
    if ($frontendResponse.FinalHost -and $frontendResponse.FinalHost -like "*.login.microsoftonline.com") {
        Write-Host "Frontend reachable via Azure AD login challenge: HTTP $($frontendResponse.StatusCode)"
    } else {
        Write-Host "Frontend reachable: HTTP $($frontendResponse.StatusCode)"
    }
}

$unauthenticated = Invoke-WebRequest -Uri "$sandboxUrl/kill-switches" -Method GET -Headers $apimHeaders -MaximumRedirection 0 -SkipHttpErrorCheck
if ([int]$unauthenticated.StatusCode -ne 401) {
    throw "Expected unauthenticated APIM request to return 401, got $($unauthenticated.StatusCode)."
}
Write-Host "Unauthenticated APIM check returned 401 as expected"

$headers = @{}
foreach ($entry in $apimHeaders.GetEnumerator()) {
    $headers[$entry.Key] = $entry.Value
}

$accessToken = $null
try {
    $accessToken = Get-AccessToken -ClientId $AadClientId
} catch {
    if (-not $AllowHealthOnlyFallback) {
        throw
    }

    Write-Warning $_.Exception.Message
    Write-Host "Authenticated checks skipped; fallback mode validated frontend reachability and APIM edge authentication behavior only"
    Write-Host "Smoke test succeeded in fallback mode"
    return
}

$headers["Authorization"] = "Bearer $accessToken"

$killSwitches = Invoke-JsonRequest -Method GET -Uri "$sandboxUrl/kill-switches" -Headers $headers -ExpectedStatusCodes @(200)
if (-not $killSwitches.Json.flags -or $killSwitches.Json.flags.Count -lt 1) {
    throw "Authenticated kill-switch response did not contain any flags."
}
Write-Host "Authenticated APIM check succeeded"

$runStart = Invoke-JsonRequest -Method POST -Uri "$sandboxUrl/runs" -Headers $headers -Body @{
    agent_type = $AgentType
    task = $Task
} -ExpectedStatusCodes @(202)

$runId = [string]$runStart.Json.run_id
if ([string]::IsNullOrWhiteSpace($runId)) {
    throw "Run creation did not return a run_id."
}
Write-Host "Started run $runId"

$ssePayload = Test-SseConnection -Uri "$sandboxUrl/stream/runs/$runId" -Headers $headers -TimeoutSeconds $SseTimeoutSeconds
Write-Host "Received SSE payload type: $($ssePayload.type)"

$terminalStates = @("completed", "failed", "killed")
$runState = $null
for ($attempt = 1; $attempt -le $PollAttempts; $attempt++) {
    $runStatus = Invoke-JsonRequest -Method GET -Uri "$sandboxUrl/runs/$runId" -Headers $headers -ExpectedStatusCodes @(200)
    $runState = [string]$runStatus.Json.status
    Write-Host "Run status poll ${attempt}/${PollAttempts}: $runState"
    if ($terminalStates -contains $runState) {
        break
    }
    Start-Sleep -Seconds $PollIntervalSeconds
}

if ($runState -ne "completed") {
    throw "Run $runId did not complete successfully. Final state: $runState"
}

$timeline = Invoke-JsonRequest -Method GET -Uri "$sandboxUrl/runs/$runId/timeline" -Headers $headers -ExpectedStatusCodes @(200)
if (-not $timeline.Json.events -or $timeline.Json.events.Count -lt 1) {
    throw "Timeline for run $runId did not include any events."
}

$eventTypes = @($timeline.Json.events | ForEach-Object { $_.action_type })
Write-Host "Timeline source: $($timeline.Json.source)"
Write-Host "Timeline events observed: $($eventTypes -join ', ')"
Write-Host "Smoke test succeeded for run $runId"