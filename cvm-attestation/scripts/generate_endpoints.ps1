# generate_endpoints.ps1
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Get endpoints for all regions
$endpoints = (Get-AzAttestationDefaultProvider).Value | Sort-Object Location | Select-Object -Property Location, AttestUri

# Generates JSON file with all the attestation endpoints by region
$endpointsJson = [ordered]@{}
foreach ($endpoint in $endpoints) {
  $endpointsJson[($endpoint.Location -replace ' ', '').ToLower()] = $endpoint.AttestUri
}
$endpointsJson | ConvertTo-Json > attestation_uri_table.json