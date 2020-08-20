$FileHash = Get-FileHash -Path openEDR.msi
echo $FileHash.Hash
(Get-Content -path install.ps1 -Raw) -match "OPENEDR_SHA256_HASH='(.*)'"
$matches[1]
((Get-Content -path install.ps1 -Raw) -replace $matches[1],$FileHash.Hash) | Set-Content -Path install.ps1