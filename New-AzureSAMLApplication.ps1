[CmdletBinding()]
param(
[parameter(Mandatory=$true)]
[String]$Name,
[String]$TenantId,
[String]$Identifier,
[String]$ReplayURL,
[String]$email
)




$rmAccount = Add-AzureRmAccount


$curAzureContext = Get-AzureRmContext

$tenanId = $curAzureContext.Tenant.Id

$accountId = $curAzureContext.Account.Id

Connect-AzureAD -TenantId $tenanId -AccountId $accountId




$TokenEndpoint = {https://login.windows.net/{0}/oauth2/token} -f $TenantId
$ARMResource = "74658136-14ec-4630-ad9b-26e160ff0fc6";

$acc = $rmAccount.Context.TokenCache.ReadItems() | Where { $_.DisplayableId -eq $accountId }


$Body = @{
        'resource'= $ARMResource
        'grant_type' = 'refresh_token'
        'refresh_token' = $acc[2].RefreshToken

}

$params = @{
    ContentType = 'application/x-www-form-urlencoded'
    Headers = @{'accept'='application/json'}
    Body = $Body
    Method = 'Post'
    URI = $TokenEndpoint
}

$token = Invoke-RestMethod @params


$body = '{"accountEnabled":null,"isAppVisible":null,"appListQuery":0,"top":50,"loadLogo":false,"putCachedLogoUrlOnly":true,"nextLink":"","usedFirstPartyAppIds":null,"__ko_mapping__":{"ignore":[],"include":["_destroy"],"copy":[],"observe":[],"mappedProperties":{"accountEnabled":true,"isAppVisible":true,"appListQuery":true,"searchText":true,"top":true,"loadLogo":true,"putCachedLogoUrlOnly":true,"nextLink":true,"usedFirstPartyAppIds":true},"copiedProperties":{}}}'


$appList = Invoke-RestMethod -Method Post `
                  -Uri ("https://main.iam.ad.ext.azure.com/api/ManagedApplications/List") `
                  -Body $body `
                  -Headers @{ "Authorization" = "Bearer " + $token.access_token
                   "x-ms-client-session-id" = "e323ec86d85e40789462d1edd55a9f30"
                   "x-ms-effective-locale" = "en.de-de"
                   "Content-Type" = "application/json"
                   #"Accept" = "*/*"
                   "x-ms-client-request-id" = "b9cc97b8-2893-4592-86e7-02412716505f"
                   #"User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"
                   #"Origin" = "https://portal.azure.com"
                   
                   #"Sec-Fetch-Site" = "same-site"
                   #"Accept-Encoding" = "gzip, deflate, br"
 }

$body2 = '{"displayName":"'+$Name+'"}'

 $app = Invoke-RestMethod -Method Post `
                  -Uri ("https://main.iam.ad.ext.azure.com/api/GalleryApplications/customApplications?skipSamlCertCreation=true") `
                  -Body $body2 `
                  -Headers @{ "Authorization" = "Bearer " + $token.access_token
                   "x-ms-client-session-id" = "e323ec86d85e40789462d1edd55a9f30"
                   "x-ms-effective-locale" = "en.de-de"
                   "Content-Type" = "application/json"
                   #"Accept" = "*/*"
                   "x-ms-client-request-id" = "b9cc97b8-2893-4592-86e7-02412716505f"
                   #"User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"
                   #"Origin" = "https://portal.azure.com"
                   
                   #"Sec-Fetch-Site" = "same-site"
                   #"Accept-Encoding" = "gzip, deflate, br"
 }



 $objectId = $app.objectId.ToString()
 $appId = $app.appId.ToString()
 #########################################################################################################################

 $body = '{"certificates":[{"expirationDateTime":"2022-12-12T09:25:14.849Z","state":3,"thumbprint":"Will be displayed on save","thumbprintSha256":"Will be displayed on save","publicCertificateBase64":"","isGlobalCert":false}]}'
 
   Invoke-RestMethod -Method POST `
                  -Uri ("https://main.iam.ad.ext.azure.com/api/ApplicationSso/$objectId/SamlCertificatesV2") `
                  -Body $body `
                  -Headers @{ "Authorization" = "Bearer " + $token.access_token
                   "x-ms-client-session-id" = "e323ec86d85e40789462d1edd55a9f30"
                   "x-ms-effective-locale" = "en.de-de"
                   "Content-Type" = "application/json"
                   #"Accept" = "*/*"
                   "x-ms-client-request-id" = "b9cc97b8-2893-4592-86e7-02412716505f"
                   #"User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"
                   #"Origin" = "https://portal.azure.com"
                   
                   #"Sec-Fetch-Site" = "same-site"
                   #"Accept-Encoding" = "gzip, deflate, br"
 }  
 
 
  
 
 
 ##################################################################################################################################################  

 $body = '{"appId":"'+$appId+'","uriToValidate":"'+$Identifier+'"}'

    Invoke-RestMethod -Method POST `
                  -Uri ("https://main.iam.ad.ext.azure.com/api/ApplicationSso/IsValidIdentifierUri") `
                  -Body $body `
                  -Headers @{ "Authorization" = "Bearer " + $token.access_token
                   "x-ms-client-session-id" = "e323ec86d85e40789462d1edd55a9f30"
                   "x-ms-effective-locale" = "en.de-de"
                   "Content-Type" = "application/json"
                   #"Accept" = "*/*"
                   "x-ms-client-request-id" = "b9cc97b8-2893-4592-86e7-02412716505f"
                   #"User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"
                   #"Origin" = "https://portal.azure.com"
                   
                   #"Sec-Fetch-Site" = "same-site"
                   #"Accept-Encoding" = "gzip, deflate, br"
 }    

 $body = '{"objectId":"'+$ojectId+'","identifierUris":["'+$Identifier+'"],"certificateNotificationEmail":"'+$email+'","signOnUrl":"","logoutUrl":"","replyUrls":["'+$ReplayURL+'"],"relayState":"","idpIdentifier":"'+$Identifier+'","idpReplyUrl":"'+$ReplayURL+'","defaultClaimIssuancePolicy":{"version":1,"defaultTokenType":"SAML","allowPassThruUsers":"true","includeBasicClaimSet":"true","claimsSchema":[{"samlClaimType":"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier","samlNameIdFormat":"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress","source":"User","extensionID":null,"id":"userprincipalname","value":null,"transformationId":null,"appliesToUserType":null,"memberOf":null},{"samlClaimType":"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname","source":"User","extensionID":null,"id":"givenname","value":null,"transformationId":null,"appliesToUserType":null,"memberOf":null},{"samlClaimType":"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname","source":"User","extensionID":null,"id":"surname","value":null,"transformationId":null,"appliesToUserType":null,"memberOf":null},{"samlClaimType":"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress","source":"User","extensionID":null,"id":"mail","value":null,"transformationId":null,"appliesToUserType":null,"memberOf":null},{"samlClaimType":"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name","source":"User","extensionID":null,"id":"userprincipalname","value":null,"transformationId":null,"appliesToUserType":null,"memberOf":null}],"claimsTransformations":[]},"externalClaimIssuancePolicy":null,"claimNameIdentifier":"userprincipalname","claimExtensionNameIdentifier":null,"claimMethodNameIdentifier":"mail","claimMethodDomainName":null,"tokenIssuancePolicy":{"version":1,"signingAlgorithm":"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256","tokenResponseSigningPolicy":"TokenOnly","samlTokenVersion":"2.0"},"tokenIssuancePolicySource":"default"}'

 

   Invoke-RestMethod -Method POST `
                  -Uri ("https://main.iam.ad.ext.azure.com/api/ApplicationSso/$objectId/FederatedSsoConfigV2") `
                  -Body $body `
                  -Headers @{ "Authorization" = "Bearer " + $token.access_token
                   "x-ms-client-session-id" = "e323ec86d85e40789462d1edd55a9f30"
                   "x-ms-effective-locale" = "en.de-de"
                   "Content-Type" = "application/json"
                   #"Accept" = "*/*"
                   "x-ms-client-request-id" = "b9cc97b8-2893-4592-86e7-02412716505f"
                   #"User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"
                   #"Origin" = "https://portal.azure.com"
                   
                   #"Sec-Fetch-Site" = "same-site"
                   #"Accept-Encoding" = "gzip, deflate, br"
 }

 $body = '{"currentSingleSignOnMode":"federated","signInUrl":null}'

 

   Invoke-RestMethod -Method POST `
                  -Uri ("https://main.iam.ad.ext.azure.com/api/ApplicationSso/$objectId/SingleSignOn") `
                  -Body $body `
                  -Headers @{ "Authorization" = "Bearer " + $token.access_token
                   "x-ms-client-session-id" = "e323ec86d85e40789462d1edd55a9f30"
                   "x-ms-effective-locale" = "en.de-de"
                   "Content-Type" = "application/json"
                   #"Accept" = "*/*"
                   "x-ms-client-request-id" = "b9cc97b8-2893-4592-86e7-02412716505f"
                   #"User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"
                   #"Origin" = "https://portal.azure.com"
                   
                   #"Sec-Fetch-Site" = "same-site"
                   #"Accept-Encoding" = "gzip, deflate, br"
 }

 $body = '{"appId":"'+$appId+'","objectId":"'+$objectId+'","emailAddresses":["'+$email+'"],"certificateExpiryDateInUTC":"2022-08-12T09:30:51.000Z","imageUri":null,"displayName":null}'



   Invoke-RestMethod -Method POST `
                  -Uri ("https://main.iam.ad.ext.azure.com/api/ApplicationSso/CreateSamlAppV2") `
                  -Body $body `
                  -Headers @{ "Authorization" = "Bearer " + $token.access_token
                   "x-ms-client-session-id" = "e323ec86d85e40789462d1edd55a9f30"
                   "x-ms-effective-locale" = "en.de-de"
                   "Content-Type" = "application/json"
                   #"Accept" = "*/*"
                   "x-ms-client-request-id" = "b9cc97b8-2893-4592-86e7-02412716505f"
                   #"User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"
                   #"Origin" = "https://portal.azure.com"
                   
                   #"Sec-Fetch-Site" = "same-site"
                   #"Accept-Encoding" = "gzip, deflate, br"
 }


 ########################################################################################
