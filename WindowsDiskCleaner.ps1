#####################################################################################
# Basic flow: Read server(s) > (Find.Range)/Find.Domain > Select.Creds > Clear.Space
#####################################################################################



function Find.Domain($myServer){
    write-host "Determining domain..."
    $Domain=''
    Try{$Domain = [System.Net.Dns]::GetHostByName($myServer).HostName}
    Catch{write-host "...No such host is known (DNS lookup failed)"
        Try{$Domain = [System.Net.Dns]::GetHostByName($myServer+".domain.local").HostName}
        Catch{write-host "...Not in production" $Domain
            Try{$Domain = [System.Net.Dns]::GetHostByName($myServer+".redacted.domain.com").HostName}
            Catch{write-host "...Not in Domain1"
                Try{$Domain = [System.Net.Dns]::GetHostByName($myServer+".redacted2.domain.com").HostName}
                Catch{write-host "...Not in Domain2"
                    Try{$Domain = [System.Net.Dns]::GetHostByName($myServer+".redacted3.domain.com").HostName}
                    Catch{write-host "...Not in Domain3"
                        Try{$Domain = [System.Net.Dns]::GetHostByName($myServer+".stage.local").HostName}
                        Catch{write-host "...Not in Staging" $Domain; $Domain='' }  # *** Final catch should return empty string ***
                    
                    }
                }
            }
        }
    }
    
    if($Domain -eq ''){
        write-host "Domain not found"}
    Else {
        write-host "Domain:"$Domain;}

    #if GetHostByName only returns host name and not FQDN:
    if($Domain -ne '' -and $Domain.Contains('.') -In "False"){
        write-host "GetHostByName only returned a host name and not a FQDN..."
        $ServerIP=[System.Net.Dns]::GetHostAddresses($myServer).IPAddressToString
        $Domain = [System.Net.Dns]::GetHostByAddress($ServerIP).HostName
    }
    


    return $Domain
}






#Find range of nodes (Example: server03:server07)
function Find.Range($test){
    
    #Create/Santize variables
    $Servers = $test.Split(':')
    Write-host "--MULTIPLE SERVERS--"
    $FQDN =''
    $FStr =''
    $LStr =''
    $FirstNode=($Servers[0])
    $LastNode=($Servers[1])
    $FQDN = Find.Domain($FirstNode)


    #Find tail indexes with integers
	#Start from tail to avoid mid-name numbers that may occur in server name.
    $isNum=$true
    $countIndex = 0
    while($isNum -eq $true){
        
        if($FirstNode[$countIndex-1] -match “[0-9]”)
        {
            $FStr=$FirstNode[$countIndex-1]+$FStr
            $LStr=$LastNode[$countIndex-1]+$LStr
            $countIndex    = $countIndex-1
        }
        ElseIf($FirstNode[$countIndex-1] -notmatch “[0-9]”){
            $isNum=$False #Break While Loop
        }
    }


    #Convert to int and create list
    [int]$IntFStr = [convert]::ToInt32($FStr,10)
    [int]$IntLStr = [convert]::ToInt32($LStr,10)
    $myArray  = ($IntFStr..$IntLStr)

    #base name (without node number)
    $BaseName = $FirstNode.Substring(0,($FirstNode.Length+($countIndex))) 

    #Build list of server names
    $NodeArray= @()
    $myArray | % {$i=0} {
        if($_ -lt [int]10){
            $NodeArray += ($BaseName+'0'+($_)) }
        ElseIf($_ -ge 10){
            $NodeArray += ($BaseName+($_))}; 
        $i++
    }


    #Add domain and clear space on servers one at a time
    $a, $b = $FQDN.split('.',2)

    $NodeArray | % {$i=0} {Select.Creds(($_+'.'+$b)); $i++}
}








#Select appropriate domain/credentials
function Select.Creds($CredServer) {

    if($CredServer -ne $null){  
        
        # Domain1 / Domain2 / Domain3 / Domain4.com
        If($CredServer.Contains("Domain1") -eq $true -Or $CredServer.Contains("Domain2") -eq $true -Or $CredServer.Contains("Domain3") -eq $true -Or $CredServer.Contains("Domain4.com") -eq $true){
            Clear-Space $CredServer $User
        }

        # Production Environment 
        ElseIf($CredServer.Contains("domain.local") -eq $true){
            Clear-Space $CredServer $ProductionUser
        }

        # Staging Environment
        ElseIf($CredServer.Contains("staging") -eq $true){
            Write-host "Enter your Staging credentials..." -ForegroundColor Yellow
            if($StagingUser -eq ''){
                if($env:USERNAME[1] -eq '-'){
                $StagingUser = Get-Credential "staging\$env:USERNAME"}
                ElseIf($env:USERNAME[1] -ne '-'){
                $StagingUser = Get-Credential "staging\s-$env:USERNAME"}
            }
            Clear-Space $CredServer $StagingUser
        }

    }
    Else{write "FQDN not found (null)"}

}







function Clear-Space ($myDomain, $myCreds){

    write-host "Drive C: on $myDomain" -ForegroundColor Yellow

    
    #Print Free Space Before
    $Freespace = @{
        Expression = {[int]($_.Freespace/1GB)}
        Name = 'Free Space (GB)'
    }
    $PercentFree = @{
        Expression = {[int]($_.Freespace*100/$_.Capacity)}
        Name = 'Free (%)'
    }

    try{
        invoke-command -computername $myDomain -Credential $myCreds {

            #Print available space before
            write-host -NoNewLine "`nGB free before:  " -ForegroundColor Cyan; Get-WmiObject -Class win32_logicaldisk -filter "DeviceID='C:'" | ForEach-Object {[int]($_.Freespace/1GB)} | Write-Host ;
            write-host -NoNewLine "Pct free before: " -ForegroundColor Cyan; Get-WmiObject -Class win32_logicaldisk -filter "DeviceID='C:'" | ForEach-Object {[int]($_.Freespace*100/$_.Size)} ;
    
            write-host "`nClearing space..." -ForegroundColor Yellow

            #Directories/Logs to be cleared:
            remove-item 'env:\TEMP\*' -recurse -force;
            remove-item 'C:\Documents and Settings\*\Local Settings\Temp\*' -recurse -force;
            remove-item 'C:\$Recycle.Bin\*' -recurse -force;
            remove-item 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive\*' -recurse -force;
            remove-item 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue\*' -recurse -force;
    
            remove-item 'C:\AnthillAgent\var\log\*\*.log' -recurse -force;
            remove-item 'C:\AnthillAgent-0\var\log\*\*.log' -recurse -force;
            remove-item 'C:\PuppetTemp\*' -recurse -force;

            remove-item 'C:\Windows\Temp\*' -recurse -force;
            remove-item 'C:\Windows\SoftwareDistribution\Download\*' -recurse -force;
            remove-item 'C:\Windows\SoftwareDistribution\DataStore\Logs\*.log'
            remove-item 'C:\Windows\System32\LogFiles\*\W3SVC*\*\*.log' -recurse -force;
    
            remove-item 'C:\inetpub\logs\LogFiles\*\*.log' -Recurse -force;
            remove-item 'C:\inetpub\logs\LogFiles\*\*\*.log' -Recurse -force;

            remove-item 'C:\Windows\System32\LogFiles\*\*.log' -recurse -force;
            remove-item 'C:\Windows\System32\LogFiles\*\*\*.log' -recurse -force;


            remove-item 'C:\inetpub\wwwroot\REDACTED\httpdocs\wp-content\*\*.log' -recurse -force;
            remove-item 'C:\inetpub\wwwroot\REDACTED\Public\*\Logs\archive\*.log'
            remove-item 'C:\inetpub\wwwroot\REDACTED\PublicV2\*\Logs\archive\*.log'
            remove-item 'C:\inetpub\wwwroot\REDACTED\Public\*\Logs\archive\*.log'
            remove-item 'C:\inetpub\wwwroot\REDACTED\Authentication\*\Logs\archive\*.log' -recurse -force;
            remove-item 'C:\inetpub\wwwroot\REDACTED\UsageReport\*\Logs\archive\*.log'
    
            remove-item 'C:\Program Files\SplunkUniversalForwarder\var\log\introspection\*.log.*'
            remove-item 'C:\Program Files\SplunkUniversalForwarder\var\log\splunk\*.log*' -recurse -force;

            remove-item 'C:\Windows\System32\LogFiles\REDACTED\W3SVC1000\*.log'
            remove-item 'C:\Windows\System32\LogFiles\REDACTED\W3SVC1\*.log'
           
            remove-item 'C:\Windows\SoftwareDistribution\DataStore\Logs\*.log'
    


            #Print available space after
            write-host -NoNewLine "`nGB free after:  " -ForegroundColor Cyan; Get-WmiObject -Class win32_logicaldisk -filter "DeviceID='C:'" | ForEach-Object {[int]($_.Freespace/1GB)} | Write-Host;
            write-host -NoNewLine "Pct free after: "   -ForegroundColor Cyan; Get-WmiObject -Class win32_logicaldisk -filter "DeviceID='C:'" | ForEach-Object {[int]($_.Freespace*100/$_.Size)};
            write-host "`n---------------------------------" -ForegroundColor Green
        } -ErrorAction SilentlyContinue 
    }
    catch{$skipped += $myDomain}

    


}





# Do Once (prompt for creds & print banner)
write-host "`n`nEnter Credentials..." -ForegroundColor Yellow

#Prompt Standard and Production Creds
if($env:USERNAME[1] -eq '-'){
    $User = Get-Credential "domain\$env:USERNAME"
    $S_to_P = $env:USERNAME.Replace("s-","p-")
    $ProductionUser = Get-Credential "production\$S_to_P"
}

ElseIf($env:USERNAME[1] -ne '-'){
    $User = Get-Credential "domain\s-$env:USERNAME"
    $S_to_P = $env:USERNAME.Replace("s-","p-")
    $ProductionUser = Get-Credential "production\p-$S_to_P"
}

# User will be prompted for stage only if server is found to be on Stage.
$StagingUser = ''  

write-host "Accepts Range of Servers (separate with ':')" -ForegroundColor Yellow
write-host "Example- server03:server07" -ForegroundColor Red


############################################################
#
# MAIN Loop: Read server(s) 
# Flow: Find.Range/Find.Domain > Select.Creds > Clear.Space
#
############################################################

$myLoop=0
$ServerInput = ""
$FQDN = ''
While($myLoop -eq 0){

    write-host "`n`n#################################################" -ForegroundColor Green
    $Server = Read-Host -Prompt 'Server'

    #Process multiple servers
    If($Server.Contains(":") -eq $true)
    {
       Find.Range($Server.trim())

    }
    

    #Process single server
    If($Server.Contains(":") -eq $false){
        #Determine Domain by FQDN 
        $FQDN = ''
        $FQDN = Find.Domain $Server.trim()
        #write-host "FQDN: $FQDN"
        Select.Creds($FQDN)
    }


}