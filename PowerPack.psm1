function Invoke-SessionHunter {
    <#
        .Synopsis
        .Description
        .Parameter HostList
        .Notes
        .Example
        
    #>

    [CmdletBinding(DefaultParameterSetName = "default")]
    param (
        [ValidateSet(0, 1, 2, 10, 502)]
        [int]$Level = 10,

        [Parameter(ParameterSetName = "method", HelpMessage = "List of hostnames or IPs via comma delimited list to enuemarate sessions on")]
        [string[]]$HostList,

        [Parameter(ParameterSetName = "method", HelpMessage = "Gather a list of all the machines registered in active directory to enumerate sessions on")]
        [switch]$ADComputerList,

        [Parameter(ParameterSetName = "method", HelpMessage = "Gather a list of all the machines based on a given list of subnets to enumerate sessions on")]
        [string[]]$SubnetList, 

        [Parameter(HelpMessage = "Show the progress bar during the enumeration process")]
        [switch]$ShowProgress,

        [Parameter(HelpMessage = "Maximum amount of threads to use during the enumeration process")]
        [int]$Threads = 50, 

        [Parameter(HelpMessage = "The amount of time in milliseconds to wait during each phase of the enumeration process")]
        [int]$Wait = 0, 

        [Parameter(HelpMessage = "Use a different set of credentials to run enumeration process with (useful when using level 502)")]
        [System.Management.Automation.PSCredential]$Credentials
 
    )

    

    # Scriptblock for PSJobs
    $GetSessions = {
        [CmdletBinding()]
        param (
            [string]$rhost
        )

        Add-Type -Name NSE -Namespace W32API -MemberDefinition @"
[DllImport("netapi32.dll", SetLastError=true)]
        public static extern int NetSessionEnum(
            [In,MarshalAs(UnmanagedType.LPWStr)] string ServerName,
            [In,MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
            [In,MarshalAs(UnmanagedType.LPWStr)] string UserName,
            Int32 Level,
            out IntPtr bufptr,
            int prefmaxlen,
            ref Int32 entriesread,
            ref Int32 totalentries,
            ref Int32 resume_handle);

    [DllImport("netapi32.dll")]
    public static extern uint NetApiBufferFree(IntPtr Buffer);

    public const int MAX_PREFERRED_LENGTH = -1;

    public enum NET_API_STATUS : uint {
        NERR_Success = 0,
        NERR_InvalidComputer = 2351,
        NERR_NotPrimary = 2226,
        NERR_SpeGroupOp = 2234,
        NERR_LastAdmin = 2452,
        NERR_BadPassword = 2203,
        NERR_PasswordTooShort = 2245,
        NERR_UserNotFound = 2221,
        ERROR_ACCESS_DENIED = 5,
        ERROR_NOT_ENOUGH_MEMORY = 8,
        ERROR_INVALID_PARAMETER = 87,
        ERROR_INVALID_NAME = 123,
        ERROR_INVALID_LEVEL = 124,
        ERROR_MORE_DATA = 234 ,
        ERROR_SESSION_CREDENTIAL_CONFLICT = 1219
    }

    //https://stackoverflow.com/questions/12451246/working-with-intptr-and-marshaling-using-add-type-in-powershell
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct SESSION_INFO_10 {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string sesi10_cname;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string sesi10_username;
        public uint sesi10_time;
        public uint sesi10_idle_time;
    }
"@;

        try {
            $Sessions = New-Object System.Collections.ArrayList;
            [System.IntPtr]$bufptr = 0;
            [int]$entriesread = 0;
            [int]$totalentries = 0;
            [int]$resume_handle = 0;

            $status = [w32api.NSE]::NetSessionEnum($rhost, $null, $null, 10, [ref]$bufptr, [W32API.NSE]::MAX_PREFERRED_LENGTH, [ref]$entriesread, [ref]$totalentries, [ref]$resume_handle);
            $bufref = $bufptr.ToInt64();

            if (($status -eq [W32API.NSE+NET_API_STATUS]::NERR_Success -or $status -eq [W32API.NSE+NET_API_STATUS]::ERROR_MORE_DATA) -and $entriesread -gt 0) {
                for ($s = 0; $s -lt $entriesread; $s++) {
                    [W32API.NSE+SESSION_INFO_10]$sinfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($bufptr.ToInt64(), [System.Type][W32API.NSE+SESSION_INFO_10]);

                    $SessionTime = [System.TimeSpan]::FromSeconds($sinfo.sesi10_time);
                    $IdleTime = [System.TimeSpan]::FromSeconds($sinfo.sesi10_idle_time);
                    
                    [void]$Sessions.Add([PSCustomObject][Ordered]@{
                            Source      = $sinfo.sesi10_cname.TrimStart("\")
                            Account     = $sinfo.sesi10_username
                            Destination = $rhost
                            SessionTime = ("{0}D:{1}H:{2}M:{3}S" -f $SessionTime.Days, $SessionTime.Hours, $SessionTime.Minutes, $SessionTime.Seconds)
                            IdleTime    = ("{0}D:{1}H:{2}M:{3}S" -f $IdleTime.Days, $IdleTime.Hours, $IdleTime.Minutes, $IdleTime.Seconds)
                    })
                
                    $bufptr = $bufptr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf([System.Type][W32API.NSE+SESSION_INFO_10]);
                }
            }
        }
        catch {
            "Error: $_";
        }
        finally {
            $fmresult = [W32API.NSE]::NetApiBufferFree($bufref);

            if ($fmresult -eq 0) {
                Write-Verbose "Success, memory freed!";
            }
        }
        return $Sessions;
    }

    # https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Subnet-db45ec74
    function Get-IPs { 
 
        Param( 
            [Parameter(Mandatory = $true)] 
            [array] $Subnets 
        ) 
 
        foreach ($subnet in $subnets) { 
         
            #Split IP and subnet 
            $IP = ($Subnet -split "\/")[0] 
            $SubnetBits = ($Subnet -split "\/")[1] 
         
            #Convert IP into binary 
            #Split IP into different octects and for each one, figure out the binary with leading zeros and add to the total 
            $Octets = $IP -split "\." 
            $IPInBinary = @() 
            foreach ($Octet in $Octets) { 
                #convert to binary 
                $OctetInBinary = [convert]::ToString($Octet, 2) 
                 
                #get length of binary string add leading zeros to make octet 
                $OctetInBinary = ("0" * (8 - ($OctetInBinary).Length) + $OctetInBinary) 
 
                $IPInBinary = $IPInBinary + $OctetInBinary 
            } 
            $IPInBinary = $IPInBinary -join "" 
 
            #Get network ID by subtracting subnet mask 
            $HostBits = 32 - $SubnetBits 
            $NetworkIDInBinary = $IPInBinary.Substring(0, $SubnetBits) 
         
            #Get host ID and get the first host ID by converting all 1s into 0s 
            $HostIDInBinary = $IPInBinary.Substring($SubnetBits, $HostBits)         
            $HostIDInBinary = $HostIDInBinary -replace "1", "0" 
 
            #Work out all the host IDs in that subnet by cycling through $i from 1 up to max $HostIDInBinary (i.e. 1s stringed up to $HostBits) 
            #Work out max $HostIDInBinary 
            $imax = [convert]::ToInt32(("1" * $HostBits), 2) - 1 
 
            $IPs = @() 
 
            #Next ID is first network ID converted to decimal plus $i then converted to binary 
            For ($i = 1 ; $i -le $imax ; $i++) { 
                #Convert to decimal and add $i 
                $NextHostIDInDecimal = ([convert]::ToInt32($HostIDInBinary, 2) + $i) 
                #Convert back to binary 
                $NextHostIDInBinary = [convert]::ToString($NextHostIDInDecimal, 2) 
                #Add leading zeros 
                #Number of zeros to add  
                $NoOfZerosToAdd = $HostIDInBinary.Length - $NextHostIDInBinary.Length 
                $NextHostIDInBinary = ("0" * $NoOfZerosToAdd) + $NextHostIDInBinary 
 
                #Work out next IP 
                #Add networkID to hostID 
                $NextIPInBinary = $NetworkIDInBinary + $NextHostIDInBinary 
                #Split into octets and separate by . then join 
                $IP = @() 
                For ($x = 1 ; $x -le 4 ; $x++) { 
                    #Work out start character position 
                    $StartCharNumber = ($x - 1) * 8 
                    #Get octet in binary 
                    $IPOctetInBinary = $NextIPInBinary.Substring($StartCharNumber, 8) 
                    #Convert octet into decimal 
                    $IPOctetInDecimal = [convert]::ToInt32($IPOctetInBinary, 2) 
                    #Add octet to IP  
                    $IP += $IPOctetInDecimal 
                } 
 
                #Separate by . 
                $IP = $IP -join "." 
                $IPs += $IP 
            } 

            return $IPs 
        } 
    } 


    # 'Main' Begins Here
    $List = $null;
    $JobCounter = 0;

    # Check arguments
    try {
        if (-not $HostList -and -not $SubnetList -and $ADComputerList) {
            #perhaps replace this later with IP Subnet Calc?
            $List = (Get-ADComputer -Filter * -Properties *).Name 
            Write-Verbose ("Counted {0} machines" -f (Measure-Object $List).Count);
        }
        elseif (-not $ADComputerList -and -not $SubnetList -and ($HostList.Count -gt 0)) {
            $List = $HostList;
        }
        elseif (-not $HostList -and -not $ADComputerList -and $SubnetList) {
            $List = Get-IPs -Subnets $SubnetList
        }
        elseif (-not $HostList -and -not $ADComputerList -and -not $SubnetList) {
            $List = (Get-ADComputer -Filter * -Properties *).Name 
            Write-Verbose ("Counted {0} machines" -f (Measure-Object $List).Count);
        }
        else {
            throw "Error: -All, -SubnetList and -ADComputerList cannot be used in the same call. Please choose one of the three ways to gather a list of hosts to enumerate sessions on."
        }
    }
    catch {
        Write-Host $_ -ForegroundColor Red -BackgroundColor Black;
        exit;
    }


    #1 Start enumeration jobs (1 thread is 1 host to enumerate sessions on)
    foreach ($rhost in $List) {
        $JobCounter++;

        if ($ShowProgress) {
            Write-Progress -Activity "Start Session Enumeration Jobs" -Status ("{0} Out Of {1} Jobs Started:" -f $JobCounter, $List.Count) -PercentComplete ([System.Math]::Round((($JobCounter / $List.Count) * 100) , 2)) -CurrentOperation "Starting Session Enumeration For $rhost";
        }

        while ((Get-Job -State "Running").Count -ge $Threads) {
            Write-Verbose "Thread limit reached, waiting $Wait milliseconds...";
            Start-Sleep $Wait;
        }

        [void](Start-Job -ScriptBlock $GetSessions -ArgumentList @($rhost));
    }


    #2 Wait for all jobs to finish before getting results
    while (Get-Job -State "Running") {
        if ($ShowProgress) {
            Write-Progress -Activity "Waiting For Enumeration Jobs" -Status ("{0} Out Of {1} Jobs Are Still Running:" -f (Get-Job -State "Running").Count, (Get-Job).Count) -PercentComplete ([System.Math]::Round((((Get-Job -State "Running").Count / (Get-Job).Count) * 100) , 2)); 
        }
    
        Write-Verbose "Waiting for enumeration jobs to finish...";
        Start-Sleep $wait;
    }


    #3 Get job results
    $SessionEnumResults = [System.Collections.ArrayList]::new()
    foreach ($JobResult in (Get-Job | Receive-Job)) {
        $Result = "" | Select-Object -Property Source, Account, Destination, SessionTime, IdleTime
        $Result.Source = [string]$JobResult.Source
        $Result.Account = [string]$JobResult.Account
        $Result.Destination = [string]$JobResult.Destination
        $Result.SessionTime = [string]$JobResult.SessionTime
        $Result.IdleTime = [string]$JobResult.IdleTime

        [void]$SessionEnumResults.Add($Result);
    }

    Remove-Job *;

    return $SessionEnumResults;
}

function Invoke-SPNHunter {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        $LDAPFilter = $null,

        [Parameter(Mandatory = $false)]
        [string[]]$ServiceFilter = $null,

        [Parameter(Mandatory = $false)]
        [switch]$KerberostableSPNs,

        [Parameter(Mandatory = $false)]
        [switch]$SPNScan
    )

    $Searcher = [System.DirectoryServices.DirectorySearcher]::new();
    $Searcher.PageSize = 1000;
   
    if ($KerberostableSPNs) {
        #https://blog.stealthbits.com/discovering-service-accounts-without-using-privileges/
        $Searcher.Filter = "(&(objectclass=user)(objectcategory=user))";

        foreach ($entry in ($Searcher.FindAll() | Where-Object { $_.Properties.serviceprincipalname -ne "$null" })) {
            foreach ($SPN in $entry.Properties.serviceprincipalname) {
                if ($ServiceFilter) {
                    if ($ServiceFilter -contains ($SPN.Split("/")[0] -replace "[/ :]", "")) {
                        [PSCustomObject]@{
                            AccountName = ([string]$entry.Properties.samaccountname).Trim("{}")
                            SPN         = $SPN
                        }
                    }
                }
                else {
                    [PSCustomObject]@{
                        AccountName = ([string]$entry.Properties.samaccountname).Trim("{}")
                        SPN         = $SPN
                    }
                }
            }
        }
    }
    elseif ($SPNScan){
        $Searcher.Filter = "(serviceprincipalname=*)"

        foreach($SPN in $Searcher.FindAll().Properties.serviceprincipalname){
            $SPN
        }
    }
    elseif($LDAPFilter){
        $LDAPFilter 
    }
}

function Invoke-TGSGatherer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position = 0)]
        [string[]]$SPNList,

        [Parameter(Mandatory=$false)]
        [switch]$PurgeTickets
    )

    if($PurgeTickets){
        C:\Windows\System32\klist.exe purge
    }
    
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.IdentityModel");

    foreach($SPN in $SPNList){
        try{
            [System.IdentityModel.Tokens.KerberosRequestorSecurityToken]::new($SPN);
        }
        catch [System.Exception]{
            $_.Message;
        }
        
    }
}

function Invoke-DomainHunter {
    #Get entries with netbiosname properties from partitions container
    $Searcher = [System.DirectoryServices.DirectorySearcher]::new();
    $Searcher.Filter = "(netbiosname=*)";
    [string]$RootDomain = [string][System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().RootDomain.Name -replace "\.", ",DC=" -replace "^", "DC="
    $Searcher.SearchRoot = [string]::Format("LDAP://CN=Partitions,CN=Configuration,{0}", $RootDomain);
    $DomainConfigs = $Searcher.FindAll();
    
    foreach ($Domain in [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains) {
        $DomainDN = [string]::Format("LDAP://dc={0}", $Domain.Name.Replace(".", ",dc="));
        $DomainSid = $null;
        $DomainEntry = [System.DirectoryServices.DirectoryEntry]::new($DomainDN)
    
        foreach ($bit in $DomainEntry.objectSid) {
            $DomainSid = [System.Security.Principal.SecurityIdentifier]::new($bit, 0).Value
        }
 
        $Domain | Add-Member -NotePropertyName "FullName" -NotePropertyValue $Domain.Name
        $Domain | Add-Member -NotePropertyName "ShortName" -NotePropertyValue (($DomainConfigs | Where-Object { $Domain.Name -like $_.Properties.dnsroot }).Properties.netbiosname.Trim("{}"))
        $Domain | Add-Member -NotePropertyName "DistinguishedName" -NotePropertyValue ($DomainDN.Replace("LDAP://", $null));
        $Domain | Add-Member -NotePropertyName "DomainSID" -NotePropertyValue $DomainSid;
        $Domain | Add-Member -NotePropertyName "IsRoot" -NotePropertyValue ($Domain.Name -eq $RootDomain);
        $Domain | Add-Member -NotePropertyName "ms-DS-MachineAccountQuota" -NotePropertyValue ($DomainEntry.'ms-DS-MachineAccountQuota'.ToString().Trim("{}"))
        $Domain
    }
}

function Invoke-TrustHunter {
    #Get domain trust information
    $Searcher = [System.DirectoryServices.DirectorySearcher]::new();
    $Searcher.PageSize = 1000;
    $Searcher.Filter = "(ObjectClass=trusteddomain)";
    $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain();

    foreach ($TrustingDomain in $Searcher.FindAll()) {
        #TrustDirection
        $TrustDirection = switch ($TrustingDomain.Properties.trustdirection) {
            1 { "Inbound" }
            2 { "Outbound" }
            3 { "Bidirectional" }
            default { $TrustingDomain.Properties.trustdirection }
        }

        #TrustType
        $TrustType = switch ($TrustingDomain.Properties.trusttype) {
            0 { "TreeRoot" }
            1 { "ParentChild" }
            2 { "CrossLink/Shortcut" }
            3 { "External" }
            4 { "Forest" }
            5 { "Kerberos" }
            6 { "Unknown" }
            default { $TrustingDomain.Properties.trusttype }
        }

        #TrustAttributes
        $TrustAttributes = switch ($TrustingDomain.Properties.trustattributes) { 
            1 { "Non-Transitive" } 
            2 { "Uplevel clients only (Windows 2000 or newer" } 
            4 { "Quarantined Domain (External)" } 
            8 { "Forest Trust" } 
            16 { "Cross-Organizational Trust (Selective Authentication)" } 
            32 { "Intra-Forest Trust (trust within the forest)" } 
            64 { "Inter-Forest Trust (trust with another forest)" } 
            Default { $TrustingDomain.Properties.trustattributes }
        } 

        #TrustingDomainSid
        $DomainSid = ($TrustingDomain.Properties.securityidentifier | % { [System.Security.Principal.SecurityIdentifier]::new($_, 0).Value })

        [PSCustomObject][Ordered]@{
            SourceDomain        = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
            TargetDomain        = [string]($TrustingDomain.Properties.name).Trim("{}")
            FlatName            = [string]($TrustingDomain.Properties.flatname).Trim("{}")
            TrustingDomainSid   = $DomainSid
            TrustType           = $TrustType
            TrustDirection      = $TrustDirection
            TrustAttributes     = $TrustAttributes
            SidFilteringEnabled = $CurrentDomain.GetSidFilteringStatus([string]($TrustingDomain.Properties.name).Trim("{}"))
        }
    }
}  

function Invoke-InfinityHopper {
    <#
    .DESCRIPTION
    Most likely a useless script that uses nested Invoke-Command calls to bypass the double hop issue in a Windows Active Directory Environment

    .NOTES
    Use single quotes for the string arguments for the intermediary and final destination commands. The script will use regex to format the string
    for proper escaping. If you escape the string yourself it shouldn't affect it as the -replace operator will strip any extra backticks you
    throw in anyways when preparing the final product.

    Initially I was unaware that Microsoft had dedicated documentation for tackling the double hop issue using PowerShell until a couple colleagues
    and I were in the midst of trying to come up with the best solution for the issue that one of them was facing.

    My initial thought process was, "if I can execute literally any command on a remote machine via PS-Remoting then I don't see why
    using Invoke-Command on the remote machine to further execute commands on additional WinRM enabled hosts wouldn't work."

    Low and behold it did work and https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/ps-remoting-second-hop?view=powershell-7
    further proves it.

    REQUIREMENTS:
        - The credentials you provide that will be used to hop machines with needs to have the appropriate permissions
            - Be an admin
            - Be a member of the local group, Remote Management Users on the remote machine

        - The username portion of the PSCredential object needs to be in the following domain\username format

        - The command that will execute on the final destination host needs to be able to intake a PSCredential object, securestring object or username and password
            in the form of a plaintext string via a cmdlet or .NET class constructor, method, etc.
            - For example most of the cmdlets in the RSAT/PowerShell AD module have a -Credential flag which you would feed the PSCredential object
              that you've passed down to. You'd think that having a session as a user with enough privileges would be enough, but it isn't. I believe
              the double hop issue in this case occurs at the point in which the remote powershell session tries to hand off the credentials of the user running the session
              to the service. (e.g. Get-ADUser (most likey uses LDAP or something like that)). DirectoryEntry is a good example of a .NET constructor that can be fed a
              string username and password argument.


    The following command line parameter variables can be fed back into the script via other arguments for the other parameters by literally listing the variable name with the $ prefix.
    The script wil parse this input and then expand it appropriatley when crafting the final product before execution
    - $ComputerNames
    - $Username
    - $Password

    There is one variable that is created after the command line arguments are parsed
    - $Credential - a PSCredential object created from the $Username and $Password parameters

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string[]]$ComputerNames,

        [Parameter(Mandatory = $true, Position = 1)]
        [string[]]$Username,

        [Parameter(Mandatory = $true, Position = 2)]
        [string]$Password,

        [Parameter(Mandatory = $false, HelpMessage = "The command to be executed on the final destination machine")]
        [string]$FinalDestinationCmd = '$env:COMPUTERNAME; $env:USERNAME; ',

        [Parameter(Mandatory = $false, HelpMessage = "The command to be executed on the intermediary machines")]
        [string]$IntermediaryDestinationCmd = '$env:COMPUTERNAME; $env:USERNAME; ',

        [Parameter(Mandatory = $false)]
        [switch]$PrintCommandString
    )

    $Payload = "";
    #$NetworkCredential = [System.Net.NetworkCredential]::new($Username.Split("\")[1], $Password, $Username.Split("\")[0]);
    $Credential = ([System.Management.Automation.PSCredential]::new($Username, (ConvertTo-SecureString -Force -AsPlainText $Password)));
    

    foreach ($ComputerName in $ComputerNames) {
        if (($ComputerNames.IndexOf($ComputerName) - ($ComputerNames.Count - 1)) -eq 0) {
            $Payload += ("Invoke-Command -ArgumentList ```$Credential, ```$Username, ```$Password -Credential ```$Credential -ComputerName $ComputerName -ScriptBlock { param(```$Credential, ```$Username, ```$Password) $($FinalDestinationCmd -replace "\$", "```$") ")

            1..$ComputerNames.Length | ForEach-Object { $Payload += ("}"); }
        }
        else {
            $Payload += ("Invoke-Command -ArgumentList ```$Credential, ```$Username, ```$Password -Credential ```$Credential -ComputerName $ComputerName -ScriptBlock { param(```$Credential, ```$Username, ```$Password) $($IntermediaryDestinationCmd -replace "\$", "```$") ")
        }
    }
    
    #Ready the payload by dropping the backticks
    $FinalStage = ($Payload.ToString() -replace "``", $null);
    #InvokeExpression doesn't understand the backticks, so strip them
    #Taking the actual $Payload string value with the backticks in them and pasting it into a PowerShell prompt and stuffing it inbetween double quotes will automatically strip the backticks off when you hit enter

    if($PrintCommandString){
        Write-Host "$FinalStage `n"
    }

    Invoke-Expression $FinalStage;
}

#($ComputerNames.IndexOf($ComputerName) - ($ComputerNames.Length - 1)
#$computername -eq $computernames[$computernames.count - 1]

function Invoke-InfinityHopper {
    <#
    .DESCRIPTION
    Most likely a useless script that uses nested Invoke-Command calls to bypass the double hop issue in a Windows Active Directory Environment

    .NOTES
    Use single quotes for the string arguments for the intermediary and final destination commands. The script will use regex to format the string
    for proper escaping. If you escape the string yourself it shouldn't affect it as the -replace operator will strip any extra backticks you
    throw in anyways when preparing the final product.

    Initially I was unaware that Microsoft had dedicated documentation for tackling the double hop issue using PowerShell until a couple colleagues
    and I were in the midst of trying to come up with the best solution for the issue that one of them was facing.

    My initial thought process was, "if I can execute literally any command on a remote machine via PS-Remoting then I don't see why
    using Invoke-Command on the remote machine to further execute commands on additional WinRM enabled hosts wouldn't work."

    Low and behold it did work and https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/ps-remoting-second-hop?view=powershell-7
    further proves it.

    REQUIREMENTS:
        - The credentials you provide that will be used to hop machines with needs to have the appropriate permissions
            - Be an admin
            - Be a member of the local group, Remote Management Users on the remote machine

        - The username portion of the PSCredential object needs to be in the following domain\username format

        - The command that will execute on the final destination host needs to be able to intake a PSCredential object, securestring object or username and password
            in the form of a plaintext string via a cmdlet or .NET class constructor, method, etc.
            - For example most of the cmdlets in the RSAT/PowerShell AD module have a -Credential flag which you would feed the PSCredential object
              that you've passed down to. You'd think that having a session as a user with enough privileges would be enough, but it isn't. I believe
              the double hop issue in this case occurs at the point in which the remote powershell session tries to hand off the credentials of the user running the session
              to the service. (e.g. Get-ADUser (most likey uses LDAP or something like that)). DirectoryEntry is a good example of a .NET constructor that can be fed a
              string username and password argument.


    The following command line parameter variables can be fed back into the script via other arguments for the other parameters by literally listing the variable name with the $ prefix.
    The script wil parse this input and then expand it appropriatley when crafting the final product before execution
    - $ComputerNames
    - $Username
    - $Password

    There is one variable that is created after the command line arguments are parsed
    - $Credential - a PSCredential object created from the $Username and $Password parameters

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string[]]$ComputerNames,

        [Parameter(Mandatory = $true, Position = 1)]
        [string[]]$Username,

        [Parameter(Mandatory = $true, Position = 2)]
        [string]$Password,

        [Parameter(Mandatory = $false, HelpMessage = "The command to be executed on the final destination machine")]
        [string]$FinalDestinationCmd = '$env:COMPUTERNAME; $env:USERNAME; ',

        [Parameter(Mandatory = $false, HelpMessage = "The command to be executed on the intermediary machines")]
        [string]$IntermediaryDestinationCmd = '$env:COMPUTERNAME; $env:USERNAME; ',

        [Parameter(Mandatory = $false)]
        [switch]$PrintCommandString
    )

    $Payload = "";
    #$NetworkCredential = [System.Net.NetworkCredential]::new($Username.Split("\")[1], $Password, $Username.Split("\")[0]);
    $Credential = ([System.Management.Automation.PSCredential]::new($Username, (ConvertTo-SecureString -Force -AsPlainText $Password)));
    

    foreach ($ComputerName in $ComputerNames) {
        if (($ComputerNames.IndexOf($ComputerName) - ($ComputerNames.Count - 1)) -eq 0) {
            $Payload += ("Invoke-Command -ArgumentList ```$Credential, ```$Username, ```$Password -Credential ```$Credential -ComputerName $ComputerName -ScriptBlock { param(```$Credential, ```$Username, ```$Password) $($FinalDestinationCmd -replace "\$", "```$") ")

            1..$ComputerNames.Length | ForEach-Object { $Payload += ("}"); }
        }
        else {
            $Payload += ("Invoke-Command -ArgumentList ```$Credential, ```$Username, ```$Password -Credential ```$Credential -ComputerName $ComputerName -ScriptBlock { param(```$Credential, ```$Username, ```$Password) $($IntermediaryDestinationCmd -replace "\$", "```$") ")
        }
    }
    
    #Ready the payload by dropping the backticks
    $FinalStage = ($Payload.ToString() -replace "``", $null);
    #InvokeExpression doesn't understand the backticks, so strip them
    #Taking the actual $Payload string value with the backticks in them and pasting it into a PowerShell prompt and stuffing it inbetween double quotes will automatically strip the backticks off when you hit enter

    if($PrintCommandString){
        Write-Host "$FinalStage `n"
    }

    Invoke-Expression $FinalStage;
}

#($ComputerNames.IndexOf($ComputerName) - ($ComputerNames.Length - 1)
#$computername -eq $computernames[$computernames.count - 1]


function Invoke-ACEHunter {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, HelpMessage = "Scope to search within. Default is subtree. Other options are OneLevel and Base")]
        [ValidateSet("SubTree", "OneLevel", "Base")]
        [string]$SearchScope = "SubTree",

        [Parameter(Mandatory = $false, HelpMessage = "The principal to match the identityrefernce property value to (aka the principal that has permissions against object)")]
        [ValidateNotNull()]
        $Principal,

        [Parameter(Mandatory = $false, HelpMessage = "The AD object to match the ADObjectName property value to (aka the object that can be enacted upon or has the permissions against)")]
        [string]$TargetObjectName = $null,

        [Parameter(Mandatory = $false, HelpMessage = "The AD object to match the ADObjectDN property value to (aka the object that can be enacted upon or has the permissions against)")]
        [string]$TargetObjectDN = $null,

        [Parameter(Mandatory = $false, HelpMessage = "The AccessType to look for (Allow, Deny or Any)")]
        [ValidateSet("Allow", "Deny")]
        [string]$AccessType,

        [Parameter(Mandatory = $false, HelpMessage = "An array of Active Directory permissions to look for against and object")]
        [string[]]$ActiveDirectoryRight = @("ForceChangePassword", "AddMembers", "GenericAll", "GenericWrite", "WriteOwner", "WriteDACL", "WriteOwner", "AllExtendedRights", "ExtendedRights", "Self"),

        [Parameter(Mandatory = $false, HelpMessage = "This switch will recursively enumerate every group the principal is a part of. So be warned that this could take a very long time!")]
        [ValidateSet("FirstDegreeMembership", "UnrolledMembership")]
        [string]$RecursePrincipalGroupMemberShip,

        [Parameter(Mandatory = $false, HelpMessage = "Check to see if Principal value is an owner of any of the enumerate AD objects. If so this is the equivalent of having GenericAll permissions against the object even if no ACEs are present in the object's DACL that allow the principal to do anything")]
        [switch]$CheckIfOwner,

        [Parameter(Mandatory = $false, HelpMessage = "The number of results to return with each iteration. Default is 1000.")]
        [ValidateRange(1, 9999)]
        [int]$ResultPageSize = 1000,

        # [Parameter(Mandatory = $false, HelpMessage = "The principal to match the identityrefernce property value to (aka the principal that has permissions against object)")]
        # [ValidateNotNull()]
        # [string]$Domain,

        [Parameter(Mandatory = $false, HelpMessage = "The LDAP filter string to use")]
        [string]$LDAPFilter,

        [Parameter(Mandatory = $false, HelpMessage = "Include objects that have been deleted?")]
        [switch]$IncludeDeleteObjects
    )

    $Global:GroupList = [System.Collections.ArrayList]::new();

    function Recurse-ADPrincipalGroupMembership {
        [CmdletBinding(DefaultParameterSetName = "FDM")]
        param (
            [string[]]$Groups,
            [string]$MembershipRelationship
        )

        foreach ($group in $Groups) {
            [void]$Global:GroupList.Add($group);
    
            if ($MembershipRelationship -eq "UnrolledMembership" -and (Get-ADPrincipalGroupMembership -Identity $group)) {
                Recurse-ADPrincipalGroupMembership -Groups (Get-ADPrincipalGroupMembership -Identity $group).SamAccountName
            }
            elseif ($MembershipRelationship -eq "FirstDegreeMembership") {
                break;
            }
            else {
                break;
            }
        }
    }

    function Build-CustomACE {
        [CmdletBinding()]
        param (
            $AccessControlEntryObject
        )

        $ace | Add-Member -NotePropertyName "ActiveDirectoryObjectName" -NotePropertyValue $adobject.Properties.name.Trim("{}")
        $ace | Add-Member -NotePropertyName "ActiveDirectoryObjectDistinguishedName" -NotePropertyValue $adobject.Properties.distinguishedname.Trim("{}")
                    
        if ($CheckIfOwner) {
            if ($SecurityDescriptor.Owner -like "*$AccountName*") {
                $ace | Add-Member -NotePropertyName "IdentityReferenceIsOwner" -NotePropertyValue $true
            }
            else {
                $ace | Add-Member -NotePropertyName "IdentityReferenceIsOwner" -NotePropertyValue $false
            }
        }

        $ace
    }
    



    $directorysearcher = [System.DirectoryServices.DirectorySearcher]::new();
    $directorysearcher.PageSize = $ResultPageSize
    $directorysearcher.SearchScope = $SearchScope

    #Parse command line options
    if (-not [string]::IsNullOrEmpty($LDAPFilter)) {
        $directorysearcher.Filter = $LDAPFilter
    }

    if ($Domain) {
        $DomainDNString = $null

        foreach ($part in $Domain.Split(".")) {
            $DomainDNString += "dc=$part,"
        }

        $directorysearcher.SearchRoot = "LDAP://$($DomainDNString.TrimEnd(","))";
    }

    if ($IncludeDeleteObjects) {
        $directorysearcher.Tombstone = $true
    }

    if (-not $ActiveDirectoryRight -or [string]::IsNullOrEmpty($ActiveDirectoryRight)) {
        $ActiveDirectoryRight = $null;
    }

    #figure out how to get principal name to adapt to a single value or an array
    if ($RecursePrincipalGroupMemberShip) {
        Recurse-ADPrincipalGroupMembership -Groups (Get-ADPrincipalGroupMembership -Identity $Principal).SamAccountName -MembershipRelationship $RecursePrincipalGroupMemberShip
        $Principal = $Global:GroupList.ToArray()
    }




    foreach ($adobject in $directorysearcher.FindAll()) {
        $SecurityDescriptor = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$($adobject.Properties.distinguishedname)").ObjectSecurity;

        foreach ($AccountName in $Principal) {
            foreach ($Right in $ActiveDirectoryRight) {
                foreach ($ace in ($SecurityDescriptor.Access | Where-Object { $_.IdentityReference -like "*$AccountName*" -and $_.ActiveDirectoryRights -like "*$Right*" -and $_.AccessControlType -match $AccessType })) {
                    if (-not $TargetObjectName -and -not $TargetObjectDN) {
                        Build-CustomACE -AccessControlEntryObject $ace
                    }
                    elseif (-not $TargetObjectDN -and $adobject.Properties.name -like "*$TargetObjectName*") {
                        Build-CustomACE -AccessControlEntryObject $ace
                    }
                    elseif (-not $TargetObjectName -and $adobject.Properties.distinguishedname -match $TargetObjectDN) {
                        Build-CustomACE -AccessControlEntryObject $ace
                    }
                }
            }
        }
    }
}
