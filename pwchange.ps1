# Function that checks if you are on PowerShell 7
function isPS7 {
    return ($PSVersionTable.PSEdition -eq "Core") -and ($PSVersionTable.PSVersion.Major -ge 7)
}

# Function that verifies Active Directory
function isAD {
    # Boolean checks if the current machine is part of a domain via Windows Management Instrumentation
    return (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
}

# Function for deter
function isAdmin {
    param ( [Parameter(Mandatory=$true)] [string]$accountName )

    return $null -ne (Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -split '\\' -eq $accountName })
}


# Funtion for generating password
function genPass {
    if (isPS7) {
        $length = 16
        # Characters for password
        
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+="
        
        # Utiilize System.Security.Cryptography.RandomNumberGenerator (ps 7) for secure randomized bytes
        $bytes = New-Object byte[] $length
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)

        # Divide each byte by the pw length and use the remainder as an index for our char list
        $password = -join ($bytes | ForEach-Object { $chars[$_% $chars.length] })

        "$($password)" | Out-File "passwords.txt" -Append

        # Convert to secure string
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    }
    else {
        $length = 16
        # Characters for password
        
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+="
        
        # Utiilize System.Security.Cryptography.RNGCryptoServiceProvider (ps 5.1) for secure randomized bytes
        $bytes = New-Object byte[] $length
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
        $rng.GetBytes($bytes)

        # Divide each byte by the pw length and use the remainder as an index for our char list
        $password = -join ($bytes | ForEach-Object { $chars[$_% $chars.length] })
        
        "$($password)" | Out-File "passwords.txt" -Append

        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force

    }

    return $securePassword
}



# Function for changing local account passwords
function changeLocal {
    # Loop through all local users
    Get-LocalUser | ForEach-Object {

        # Exclude admin accounts
        if(-not (isAdmin -accountName $_.Name)) {
            
            try {

                "Username: $($_.Name)" | Out-File "passwords.txt" -Append
                
                # Set password for each user
                $newPass = genPass
                
                Set-LocalUser -Name $_.Name -Password $newPass
                Write-Output "Password changed for user: $($_.Name)"
               
            }
            catch {
                Write-Output "Failed to change password for user: $($_.Name)"
                Write-Output "Error details: $($_.Exception.InnerException)"
                
            }
        }
        else {
            Write-Output "Ignored:$($_.Name)"
            "Username:$($_.Name) ADMINISTRATOR" | Out-File "passwords.txt" -Append
        }
        "---------------------------------------------------------------" | Out-File "passwords.txt" -Append
    }
}


# Function for changing AD Account Passwords
function changeAD {

    Get-ADUser | ForEach-Object {
        try {
            if ($_.adminCount -eq 0){
                $newPass = genPass
                Set-ADAccountPassword -Name $_.Name -Password $newPass
            }
            else {
                Write-OutPut "$($_Name) is Admin" | Out-Host
            }
        }
        catch {
            Write-Output "Failed to change password for users: $($_.Name)"
        }
    }

}

function main {
    changeLocal
    if (isAD) { changeAD }
    else { Write-Output "No Active" }
}

main