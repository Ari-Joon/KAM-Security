/*
 * Rules for what Microsoft Defender tolerates.
 *
 * Defender is very good at malware and deliberately permissive about the grey
 * band next to it: bundled adware, scareware "optimisers", browser hijackers,
 * commercial packers, and remote-access tools that are legitimate right up
 * until someone is talked into installing one over the phone. Most of that is
 * not malware and Defender is right not to delete it. It is still worth being
 * told about, which is the entire purpose of this file.
 *
 * Every rule carries three pieces of metadata that the interface reads:
 *
 *   kam_category    what kind of thing this is
 *   kam_confidence  informational | notable | strong
 *   kam_explains    a sentence written for the person reading the screen
 *
 * The confidence levels mean specific things and are not decoration:
 *
 *   informational  a true statement about the file that implies no wrongdoing.
 *                  "This is packed." "This is a remote-access tool." Shown
 *                  because it is useful context, never as an accusation.
 *   notable        characteristic of unwanted software. Legitimate programs do
 *                  trigger these.
 *   strong         highly specific to a behaviour with few innocent uses.
 *
 * Two globals are supplied by the host before each file is matched:
 *
 *   kam_script   true when the file's extension is one Windows will execute as
 *                a script (.ps1, .bat, .cmd, .vbs, .js and friends)
 *   kam_ext      that extension, lowercased, without the dot
 *
 * They exist because several rules below look for text rather than structure,
 * and text rules match text: this very file contains every string they search
 * for, as would a blocklist or a piece of documentation. `pe.is_pe or
 * kam_script` fences those rules to files that can actually run, which is the
 * only case where the text means anything.
 *
 * Rules are written to be specific rather than broad. A rule that fires on
 * something legitimate costs far more than one that misses: this whole layer is
 * worth having only while its output is short enough to read and trustworthy
 * enough to act on. Where a rule needs several independent markers before it
 * fires, that is deliberate.
 */

import "pe"

rule cryptocurrency_miner
{
    meta:
        kam_category = "Cryptocurrency miner"
        kam_confidence = "strong"
        kam_explains = "This contains the machinery of a cryptocurrency miner: mining-pool addresses and mining algorithm names. Miners are sometimes installed deliberately, but they are also the most common thing bundled silently into cracked software, and they will run your processor at full load whenever the machine is idle."

    strings:
        // Strong markers: long, structured, and specific to mining. Nothing
        // produces one of these by accident.
        $strong_pool_tcp = "stratum+tcp://" ascii wide
        $strong_pool_ssl = "stratum+ssl://" ascii wide
        $strong_donate = "--donate-level" ascii wide
        $strong_nicehash = "--nicehash" ascii wide
        $strong_supportxmr = "pool.supportxmr.com" ascii wide nocase
        $strong_minexmr = "pool.minexmr.com" ascii wide nocase
        $strong_nanopool = "nanopool.org" ascii wide nocase
        $strong_f2pool = "f2pool.com" ascii wide nocase
        $strong_xmrig = "xmrig" ascii wide nocase
        $strong_phoenix = "PhoenixMiner" ascii wide nocase

        // Weak markers: short algorithm names. Real miners contain them, but so
        // does any sufficiently large blob of compressed data -- six characters
        // of lowercase ASCII turn up in installer payloads by chance. These
        // corroborate a strong marker and can never establish one.
        $weak_randomx = "randomx" ascii wide nocase
        $weak_cryptonight = "cryptonight" ascii wide nocase
        $weak_ethash = "ethash" ascii wide nocase
        $weak_claymore = "Claymore" ascii wide nocase
        $weak_coin = "--coin=" ascii wide

    condition:
        // At least one strong marker, and two markers in total. Requiring "two
        // of anything" was not enough: Git's installer carries "randomx" and
        // "ethash" somewhere inside its compressed payload, and on that basis
        // alone this rule accused it of being a miner.
        (pe.is_pe or kam_script) and
        any of ($strong*) and
        2 of them
}

rule bundled_installer_wrapper
{
    meta:
        kam_category = "Bundled software installer"
        kam_confidence = "notable"
        kam_explains = "This installer is built on a platform whose business is bundling extra software with whatever you meant to install — toolbars, search hijackers, trial antivirus. The bundled offers are usually pre-ticked and are why people end up with software they never chose."

    strings:
        // Named monetisation SDKs. These are product names, not generic words.
        $installcore = "InstallCore" ascii wide nocase
        $opencandy = "OpenCandy" ascii wide nocase
        $amonetize = "Amonetize" ascii wide nocase
        $domaiq = "DomaIQ" ascii wide nocase
        $installmonetizer = "InstallMonetizer" ascii wide nocase
        $vittalia = "Vittalia" ascii wide nocase
        $ibryte = "iBryte" ascii wide nocase
        $solimba = "Solimba" ascii wide nocase
        $softonic = "SoftonicDownloader" ascii wide nocase
        $downloadadmin = "DownloadAdmin" ascii wide nocase
        $installrex = "InstallRex" ascii wide nocase

    condition:
        // Only for things that actually run. The names above appear inside
        // antivirus definition files and blocklists, which are data, not
        // programs, and flagging those would be nonsense.
        pe.is_pe and any of them
}

rule remote_access_tool
{
    meta:
        kam_category = "Remote-access tool"
        kam_confidence = "informational"
        kam_explains = "This is remote-desktop software, which lets someone else see and control this machine. That is completely legitimate and widely used for support. It is worth knowing about only because it is also the standard tool of telephone support scams: if you did not install this yourself, or installed it because someone on the phone asked you to, it is worth a second look."

    condition:
        // Read the file's own version resource rather than searching its bytes.
        //
        // A program that *mentions* AnyDesk is not AnyDesk. Safe Exam Browser
        // carries a list of remote-access tools because its job is to block
        // them during exams, and a plain string search called it remote-access
        // software on that basis. The version resource is where a file states
        // what it is, so that is what gets read.
        pe.is_pe and
        for any key, value in pe.version_info : (
            value icontains "AnyDesk" or
            value icontains "TeamViewer" or
            value icontains "ScreenConnect" or
            value icontains "ConnectWise Control" or
            value icontains "UltraViewer" or
            value icontains "Ammyy" or
            value icontains "RustDesk" or
            value icontains "Supremo" or
            value icontains "LogMeIn" or
            value icontains "Splashtop" or
            value icontains "GoToAssist"
        )
}

rule commercially_packed
{
    meta:
        kam_category = "Packed or protected"
        kam_confidence = "informational"
        kam_explains = "The contents of this program are compressed or encrypted, so nothing can inspect what it actually does without running it. Commercial software uses this legitimately to protect against copying, and games use it constantly. Malware uses it to hide. On its own it means only that this file cannot be examined."

    condition:
        pe.is_pe and
        for any section in pe.sections : (
            section.name == "UPX0" or
            section.name == "UPX1" or
            section.name == ".themida" or
            section.name == ".vmp0" or
            section.name == ".vmp1" or
            section.name == ".enigma1" or
            section.name == ".aspack" or
            section.name == ".petite"
        )
}

rule encoded_powershell_launcher
{
    meta:
        kam_category = "Hidden PowerShell command"
        kam_confidence = "strong"
        kam_explains = "This launches PowerShell with its command base64-encoded and its window hidden. Encoding a command's text has no legitimate purpose other than to stop a person reading it, and hiding the window stops them seeing it run. Installers and scripts that have nothing to conceal do not do either."

    strings:
        $ps = "powershell" ascii wide nocase

        $enc_short = "-enc " ascii wide nocase
        $enc_long = "-EncodedCommand" ascii wide nocase
        $enc_e = "-e JAB" ascii wide nocase

        $hidden_w = "-w hidden" ascii wide nocase
        $hidden_long = "-WindowStyle Hidden" ascii wide nocase
        $nop = "-NoProfile" ascii wide nocase

    condition:
        (pe.is_pe or kam_script) and
        $ps and any of ($enc*) and any of ($hidden*, $nop)
}

rule downloads_and_executes
{
    meta:
        kam_category = "Downloads and runs code"
        kam_confidence = "strong"
        kam_explains = "This fetches code from the internet and runs it immediately, without writing it to disk where anything could examine it first. It is a standard technique for keeping the part that does the real work off the machine until the last moment, and it is also how some legitimate install scripts work — so check where it is downloading from."

    strings:
        $iex_full = "Invoke-Expression" ascii wide nocase
        $iex_short = "IEX(" ascii wide nocase
        $iex_pipe = "| IEX" ascii wide nocase

        $dl_string = "DownloadString" ascii wide nocase
        $dl_file = "DownloadFile" ascii wide nocase
        $dl_webclient = "Net.WebClient" ascii wide nocase

        // Living-off-the-land downloads: Windows' own signed tools, used as
        // downloaders precisely because they are signed and expected.
        $certutil = "certutil" ascii wide nocase
        $urlcache = "-urlcache" ascii wide nocase
        $bitsadmin = "bitsadmin" ascii wide nocase
        $transfer = "/transfer" ascii wide nocase
        $mshta_http = "mshta http" ascii wide nocase

    condition:
        (
            // Fetch-and-run in a script is the real pattern: a script is read
            // as text, so these strings are the code itself. Inside a compiled
            // program the same words are just words -- git-lfs contains both
            // "Invoke-Expression" and "DownloadFile" for entirely ordinary
            // reasons, and was accused on that basis.
            kam_script and any of ($iex*) and any of ($dl_*)
        ) or
        (
            // These pair a specific tool with the specific flag that turns it
            // into a downloader, which is narrow enough to mean something in a
            // compiled program too.
            (pe.is_pe or kam_script) and
            (
                ($certutil and $urlcache) or
                ($bitsadmin and $transfer) or
                $mshta_http
            )
        )
}

rule browser_search_hijack
{
    meta:
        kam_category = "Browser search hijacker"
        kam_confidence = "notable"
        kam_explains = "This reaches into browser settings that control your search engine, home page and extensions. Browsers and their own installers do this legitimately. Anything else doing it is usually changing where your searches go, which is how search hijacking makes money."

    strings:
        $ie_main = "Software\\Microsoft\\Internet Explorer\\Main" ascii wide
        $scopes = "SearchScopes" ascii wide
        $start_page = "Start Page" ascii wide
        $chrome_secure = "Secure Preferences" ascii wide
        $chrome_load = "--load-extension" ascii wide
        $default_search = "DefaultSearchProviderSearchURL" ascii wide
        $ext_forcelist = "ExtensionInstallForcelist" ascii wide
        $firefox_prefs = "user_pref(\"browser.search" ascii wide

    condition:
        // Three independent markers. A browser touches one or two of these as a
        // matter of course; something reaching for several at once is
        // rearranging settings rather than using them.
        pe.is_pe and 3 of them
}

rule fake_system_optimiser
{
    meta:
        kam_category = "Scareware optimiser"
        kam_confidence = "notable"
        kam_explains = "This contains the vocabulary of a fake optimiser: alarming claims about errors and threats, paired with a prompt to pay. These programs invent the problems they then offer to fix, and the counts they display are not measurements of anything. Genuine tools report what they found; these report what sells."

    strings:
        $scare1 = "Your PC is at risk" ascii wide nocase
        $scare2 = "Your computer is infected" ascii wide nocase
        $scare3 = "registry errors" ascii wide nocase
        $scare4 = "problems were found" ascii wide nocase
        $scare5 = "Speed up your PC" ascii wide nocase
        $scare6 = "junk files found" ascii wide nocase
        $scare7 = "Your system is slow" ascii wide nocase
        $scare8 = "critical errors detected" ascii wide nocase

        $sell1 = "Activate Now" ascii wide nocase
        $sell2 = "Buy Full Version" ascii wide nocase
        $sell3 = "Upgrade to Pro" ascii wide nocase
        $sell4 = "Register Now to Fix" ascii wide nocase
        $sell5 = "Purchase the full" ascii wide nocase

    condition:
        // The alarm on its own is not enough: real security software says
        // alarming things too, accurately. It is the alarm attached to a till
        // that identifies this pattern.
        pe.is_pe and 2 of ($scare*) and any of ($sell*)
}

rule browser_credential_theft
{
    meta:
        kam_category = "Browser credential theft"
        kam_confidence = "strong"
        kam_explains = "This reaches directly for the files a browser keeps saved passwords, cookies and card details in — the login database, the cookie store, and the key that decrypts them. Software that legitimately reads those is the browser itself. Anything else opening them by their exact internal paths is an infostealer collecting what to send off the machine, which is how a single unlucky download turns into a hijacked email, Discord or Instagram account."

    strings:
        // The exact on-disk names of the credential stores. A program that
        // names several of these is navigating a browser's private files, not
        // its own.
        $login_data = "\\Login Data" ascii wide nocase
        $web_data = "\\Web Data" ascii wide nocase
        $cookies_net = "\\Network\\Cookies" ascii wide nocase
        $local_state = "\\Local State" ascii wide nocase
        $leveldb = "\\Local Storage\\leveldb" ascii wide nocase
        $ff_logins = "logins.json" ascii wide nocase
        $ff_key = "key4.db" ascii wide nocase

        // The two ways the saved-password encryption key is unwrapped: the
        // older DPAPI blob prefix, and the newer app-bound key.
        $dpapi = "DPAPI" ascii wide
        $app_bound = "app_bound_encrypted_key" ascii wide nocase
        $os_crypt = "os_crypt" ascii wide nocase
        $encrypted_key = "encrypted_key" ascii wide nocase

        // Where stealers look for browser profiles, and the wallets they take
        // alongside them.
        $user_data = "\\User Data\\" ascii wide nocase
        $wallet = "wallet.dat" ascii wide nocase
        $metamask = "MetaMask" ascii wide

    condition:
        // Only for something that runs, and only when it reaches for more than
        // one of these at once. A single mention is a browser, a backup tool,
        // or documentation; the whole set together is theft.
        (pe.is_pe or kam_script) and
        (
            (2 of ($login_data, $web_data, $cookies_net, $local_state, $leveldb, $ff_logins, $ff_key)) or
            (any of ($login_data, $web_data, $ff_logins, $local_state) and any of ($dpapi, $app_bound, $os_crypt, $encrypted_key)) or
            (any of ($login_data, $cookies_net, $leveldb, $user_data) and any of ($wallet, $metamask))
        )
}

rule build_tool_loader
{
    meta:
        kam_category = "Build tool used as a loader"
        kam_confidence = "strong"
        kam_explains = "This is a build project file that carries an inline code task — a program embedded inside what should be a description of how to compile software. MSBuild, which is signed by Microsoft and trusted everywhere, will run that code when handed the file, and antivirus does not read project files. It is a known way to run a payload while the only thing on screen is a trusted Microsoft process, and it is exactly how the infection this tool was hardened against stayed hidden."

    strings:
        // MSBuild's inline-task machinery: a task written in C# compiled and run
        // at build time. Legitimate but rare, and the load-bearing part of this
        // technique.
        $usingtask = "UsingTask" ascii wide nocase
        $codetaskfactory = "CodeTaskFactory" ascii wide nocase
        $roslyn = "RoslynCodeTaskFactory" ascii wide nocase
        $task_code = "<Code" ascii wide nocase
        $lang_cs = "Language=\"cs\"" ascii wide nocase

        // What that inline code reaches for when it is a loader rather than a
        // build step: reflective assembly loading and in-memory execution.
        $assembly_load = "Assembly.Load" ascii wide
        $from_base64 = "FromBase64String" ascii wide
        $gzip = "GZipStream" ascii wide
        $invoke = "Invoke(" ascii wide

    condition:
        // Fenced to files that MSBuild actually executes: a project or an
        // imported targets/props file. Without this the rule would match its
        // own description and any document quoting these API names, since a
        // project file is neither a PE nor a script in the `kam_script` sense.
        (
            kam_ext == "csproj" or kam_ext == "vbproj" or kam_ext == "fsproj" or
            kam_ext == "proj" or kam_ext == "targets" or kam_ext == "props" or
            kam_ext == "sln"
        ) and
        $usingtask and
        any of ($codetaskfactory, $roslyn, $task_code, $lang_cs) and
        any of ($assembly_load, $from_base64, $gzip, $invoke)
}
