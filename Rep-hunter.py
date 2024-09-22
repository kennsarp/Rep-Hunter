import csv
import os
import requests
import json
from datetime import datetime
from termcolor import colored
import math
import base64


def set_console_color(foreground, background):
    #print(colored('', foreground, background))
    pass  # Implementation not provided in Python


def display_banner():
    set_console_color('green', 'black')
    print("""
************************************************************************************
*██████╗ ███████╗██████╗       ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ *
*██╔══██╗██╔════╝██╔══██╗      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗*
*██████╔╝█████╗  ██████╔╝█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝*
*██╔══██╗██╔══╝  ██╔═══╝ ╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗*
*██║  ██║███████╗██║           ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║*
*╚═╝  ╚═╝╚══════╝╚═╝           ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝*
*   powered by kennsarp                                                    ver:1.0 *
************************************************************************************
           Query VirusTotal for IP, URL, Domain and file hash reputation.

    """)
    set_console_color('Green', 'black')


def get_vt_report(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        response_json = response.json()

        return {
            'IP':
            ip,
            'LastAnalysis':
            response_json['data']['attributes']['last_analysis_stats']
        }
    except Exception as e:
        print(f"Error occurred while querying VirusTotal for IP: {ip}")


def get_hash_report(hash_val, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_val}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        response_json = response.json()

        return {
            'Hash':
            hash_val,
            'LastAnalysis':
            response_json['data']['attributes']['last_analysis_stats']
        }
    except Exception as e:
        print(f"Error occurred while querying VirusTotal for hash: {hash_val}")


def encode_url_base64(url):
    bytes_data = url.encode('utf-8')
    base64_data = bytes_data.hex()
    return base64_data


def get_url_report(url, api_key):
    encoded_url = encode_url_base64(url)
    api_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(api_url, headers=headers)
        response_json = response.json()

        return {
            'URL':
            url,
            'LastAnalysis':
            response_json['data']['attributes']['last_analysis_stats'],
            'ScanResults':
            response_json['data']['attributes']['last_analysis_results']
        }
    except Exception as e:
        print(f"Error occurred while querying VirusTotal for URL: {url}")


def get_domain_report(domain, api_key):
    api_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(api_url, headers=headers)
        response_json = response.json()

        return {
            'Domain':
            domain,
            'LastAnalysis':
            response_json['data']['attributes']['last_analysis_stats']
        }
    except Exception as e:
        print(f"Error occurred while querying VirusTotal for Domain: {domain}")


def save_config(api_key):
    config = {'ApiKey': api_key}
    with open(os.path.join(os.environ.get('HOME', ''), 'Rep-HunterConfig.txt'),
              'w') as file:
        json.dump(config, file, indent=4)


#def newl():
#    print("\n")


def get_file_ip_report(file_path, api_key, output_file):
    ip_set = set()
    
    # Ensure file_path ends with .csv or .txt
    if not (file_path.endswith('.csv') or file_path.endswith('.txt')):
        print("Error: Input file must be a .csv or .txt file.")
        return

    # Ensure output_file ends with .txt
    if not output_file.endswith('.txt'):
        print("Error: Output file must be a .txt file.")
        return

    try:
        with open(file_path, 'r') as file:
            if file_path.endswith('.csv'):
                csv_data = csv.DictReader(file)
                columns = input("Enter the column names containing IPs (comma-separated if multiple): ").split(',')
                # Check if columns exist in CSV
                for column in columns:
                    if column not in csv_data.fieldnames:
                        raise ValueError(f"Column '{column}' not found in the CSV file.")
                for row in csv_data:
                    for column in columns:
                        ip_set.add(row[column])
            elif file_path.endswith('.txt'):
                ip_set = set(file.read().splitlines())
            else:
                raise ValueError("Invalid file format. Only .txt or .csv files are supported.")
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return
    except ValueError as ve:
        print(f"Error: {ve}")
        return
    except Exception as e:
        print(f"An unexpected error occurred while reading the file: {e}")
        return

    total_ips_scanned = 0
    malicious_ips = 0
    non_malicious_ips = 0
    malicious_ip_list = []
    non_malicious_ip_list = []

    start_time = datetime.now()

    # Scan intro message
    print()
    print("Bulk IP Reputation Scan Initiated...")

    results = []
    for ip in ip_set:
        try:
            print(colored(f"Processing IP: {ip}", 'green'))  # Log the IP being processed
            result = get_vt_report(ip, api_key)
            if result:
                results.append(result)
                total_ips_scanned += 1
                if result['LastAnalysis']['malicious'] > 0 or result['LastAnalysis']['suspicious'] > 0:
                    malicious_ips += 1
                    malicious_ip_list.append(result['IP'])
                    print(colored(f"IP {ip} is marked as malicious or suspicious.", 'red'))
                else:
                    non_malicious_ips += 1
                    non_malicious_ip_list.append(result['IP'])
                    print(colored(f"IP {ip} is marked as non-malicious.", 'blue'))
            else:
                print(colored(f"Failed to retrieve data for IP: {ip}", 'yellow'))
        except requests.RequestException as re:
            print(f"Network error occurred while querying VirusTotal for IP: {ip}. Details: {re}")
        except KeyError as ke:
            print(f"Unexpected response format while processing IP: {ip}. Missing key: {ke}")
        except Exception as e:
            print(f"An unexpected error occurred while processing IP: {ip}. Details: {e}")

    end_time = datetime.now()
    duration = end_time - start_time

    summary = "===========================================================\n"
    summary += "|                    IP Reputation Scan                   |\n"
    summary += "|---------------------------------------------------------|\n"
    summary += f"| Date and Time of Scan: {datetime.now().strftime('%m/%d/%Y %H:%M:%S')}             |\n"
    summary += f"| Duration: {duration}                                      |\n"
    summary += f"| Total IPs Scanned: {total_ips_scanned}                                  |\n"
    summary += f"| Malicious IPs: {malicious_ips}                                      |\n"
    summary += f"| Non-Malicious IPs: {non_malicious_ips}                                   |\n"
    summary += "===========================================================\n\n"
    summary += "Malicious IPs                 \n"
    summary += "-------------\n"
    summary += "\n".join(malicious_ip_list)
    summary += "\n\nNon-Malicious IPs\n"
    summary += "-----------------\n"
    summary += "\n".join(non_malicious_ip_list)

    try:
        with open(output_file, 'w', encoding='utf-8') as out_file:
            out_file.write(summary)
    except IOError as ioe:
        print(f"Error writing to output file {output_file}. Details: {ioe}")

    return results


def get_file_hash_report(file_path, api_key, output_file):
    hash_set = set()

    # Ensure file_path ends with .csv or .txt
    if not (file_path.endswith('.csv') or file_path.endswith('.txt')):
        print("Error: Input file must be a .csv or .txt file.")
        return

    # Ensure output_file ends with .txt
    if not output_file.endswith('.txt'):
        print("Error: Output file must be a .txt file.")
        return

    try:
        with open(file_path, 'r') as file:
            if file_path.endswith('.csv'):
                csv_data = csv.DictReader(file)
                columns = input("Enter the column names containing hash values (comma-separated if multiple): ").split(',')
                # Check if columns exist in CSV
                for column in columns:
                    if column not in csv_data.fieldnames:
                        raise ValueError(f"Column '{column}' not found in the CSV file.")
                for row in csv_data:
                    for column in columns:
                        hash_set.add(row[column])
            elif file_path.endswith('.txt'):
                hash_set = set(file.read().splitlines())
            else:
                raise ValueError("Invalid file format. Only .txt or .csv files are supported.")
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return
    except ValueError as ve:
        print(f"Error: {ve}")
        return
    except Exception as e:
        print(f"An unexpected error occurred while reading the file: {e}")
        return

    total_hashes_scanned = 0
    malicious_hashes = 0
    non_malicious_hashes = 0
    malicious_hash_list = []
    non_malicious_hash_list = []

    start_time = datetime.now()

    # Scan intro message
    print()
    print("Bulk Hash Reputation Scan Initiated...")

    results = []
    for hash_value in hash_set:
        try:
            print(colored(f"Processing Hash: {hash_value}", 'green'))  # Log the hash being processed
            result = get_vt_report(hash_value, api_key)
            if result:
                results.append(result)
                total_hashes_scanned += 1
                if result['LastAnalysis']['malicious'] > 0 or result['LastAnalysis']['suspicious'] > 0:
                    malicious_hashes += 1
                    malicious_hash_list.append(result['hash'])
                    print(colored(f"Hash {hash_value} is marked as malicious or suspicious.", 'red'))
                else:
                    non_malicious_hashes += 1
                    non_malicious_hash_list.append(result['hash'])
                    print(colored(f"Hash {hash_value} is marked as non-malicious.", 'blue'))
            else:
                print(colored(f"Failed to retrieve data for hash: {hash_value}", 'yellow'))
        except requests.RequestException as re:
            print(f"Network error occurred while querying VirusTotal for hash: {hash_value}. Details: {re}")
        except KeyError as ke:
            print(f"Unexpected response format while processing hash: {hash_value}. Missing key: {ke}")
        except Exception as e:
            print(f"An unexpected error occurred while processing hash: {hash_value}. Details: {e}")

    end_time = datetime.now()
    duration = end_time - start_time

    summary = "===========================================================\n"
    summary += "|                   Hash Reputation Scan                  |\n"
    summary += "|---------------------------------------------------------|\n"
    summary += f"| Date and Time of Scan: {datetime.now().strftime('%m/%d/%Y %H:%M:%S')}             |\n"
    summary += f"| Duration: {duration}                                      |\n"
    summary += f"| Total Hashes Scanned: {total_hashes_scanned}                              |\n"
    summary += f"| Malicious Hashes: {malicious_hashes}                                    |\n"
    summary += f"| Non-Malicious Hashes: {non_malicious_hashes}                              |\n"
    summary += "===========================================================\n\n"
    summary += "Malicious Hashes\n"
    summary += "----------------\n"
    summary += "\n".join(malicious_hash_list)
    summary += "\n\nNon-Malicious Hashes\n"
    summary += "--------------------\n"
    summary += "\n".join(non_malicious_hash_list)

    try:
        with open(output_file, 'w', encoding='utf-8') as out_file:
            out_file.write(summary)
    except IOError as ioe:
        print(f"Error writing to output file {output_file}. Details: {ioe}")

    return results


def get_file_url_report(file_path, api_key, output_file):
    url_set = set()

    # Ensure file_path ends with .csv or .txt
    if not (file_path.endswith('.csv') or file_path.endswith('.txt')):
        print("Error: Input file must be a .csv or .txt file.")
        return

    # Ensure output_file ends with .txt
    if not output_file.endswith('.txt'):
        print("Error: Output file must be a .txt file.")
        return

    try:
        with open(file_path, 'r') as file:
            if file_path.endswith('.csv'):
                csv_data = csv.DictReader(file)
                columns = input("Enter the column names containing URLs (comma-separated if multiple): ").split(',')
                # Check if columns exist in CSV
                for column in columns:
                    if column not in csv_data.fieldnames:
                        raise ValueError(f"Column '{column}' not found in the CSV file.")
                for row in csv_data:
                    for column in columns:
                        url_set.add(row[column])
            elif file_path.endswith('.txt'):
                url_set = set(file.read().splitlines())
            else:
                raise ValueError("Invalid file format. Only .txt or .csv files are supported.")
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return
    except ValueError as ve:
        print(f"Error: {ve}")
        return
    except Exception as e:
        print(f"An unexpected error occurred while reading the file: {e}")
        return

    total_urls_scanned = 0
    malicious_urls = 0
    non_malicious_urls = 0
    malicious_url_list = []
    non_malicious_url_list = []

    start_time = datetime.now()

    # Scan intro message
    print()
    print("Bulk URL Reputation Scan Initiated...")

    results = []
    for url in url_set:
        try:
            print(colored(f"Processing URL: {url}", 'green'))  # Log the URL being processed
            result = get_vt_report(url, api_key)
            if result:
                results.append(result)
                total_urls_scanned += 1
                if result['LastAnalysis']['malicious'] > 0 or result['LastAnalysis']['suspicious'] > 0:
                    malicious_urls += 1
                    malicious_url_list.append(result['url'])
                    print(colored(f"URL {url} is marked as malicious or suspicious.", 'red'))
                else:
                    non_malicious_urls += 1
                    non_malicious_url_list.append(result['url'])
                    print(colored(f"URL {url} is marked as non-malicious.", 'blue'))
            else:
                print(colored(f"Failed to retrieve data for URL: {url}", 'yellow'))
        except requests.RequestException as re:
            print(f"Network error occurred while querying VirusTotal for URL: {url}. Details: {re}")
        except KeyError as ke:
            print(f"Unexpected response format while processing URL: {url}. Missing key: {ke}")
        except Exception as e:
            print(f"An unexpected error occurred while processing URL: {url}. Details: {e}")

    end_time = datetime.now()
    duration = end_time - start_time

    summary = "===========================================================\n"
    summary += "|                   URL Reputation Scan                    |\n"
    summary += "|---------------------------------------------------------|\n"
    summary += f"| Date and Time of Scan: {datetime.now().strftime('%m/%d/%Y %H:%M:%S')}             |\n"
    summary += f"| Duration: {duration}                                      |\n"
    summary += f"| Total URLs Scanned: {total_urls_scanned}                              |\n"
    summary += f"| Malicious URLs: {malicious_urls}                                    |\n"
    summary += f"| Non-Malicious URLs: {non_malicious_urls}                              |\n"
    summary += "===========================================================\n\n"
    summary += "Malicious URLs\n"
    summary += "--------------\n"
    summary += "\n".join(malicious_url_list)
    summary += "\n\nNon-Malicious URLs\n"
    summary += "------------------\n"
    summary += "\n".join(non_malicious_url_list)

    try:
        with open(output_file, 'w', encoding='utf-8') as out_file:
            out_file.write(summary)
    except IOError as ioe:
        print(f"Error writing to output file {output_file}. Details: {ioe}")

    return results


def get_file_domain_report(file_path, api_key, output_file):
    domain_set = set()

    # Ensure file_path ends with .csv or .txt
    if not (file_path.endswith('.csv') or file_path.endswith('.txt')):
        print("Error: Input file must be a .csv or .txt file.")
        return

    # Ensure output_file ends with .txt
    if not output_file.endswith('.txt'):
        print("Error: Output file must be a .txt file.")
        return

    try:
        with open(file_path, 'r') as file:
            if file_path.endswith('.csv'):
                csv_data = csv.DictReader(file)
                columns = input("Enter the column names containing domains (comma-separated if multiple): ").split(',')
                # Check if columns exist in CSV
                for column in columns:
                    if column not in csv_data.fieldnames:
                        raise ValueError(f"Column '{column}' not found in the CSV file.")
                for row in csv_data:
                    for column in columns:
                        domain_set.add(row[column])
            elif file_path.endswith('.txt'):
                domain_set = set(file.read().splitlines())
            else:
                raise ValueError("Invalid file format. Only .txt or .csv files are supported.")
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return
    except ValueError as ve:
        print(f"Error: {ve}")
        return
    except Exception as e:
        print(f"An unexpected error occurred while reading the file: {e}")
        return

    total_domains_scanned = 0
    malicious_domains = 0
    non_malicious_domains = 0
    malicious_domain_list = []
    non_malicious_domain_list = []

    start_time = datetime.now()

    # Scan intro message
    print()
    print("Bulk Domain Reputation Scan Initiated...")

    results = []
    for domain in domain_set:
        try:
            print(colored(f"Processing Domain: {domain}", 'green'))  # Log the domain being processed
            result = get_domain_report(domain, api_key)
            if result:
                results.append(result)
                total_domains_scanned += 1
                if result['LastAnalysis']['malicious'] > 0 or result['LastAnalysis']['suspicious'] > 0:
                    malicious_domains += 1
                    malicious_domain_list.append(result['domain'])
                    print(colored(f"Domain {domain} is marked as malicious or suspicious.", 'red'))
                else:
                    non_malicious_domains += 1
                    non_malicious_domain_list.append(result['domain'])
                    print(colored(f"Domain {domain} is marked as non-malicious.", 'blue'))
            else:
                print(colored(f"Failed to retrieve data for Domain: {domain}", 'yellow'))
        except requests.RequestException as re:
            print(f"Network error occurred while querying VirusTotal for Domain: {domain}. Details: {re}")
        except KeyError as ke:
            print(f"Unexpected response format while processing Domain: {domain}. Missing key: {ke}")
        except Exception as e:
            print(f"An unexpected error occurred while processing Domain: {domain}. Details: {e}")

    end_time = datetime.now()
    duration = end_time - start_time

    summary = "===========================================================\n"
    summary += "|                   Domain Reputation Scan                 |\n"
    summary += "|---------------------------------------------------------|\n"
    summary += f"| Date and Time of Scan: {datetime.now().strftime('%m/%d/%Y %H:%M:%S')}             |\n"
    summary += f"| Duration: {duration}                                      |\n"
    summary += f"| Total Domains Scanned: {total_domains_scanned}                              |\n"
    summary += f"| Malicious Domains: {malicious_domains}                                    |\n"
    summary += f"| Non-Malicious Domains: {non_malicious_domains}                              |\n"
    summary += "===========================================================\n\n"
    summary += "Malicious Domains\n"
    summary += "----------------\n"
    summary += "\n".join(malicious_domain_list)
    summary += "\n\nNon-Malicious Domains\n"
    summary += "--------------------\n"
    summary += "\n".join(non_malicious_domain_list)

    try:
        with open(output_file, 'w', encoding='utf-8') as out_file:
            out_file.write(summary)
    except IOError as ioe:
        print(f"Error writing to output file {output_file}. Details: {ioe}")

    return results


def main():
    while True:
        display_banner()
        api_key = ""

        config_file_path = config_file_path = os.path.join(
            os.environ.get('HOME', ''), 'Rep-HunterConfig.txt')

        if os.path.exists(config_file_path):
            with open(config_file_path, 'r') as file:
                config_data = json.load(file)
                api_key = config_data.get('ApiKey', "")

        else:
            api_key = input("Enter your VirusTotal API key: ")

            save_config(api_key)

        print("Choose an option:")
        print("-----------------")
        print("1. Single IP check")
        print("2. Single hash check")
        print("3. Single URL check")
        print("4. Single Domain check")
        print("5. IP check(.txt or .csv)")
        print("6. File hash check (.txt or .csv)")
        print("7. URL check (.txt or .csv)")
        print("8. Domain check (.txt or .csv)")
        print("9. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            ip = input("Enter the IP address: ")
            result = get_vt_report(ip, api_key)
            if result:
                print("IP Address:", result['IP'])
                print("Last Analysis Stats:", result['LastAnalysis'])
        elif choice == '2':
            hash_val = input("Enter the file hash to check: ")
            result = get_hash_report(hash_val, api_key)
            if result:
                print("Reputation for Hash:", result['Hash'])
                print("Last Analysis Stats:", result['LastAnalysis'])
        elif choice == '3':
            url = input("Enter the URL: ")
            result = get_url_report(url, api_key)
            if result:
                print("Reputation for URL:", result['URL'])
                print("Last Analysis Stats:", result['LastAnalysis'])
        elif choice == '4':
            domain = input("Enter the Domain: ")
            result = get_domain_report(domain, api_key)
            if result:
                print("Reputation for Hash:", result['Domain'])
                print("Last Analysis Stats:", result['LastAnalysis'])
        elif choice == '5':
            file_path = input(
                "Enter the path to the input file (.txt or .csv): ")
            output_file = input("Enter the path to the output file: ")
            # Implement bulk IP check
            results = get_file_ip_report(file_path, api_key, output_file)
            print("Bulk IP check completed.")
            print(f"Results saved to {output_file}")
        elif choice == '6':
            file_path = input(
                "Enter the path to the input file (.txt or .csv): ")
            output_file = input("Enter the path to the output file: ")
            # Implement bulk file hash check
            results = get_file_hash_report(file_path, api_key, output_file)
            print("File hash check completed.")
            print(f"Results saved to {output_file}")
        elif choice == '7':
            file_path = input(
                "Enter the path to the input file (.txt or .csv): ")
            output_file = input("Enter the path to the output file: ")
            # Implement bulk URL check
            results = get_file_url_report(file_path, api_key, output_file)
            print("URL check completed.")
            print(f"Results saved to {output_file}")
        elif choice == '8':
            file_path = input(
                "Enter the path to the input file (.txt or .csv): ")
            output_file = input("Enter the path to the output file: ")
            # Implement bulk domain check
            results = get_file_domain_report(file_path, api_key, output_file)
            print("Domain check completed.")
            print(f"Results saved to {output_file}")
        elif choice == '9':
            break
        else:
            print("Invalid choice. Please try again.")

        run_again = input("Do you want to run the script again? (yes/no) ")
        if run_again.lower() != 'yes':
            break


if __name__ == "__main__":
    main()
