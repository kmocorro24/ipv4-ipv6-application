import requests
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def get_ip_info(ip_version="ipv4"):
    """
    Fetch IP information from ipapi.co API.
    Fallback: Uses ipinfo.io if ipapi.co rate limits or fails.
    """
    try:
        url = f"https://ipapi.co/{ip_version}/json/"
        response = requests.get(url, timeout=5)

        # Success from ipapi.co
        if response.status_code == 200:
            data = response.json()
            data["source"] = "ipapi.co"
            return {
                "Source": data["source"],
                "IP Version": ip_version.upper(),
                "IP Address": data.get("ip", "N/A"),
                "City": data.get("city", "N/A"),
                "Region": data.get("region", "N/A"),
                "Country": data.get("country_name", "N/A"),
                "Country Code": data.get("country_code", "N/A"),
                "ISP": data.get("org", "N/A"),
                "ASN": data.get("asn", "N/A"),
            }

        # If rate limit reached, use fallback
        elif response.status_code == 429:
            print(Fore.YELLOW + f"Rate limit reached for {ip_version}. Trying fallback API...")
            fallback_url = "https://ipinfo.io/json"
            fb_response = requests.get(fallback_url, timeout=5)
            if fb_response.status_code == 200:
                fb_data = fb_response.json()
                fb_data["source"] = "ipinfo.io"
                return {
                    "Source": fb_data["source"],
                    "IP Version": ip_version.upper(),
                    "IP Address": fb_data.get("ip", "N/A"),
                    "City": fb_data.get("city", "N/A"),
                    "Region": fb_data.get("region", "N/A"),
                    "Country": fb_data.get("country", "N/A"),
                    "ISP": fb_data.get("org", "N/A"),
                    "ASN": fb_data.get("asn", "N/A"),
                }
            else:
                print(Fore.RED + f"Fallback API also failed. Status code: {fb_response.status_code}")
                return None
        else:
            print(Fore.RED + f"Error: Unable to fetch {ip_version} data. Status code: {response.status_code}")
            return None

    except requests.RequestException as e:
        print(Fore.RED + f"Network error while fetching {ip_version} info: {e}")
        return None


def display_info(ip_data):
    """Format and display IP information."""
    if ip_data:
        print(Fore.CYAN + "\n" + "=" * 40)
        print(Fore.GREEN + f"{ip_data['IP Version']} Information (Source: {ip_data['Source']})")
        print(Fore.CYAN + "=" * 40)
        for key, value in ip_data.items():
            if key not in ["Source", "IP Version"]:
                print(Fore.WHITE + f"{key}: {value}")
        print(Fore.CYAN + "=" * 40 + "\n")
    else:
        print(Fore.RED + "No information available.")


def main():
    print(Fore.MAGENTA + Style.BRIGHT + "🌐 IPv4/IPv6 Address Information App\n")

    ipv4_info = get_ip_info("ipv4")
    display_info(ipv4_info)

    ipv6_info = get_ip_info("ipv6")
    display_info(ipv6_info)

    print(Fore.GREEN + "✅ Data successfully retrieved and displayed.\n")


if __name__ == "__main__":
    main()
