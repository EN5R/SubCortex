
# SubCortex

SubCortex is a fast and effective tool designed for discovering valid subdomains for websites. It performs passive subdomain enumeration by collecting data from various sources.


## Features

- **Fast and Powerful:** Quickly gathers subdomain data from various APIs.
- **Advanced Retry Mechanism:** Automatically retries commands in case of any errors.
- **Modular Architecture:** Easily extensible with support for different data sources.
- **Comprehensive Support:** Customizable through various command-line flags.


## Screenshots

![App Screenshot](https://raw.githubusercontent.com/EN5R/SubCortex/main/SubCortex.png)


## Usage

You can view the usage instructions with the following command:

```bash
  python3.12 subcortex.py -h
```

## Examples

To collect subdomains:

```bash
  python3.12 subcortex.py -d example.com
```
## Installation

SubCortex can be easily installed along with its required libraries as follows:

```bash
  pip3.12 install -r requirements.txt
```
    
## Running

You can run SubCortex with the following command:

```bash
  python3.12 subcortex.py -d example.com
```

## Important Note

Before running the Python file or if you encounter the "Your VirusTotal API key is missing." error, please edit the `subcortex.py` file by following these steps:

1. Open the `subcortex.py` file.
2. Locate the following line:
   ```python
   VT_API_KEY = 'your_virustotal_api_key_here' 
   ```
3. Replace 'your_virustotal_api_key_here' with your actual VirusTotal API key.
4. Save the file and try running the program again.


## About the Project

SubCortex collects its resources through APIs. Key sources used for gathering subdomains include:

- **Traceninja:** TraceNinja is a subdomain enumeration tool. [**TraceNinja's LINK**](https://github.com/mohdh34m/TraceNinja)

- **Subfinder:** Discovers subdomains from passive sources. [**Subfinder LINK**](https://github.com/projectdiscovery/subfinder)

- **Assetfinder:** Finds subdomains for a specified domain. [**Assetfinder LINK**](https://github.com/projectdiscovery/subfinder)

- **VirusTotal:** VirusTotal provides information about subdomains by analyzing domain records and DNS information through its public API. [**VirusTotal LINK**](https://www.virustotal.com/gui/my-apikey)

## 🔗 Links
[![portfolio](https://img.shields.io/badge/my_portfolio-000?style=for-the-badge&logo=ko-fi&logoColor=white)](https://github.com/EN5R/)
[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=000000)](https://www.buymeacoffee.com/EN5R)
[![Join Telegram](https://img.shields.io/badge/Join%20Telegram-0088cc?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/+K3G9CJmZfShmOGI0)

## License

This project is licensed under the [MIT License.](https://raw.githubusercontent.com/EN5R/SubCortex/main/LICENSE)

Feel free to modify or add any information as needed! If there's anything more you'd like to include, just let me know!
