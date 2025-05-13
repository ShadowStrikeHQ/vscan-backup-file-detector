#!/usr/bin/env python3

import argparse
import logging
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# List of common backup file extensions to check for
BACKUP_EXTENSIONS = ['.bak', '.swp', '~', '.old', '.tmp', '.backup', '.orig']

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="vscan-backup-file-detector: Identifies common backup file extensions that may contain sensitive information.")
    parser.add_argument("url", help="The URL to scan (e.g., http://example.com)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging)")
    parser.add_argument("-o", "--output", help="Output file to save results to")
    parser.add_argument("-e", "--extensions", nargs='+', help="Specify custom backup file extensions (space-separated). Overrides default extensions.")
    return parser.parse_args()

def is_valid_url(url):
    """
    Validates if the given URL is properly formatted.
    Returns True if valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def check_backup_files(url, extensions):
    """
    Checks for the existence of backup files based on common extensions.

    Args:
        url (str): The base URL to scan.
        extensions (list): A list of file extensions to check.

    Returns:
        list: A list of URLs that resulted in a 200 status code.
    """
    found_files = []
    for ext in extensions:
        backup_url = url + ext
        try:
            logging.debug(f"Checking for: {backup_url}")
            response = requests.get(backup_url, allow_redirects=True)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            if response.status_code == 200:
                logging.info(f"Found backup file: {backup_url}")
                found_files.append(backup_url)
            else:
                logging.debug(f"Status code {response.status_code} for {backup_url}")

        except requests.exceptions.RequestException as e:
            logging.debug(f"Error checking {backup_url}: {e}")  # Log the error, but continue checking

    return found_files

def save_results(filename, results):
    """
    Saves the scan results to a file.

    Args:
        filename (str): The name of the file to save to.
        results (list): A list of URLs that were found.
    """
    try:
        with open(filename, "w") as f:
            for result in results:
                f.write(result + "\n")
        logging.info(f"Results saved to: {filename}")
    except IOError as e:
        logging.error(f"Error saving results to file: {e}")

def main():
    """
    Main function to orchestrate the backup file detection process.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    url = args.url

    if not is_valid_url(url):
        logging.error("Invalid URL provided. Please provide a valid URL including scheme (e.g., http://example.com).")
        sys.exit(1)

    logging.info(f"Scanning URL: {url}")

    # Determine which extensions to use
    extensions_to_use = args.extensions if args.extensions else BACKUP_EXTENSIONS

    found_files = check_backup_files(url, extensions_to_use)

    if found_files:
        print("Possible backup files found:")
        for file in found_files:
            print(file)

        if args.output:
            save_results(args.output, found_files)
    else:
        print("No backup files found.")


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Scan a website for default backup extensions:
#    python vscan-backup-file-detector.py http://example.com
#
# 2. Scan a website with verbose output:
#    python vscan-backup-file-detector.py -v http://example.com
#
# 3. Scan a website and save the results to a file:
#    python vscan-backup-file-detector.py -o results.txt http://example.com
#
# 4. Scan a website with custom extensions:
#    python vscan-backup-file-detector.py -e .bak .old .config http://example.com