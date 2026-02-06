import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup

BASE_URL = "https://learn.microsoft.com/en-us/azure/azure-monitor"
OUTPUT_FILE = "sigma/pipelines/azuremonitor/tables.py"


def get_request(url: str) -> requests.Response:
    """
    Sends a GET request to the specified URL and returns the response.

    :param url: The URL to send the GET request to.
    :return: The response from the GET request.
    """
    response = requests.get(url)
    response.raise_for_status()

    return response


def extract_table_hrefs(items: List[dict]) -> List[str]:
    """Extracts hrefs for Azure Monitor tables from the JSON data."""
    for item in items:
        if item.get("toc_title") == "Reference":
            return find_tables_section(item.get("children", []))
    return []


from urllib.parse import urljoin

def extract_links_from_page(url: str) -> List[str]:
    """Extracts table links from a documentation page."""
    try:
        response = get_request(url)
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch {url}: {e}")
        return []

    soup = BeautifulSoup(response.content, "html.parser")
    links = []
    
    all_links = soup.find_all("a", href=True)
    
    # Look for all links that look like table references
    # Usually in a table or list
    for a in all_links:
        href = a["href"]
        # Filter for table links (usually contain /tables/)
        if "tables/" in href and "tables-index" not in href:
            full_href = urljoin(url, href)
            links.append(full_href)
            
    return links


def find_tables_section(items: List[dict]) -> List[str]:
    """Finds the Tables section and returns the relevant hrefs."""
    for item in items:
        title = item.get("toc_title")
        if title == "Tables" or title == "Logs tables reference":
            children = item.get("children", [])
            if children:
                return collect_table_hrefs(children)
            elif "href" in item:
                # If no children in TOC, scrape the index page
                href = item["href"]
                if href.startswith("/"):
                    full_url = f"https://learn.microsoft.com/en-us{href}"
                else:
                    full_url = f"{BASE_URL}/{href}"
                print(f"Scraping links from index page: {full_url}")
                return extract_links_from_page(full_url)
        
        if title == "Azure Monitor Logs":
            # Recursively search in Azure Monitor Logs
            return find_tables_section(item.get("children", []))
            
    return []


def collect_table_hrefs(items: List[dict]) -> List[str]:
    """Recursively collects hrefs from the Tables section."""
    hrefs = []
    for item in items:
        if "href" in item:
            hrefs.append(item["href"])
        if "children" in item:
            hrefs.extend(collect_table_hrefs(item["children"]))
    return hrefs


def get_azure_monitor_tables() -> List[str]:
    """Fetches the Azure Monitor table hrefs from documentation."""
    url = f"{BASE_URL}/toc.json"
    print(f"Fetching TOC from {url}...")
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()
    return extract_table_hrefs(data.get("items", []))


def extract_table_name_and_fields(url: str) -> Dict[str, List[Dict[str, str]]]:
    """
    Extracts the table name and field schema from an Azure Monitor table page.

    :param url: Full URL of the schema page.
    :return: A dictionary with the table name and a list of field schemas.
    """
    try:
        response = get_request(url)
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch {url}: {e}")
        return None

    soup = BeautifulSoup(response.content, "html.parser")

    table_name = extract_table_name(soup, url)
    if table_name is None:
        print(f"No table name found for {url}. Skipping...")
        return None

    field_data = extract_field_data(soup)
    if not field_data:
        print(f"No field data found for {table_name} ({url}). Skipping...")
        return None

    return {table_name: field_data}


def extract_table_name(soup: BeautifulSoup, url: str) -> Optional[str]:
    """
    Extracts the table name from the BeautifulSoup object or URL.

    :param soup: BeautifulSoup object of the schema page.
    :param url: URL of the page.
    :return: The extracted table name or None if not found.
    """
    # Method 1: Title of the page usually contains the table name
    title = soup.find("h1")
    if title:
        # Titles are often "TableName table" or just "TableName"
        text = title.get_text().strip()
        # Remove " table" suffix if present
        if text.lower().endswith(" table"):
            return text[:-6].strip()
        # Sometimes the title is "Azure Monitor Logs reference - TableName"
        if " - " in text:
            return text.split(" - ")[-1].strip()
        return text

    # Method 2: Extract from URL
    # URL format: .../reference/tables/tablename
    match = re.search(r"/tables/([^/?#]+)", url)
    if match:
        return match.group(1)

    return None


def extract_field_data(soup: BeautifulSoup) -> Dict[str, Dict[str, str]]:
    """
    Extracts field data from an Azure Monitor table page.

    :param soup: BeautifulSoup object of the schema page.
    :return: A dictionary with the field name and type info.
    """
    field_data = {}

    # Look for the "Columns" section
    # Usually there is a table under a "Columns" header
    # But sometimes it's just the first table
    
    tables = soup.find_all("table")
    for table in tables:
        headers = [th.get_text().strip() for th in table.find_all("th")]
        # Standard headers: Column, Type, Description
        if "Column" in headers and "Type" in headers:
            # Parse each row
            for row in table.find_all("tr")[1:]:  # Skip header
                cols = [td.get_text().strip() for td in row.find_all("td")]
                if len(cols) >= 2:
                    field_name = cols[0]
                    data_type = cols[1]
                    description = cols[2] if len(cols) > 2 else ""
                    
                    field_data[field_name] = {
                        "data_type": data_type,
                        "description": description
                    }
            # If we found a valid table, we can stop (usually only one main schema table)
            # However, some pages might have multiple tables. 
            # For now, let's assume the first matching table is the one.
            if field_data:
                return field_data

    return field_data


def write_schema(output_file: str, schema_tables: Dict[str, dict]):
    """Write the schema tables to a Python file."""
    with open(output_file, "w") as f:
        f.write("# This file is auto-generated. Do not edit manually.\n")
        f.write(f"# Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")
        f.write("AZURE_MONITOR_TABLES = {\n")
        for table, fields in sorted(schema_tables.items()):
            f.write(f'    "{table}": {{\n')
            for field, info in sorted(fields.items()):
                f.write(
                    f'        "{field.strip("`")}": {{"data_type": "{info["data_type"].strip("`")}", "description": {repr(info["description"])}}},\n'
                )
            f.write("    },\n")
        f.write("}\n")


def process_azure_monitor_schemas() -> Dict[str, dict]:
    """Processes all Azure Monitor schemas and extracts table names and field schemas."""
    hrefs = get_azure_monitor_tables()
    schema_data = {}

    print(f"Found {len(hrefs)} potential table links.")

    for href in hrefs:
        # Some hrefs might be relative or absolute
        if href.startswith("http"):
            full_url = href
        elif href.startswith("/"):
            # Root relative URL
            full_url = f"https://learn.microsoft.com/en-us{href}"
        else:
            # Relative to BASE_URL (which is .../azure-monitor)
            full_url = f"{BASE_URL}/{href}"
        
        # Filter for table pages only (usually contain /tables/)
        if "/tables/" not in full_url:
            continue

        print(f"Processing {full_url}...")
        if schema_info := extract_table_name_and_fields(full_url):
            schema_data.update(schema_info)

    return schema_data


if __name__ == "__main__":
    schema_data = process_azure_monitor_schemas()
    if schema_data:
        write_schema(OUTPUT_FILE, schema_data)
        print(f"Schema written to {OUTPUT_FILE}")
    else:
        print("No schema data found.")
