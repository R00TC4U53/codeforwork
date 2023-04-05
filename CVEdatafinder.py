import requests
import json

def get_cve_details(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    response = requests.get(url)

    if response.status_code == 200:
        return response.json()
    else:
        return None

def format_cve_details(cve_data):
    cve = cve_data['result']['CVE_Items'][0]
    cve_id = cve['cve']['CVE_data_meta']['ID']
    description = cve['cve']['description']['description_data'][0]['value']
    severity = cve['impact']['baseMetricV3']['cvssV3']['baseSeverity']
    score = cve['impact']['baseMetricV3']['cvssV3']['baseScore']
    attack_vector = cve['impact']['baseMetricV3']['cvssV3']['attackVector']
    published_date = cve['publishedDate']
    last_modified_date = cve['lastModifiedDate']

    confirm_remediations = []
    other_remediations = []
    for ref in cve['cve']['references']['reference_data']:
        if ref['refsource'] == 'CONFIRM':
            confirm_remediations.append(ref['url'])
        else:
            other_remediations.append(ref['url'])

    output = f"""CVE ID: {cve_id}
Description: {description}
Severity: {severity}
CVSS Score: {score}
Attack Vector: {attack_vector}
Published Date: {published_date}
Last Modified Date: {last_modified_date}
Recommended Remediations:
"""

    if confirm_remediations:
        output += "CONFIRM Remediations:\n"
        for i, url in enumerate(confirm_remediations, start=1):
            output += f"{i}. {url}\n"

    if other_remediations:
        output += "Other Remediations:\n"
        for i, url in enumerate(other_remediations, start=1):
            output += f"{i}. {url}\n"

    return output.strip()

def main():
    cve_id = input("Please enter the CVE identifier: ")
    cve_data = get_cve_details(cve_id)

    if cve_data:
        print(format_cve_details(cve_data))
    else:
        print(f"Sorry, the CVE identifier '{cve_id}' could not be found.")

if __name__ == "__main__":
    main()
