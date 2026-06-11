import os
import requests
from rich import print
from test_lib import get_app_scans, upload_app, start_analysis
import argparse

parser = argparse.ArgumentParser(description="Process and analyze apps.")
parser.add_argument("app", help="The working directory path")
args = parser.parse_args()

app = args.app
api_key = "7ab3e77bf55ea5a30333335a3de1021e388677c3fa585a8923c0bd39df0bde45"
dump_folder = "/results/MobSF" # Path aggiornato
os.makedirs(dump_folder, exist_ok=True)

app_uploaded = upload_app("http://mobsf:8000", app, api_key) # Hostname dockerizzato

if app_uploaded and len(app_uploaded) == 1:
    start_analysis("http://mobsf:8000", app_uploaded[0], api_key, str(app))

scans = get_app_scans("http://mobsf:8000", api_key)

response = requests.post(
    "http://mobsf:8000/api/v1/report_json",
    data={"hash": scans.get(os.path.basename(app), "")},
    headers={"AUTHORIZATION": api_key}
)

if response.status_code == 200:
    response_content = response.content.decode()
    with open(os.path.join(dump_folder, f'{os.path.basename(app).replace(".", "_")}.json'), "w") as f:
        f.write(response_content)
else:
    print(f"[red]Error: Failed to retrieve report for {app}. Status code: {response.status_code}")
