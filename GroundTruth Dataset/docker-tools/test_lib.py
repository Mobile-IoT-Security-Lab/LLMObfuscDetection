from time import time
from random import randint, random
import traceback
import requests
import json
import os


def get_app_scans(server_url, apikey):
    scans = {}
    i = 1
    try:
        while True:
            response = requests.get(
                f"{server_url}/api/v1/scans?page={i}&page_size=100",
                headers={"AUTHORIZATION": apikey},
            )
            if response.status_code == 200:
                response_json = json.loads(response.content.decode())
                for scan in response_json["content"]:
                    scans[scan["FILE_NAME"]] = scan["MD5"]
            else:
                break
            i += 1
    except:
        print(traceback.format_exc())
    print(scans)
    return scans


def delete_scans(server_url, apikey):
    scans = get_app_scans(server_url, apikey)
    for app in scans:
        requests.post(
            f"{server_url}/api/v1/delete_scan",
            data={"hash": scans[app]},
            headers={"AUTHORIZATION": apikey},
        )


def upload_app(server_url, filename, apikey):
    try:
        mimes = {
            ".apk": "application/octet-stream",
            ".ipa": "application/octet-stream",
            ".appx": "application/octet-stream",
            ".zip": "application/zip",
        }
        ext = os.path.splitext(filename)[-1]
        if ext in mimes:
            files = {
                "file": (filename, open(filename, "rb"), mimes[ext], {"Expires": "0"})
            }
            response = requests.post(
                server_url + "/api/v1/upload",
                files=files,
                headers={"AUTHORIZATION": apikey},
            )

            if response.status_code == 200 and "hash" in response.json():
                uploaded = []
                uploaded.append(response.json())
                return uploaded
            else:
                return []
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        return []


def start_analysis(server_url, upl, apikey, index):
    # Salviamo i file di log dei tempi direttamente in /results così non li perdi
    log_file_path = f"/results/time_apps_mobsf.log"

    with open(log_file_path, "a") as f:
        f.write(
            "app_index "
            + str(index)
            + " ----> start analysis: "
            + upl["file_name"]
            + " "
            + str(int(time()))
            + "\n"
        )

    requests.post(
        server_url + "/api/v1/scan", data=upl, headers={"AUTHORIZATION": apikey}
    )

    with open(log_file_path, "a") as f:
        f.write(
            "app_index "
            + str(index)
            + " ----> stop analysis: "
            + upl["file_name"]
            + " "
            + str(int(time()))
            + "\n"
        )
