import json
import math
import time
from itertools import count
from shodan import Shodan
import sys
import argparse

print(
    """
    ,-:` \;',`'-,
  .'-;_,;  ':-;_,'.
 /;   '/    ,  _`.-\
| '`. (`     /` ` \`|
|:.  `\`-.   \_   / |
|     (   `,  .`\ ;'|
 \     | .'     `-'/
  `.   ;/        .'
jgs `'-._____.
"""
)


def get_shodan():
    with open(
        "shodata.json", "r"
    ) as string:
        jsondata = json.load(string)

    more_super_dict = {"nodes": [], "links": []}

    asset_id = 0

    with open("shomap_data1.json", "w+") as f:
        success = 0
        while success == 0:
            try:
                results = jsondata
                success = 1
            except Exception as e:
                time.sleep(5)
                print("Failed, sleeping for 5 sec..." + str(e))

                # print('[!] Problem with Shodan API ' + str(e))

        for c, i in enumerate(results["matches"]):
            try:
                super_dict = {
                    "id": asset_id,
                    "fake": 0,
                    "asn": i["asn"],
                    "port": i["port"],
                    "hostnames": i["hostnames"],
                    "city": i["location"]["city"],
                    "lat": i["location"]["latitude"],
                    "lon": i["location"]["longitude"],
                    "country": i["location"]["country_name"],
                    "domains": i["domains"],
                    "title": "",
                    "common_name": "",
                    "ip": "",
                    "organization": "",
                    "vulns": [],
                    "org": i["org"],
                }

                asset_id = asset_id + 1

                if "ssl" in i:
                    try:
                        super_dict["common_name"] = i["ssl"]["cert"]["subject"]["CN"]
                        super_dict["organization"] = i["ssl"]["cert"]["subject"]["O"]
                    except:
                        pass

                if "vulns" in i:
                    for vuln in i["vulns"]:
                        super_dict["vulns"].append(vuln)

                if "http" in i:
                    super_dict["title"] = i["http"]["title"]

                super_dict["ip"] = i["ip_str"]

                more_super_dict["nodes"].append(super_dict)
            except:
                break

        rsult = json.dumps(more_super_dict, indent=4)
        f.write(rsult)
        print("[i] File has been saved as shomap_data1.json")

        print("[*] Preparing visualization")
        prepare_viz("shomap_data1.json")


def prepare_viz(path):
    nodes_set = set()
    help = {}
    categories = ["port", "org", "country", "city"]
    for category in categories:
        print("[*] Grouping by " + category)
        with open(path, "r+") as f:
            json_f = json.load(f)

            for i in json_f["nodes"]:
                if i["port"] == 0:
                    break
                if i[category] not in help.keys():
                    nodes_set.add(i[category])
                    last_id = json_f["nodes"][-1]["id"]
                    help.update({i[category]: last_id + 1})
                    json_f["nodes"].append(
                        {
                            "id": last_id + 1,
                            "fake": 1,
                            "country": i[category],
                            "port": 0,
                            "city": "",
                            "org": "",
                        }
                    )
                    json_f["links"].append(
                        {"source": i["id"], "target": help[i[category]], "value": 1}
                    )

                else:
                    json_f["links"].append(
                        {"source": i["id"], "target": help[i[category]], "value": 1}
                    )

            f = open("shomap_data_" + category + ".json", "w")
            f.write(json.dumps(json_f, indent=4))
            f.close()
    # print()


print("[*] Gathering data from Shodan")
get_shodan()

## in js file, paths are hardcoded,
## everytime it runs, data will be overwritten
