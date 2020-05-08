'''List which sandboxes have mitigated findings that are not found in any other sandbox'''

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import api


RESOLUTION_STATUSES = ["PROPOSED", "APPROVED", "REJECTED"]


def process_application(application):
    '''Return application if it contains mitigated unique findings'''
    # Get all findings
    all_findings = api.get_findings(application["guid"])
    sandboxes = api.get_sandboxes(application["guid"])
    application["sandboxes"] = {}
    for sandbox in sandboxes:
        sandbox["unique_findings"] = []
        application["sandboxes"][sandbox["guid"]] = sandbox
        all_findings.extend(api.get_findings(application["guid"], sandbox["guid"]))

    mitigated_findings = [x for x in all_findings if x["finding_status"]["resolution_status"] in RESOLUTION_STATUSES]

    # Find single occurence mitigated findings
    finding_counter = Counter()
    for finding in mitigated_findings:
        finding_counter[finding["issue_id"]] += 1
    unique_mitigated_findings = [x for x in mitigated_findings if (finding_counter[x["issue_id"]] == 1 and
                                                                   x["context_guid"] != application["guid"])]

    if len(unique_mitigated_findings) != 0:
        for finding in unique_mitigated_findings:
            application["sandboxes"][finding["context_guid"]]["unique_findings"].append(finding)
        return application

    return None


def main():
    '''Main method'''
    pool = ThreadPoolExecutor(10)

    try:
        if len(sys.argv) != 2:
            print("No CSV output file name provided. Usage: main.py <filename>")
            sys.exit(1)

        with open(sys.argv[1], "w", buffering=1) as output_file:
            output_file.write("Application,Sandbox,Expiry Date,Unique Mitigated Finding Count\n")
            counter = 0
            applications = api.get_applications()
            futures = [pool.submit(process_application, x) for x in applications]
            for future in as_completed(futures):
                application = future.result()
                if application is not None:
                    sandbox_xml = api.get_sandbox_list(application["id"])
                    sandbox_dict = {sandbox.get("sandbox_id"): sandbox.get("expires") for sandbox in sandbox_xml}
                    for sandbox in application["sandboxes"].values():
                        if len(sandbox["unique_findings"]) != 0:
                            app_name = application['profile']['name']
                            sandbox_expiry = sandbox_dict[str(sandbox['id'])]
                            output_file.write(f"{app_name},{sandbox['name']},{sandbox_expiry},{len(sandbox['unique_findings'])}\n")
                counter += 1
                print(f"\rApplications processed: {counter}", end="")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
    print()
