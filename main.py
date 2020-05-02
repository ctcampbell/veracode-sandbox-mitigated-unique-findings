'''List which sandboxes have mitigated findings that are not found in any other sandbox'''

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import api


RESOLUTION_STATUSES = ["PROPOSED", "APPROVED", "REJECTED"]


if __name__ == "__main__":
    def write_message(message):
        '''Write to file or console'''
        try:
            output_file.write(message + "\n")
        except NameError:
            print(message)

    def process_application(application):
        '''Return application if it contains mitigated unique findings'''
        # Get all findings
        all_findings = api.get_findings(application["guid"])
        sandboxes = api.get_sandboxes(application["guid"])
        application["sandboxes"] = {}
        for sandbox in sandboxes:
            sandbox["single_occurrence_findings"] = []
            application["sandboxes"][sandbox["guid"]] = sandbox
            all_findings.extend(api.get_findings(application["guid"], sandbox["guid"]))

        # Count finding occurrences
        finding_counter = Counter()
        for finding in all_findings:
            finding_counter[finding["issue_id"]] += 1
        single_occurrence_findings = [k for k, v in finding_counter.items() if v == 1]

        # Determine if finding is mitigated and unique to a sandbox
        def finding_is_unique(finding):
            '''Return True if finding is mitigated and only found in one sandbox'''
            finding_sandbox_guid = list(finding["finding_status"])[0]
            finding_status = list(finding["finding_status"].values())[0]
            finding_resolution_status = finding_status["resolution_status"]
            return (finding_sandbox_guid != application["guid"] and
                    finding_resolution_status in RESOLUTION_STATUSES and
                    finding["issue_id"] in single_occurrence_findings)

        filtered_all_findings = list(filter(finding_is_unique, all_findings))
        if len(filtered_all_findings) != 0:
            for finding in filtered_all_findings:
                sandbox_guid = list(finding["finding_status"])[0]
                application["sandboxes"][sandbox_guid]["single_occurrence_findings"].append(finding)
            return application

    def write_result(application):
        '''Output results'''
        write_message(f"\rApplication Profile: {application['profile']['name']}")
        for sandbox in application["sandboxes"].values():
            if len(sandbox["single_occurrence_findings"]) != 0:
                write_message(f"\tSandbox: {sandbox['name']}")
                write_message(f"\t\tSingle occurrence mitigated findings count: {len(sandbox['single_occurrence_findings'])}")

    if len(sys.argv) == 2:
         output_file = open(sys.argv[1], "w")

    pool = ThreadPoolExecutor(5)
    futures = []
    counter = 0

    applications = api.get_applications()
    for application in applications:
        futures.append(pool.submit(process_application, application))

    for future in as_completed(futures):
        application = future.result()
        if application is not None:
            write_result(application)
        counter += 1
        print(f"\rApplications processed: {counter}", end="")

    try:
        output_file.close()
    except NameError:
        pass
    print()
