'''Get all mitigated findings with only a single occurrence, listed by sandbox name'''

from collections import Counter
import api


RESOLUTION_STATUSES = ["PROPOSED", "APPROVED", "REJECTED"]


if __name__ == "__main__":
    applications = api.get_applications()
    for application in applications:
        print(f"Application Profile: {application['profile']['name']}")
        all_findings = api.get_findings(application["guid"])
        application["sandboxes"] = {sandbox["guid"]: sandbox for sandbox in api.get_sandboxes(application["guid"])}
        # application["sandboxes"][application["guid"]] = {"name": "Policy Sandbox"}
        for guid, sandbox in application["sandboxes"].items():
            all_findings.extend(api.get_findings(application["guid"], guid))

        finding_counter = Counter()
        for finding in all_findings:
            finding_counter[finding["issue_id"]] += 1

        single_occurrence_findings = sorted([k for k, v in finding_counter.items() if v == 1])
        filtered_all_findings = list(filter(lambda finding: next(iter(finding["finding_status"].values()))["resolution_status"] in RESOLUTION_STATUSES and finding["issue_id"] in single_occurrence_findings, all_findings))

        for finding in filtered_all_findings:
            sandbox_guid = list(finding["finding_status"])[0]
            sandbox_single_occurrence_findings = application["sandboxes"][sandbox_guid].get("single_occurrence_findings", [])
            sandbox_single_occurrence_findings.append(finding)
            application["sandboxes"][sandbox_guid]["single_occurrence_findings"] = sandbox_single_occurrence_findings

        for sandbox in application["sandboxes"].values():
            if "single_occurrence_findings" in sandbox and len(sandbox["single_occurrence_findings"]) != 0:
                print(f"\tSandbox: {sandbox['name']}")
                print(f"\t\tSingle occurrence mitigated findings count: {len(sandbox['single_occurrence_findings'])}")
 