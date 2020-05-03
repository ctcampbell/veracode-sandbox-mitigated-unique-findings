## Purpose

This script will pull all open findings across all sandboxes for all applications and calculate which mitigated (proposed, accepted, or rejected) findings only exist in a single sandbox, and therefore may be deleted when the sandbox is deleted.

## Requirements

* Veracode API credentials
* Findings API enabled on Veracode organisation account (not public yet, speak to your Veracode contact if required)

## Setup

    pip install -r requirements.txt

## Usage

    python main.py <csv output filename>
    
## Example CSV output

    Application,Sandbox,Unique Mitigated Finding Count
    verademo-java,aws-codebuild,6
