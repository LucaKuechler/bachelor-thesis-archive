# Bachelor Thesis Archive

## Content

1. [Scripts &#9881;](#scripts)
2. [Data &#128190;](#data)
3. [Evaluation &#128300;](#evaluation)

&nbsp;
&nbsp;
## Scripts
In the **scripts/** folder of this repository, you'll find a collection of
scripts utilized in my bachelor thesis. These scripts are designed to
facilitate various tasks and analyses needed for the conducted research. The
following programs are stored within this directory:

- **consistency-checker.py:** Evaluate the detection rate for a specified malware sample across the three SIEM systems.
- **consistency-tracker.py:** Track the malware samples execution time.
- **consistency-malware.py:** Create the malware sample set by randomly selecting them from a given pool.
- **consistency-rules.py:** Convert the given Sigma rules for each of the three SIEM systems.

&nbsp;
&nbsp;
## Data
In the **data/** folder of this repository, you'll find a collection of all
data artifacts generated throughout conducting the experiment. This directory stores the
following artifacts:

- **time.json:** Stores the execution timeframe for each malware sample.
- **rules.json:** Contains the final 78 converted Sigma rules for each of the three SIEM systems.
- **all-rules.json:** Contains all converted Sigma rules for each of the three SIEM systems.
- **data.json:** Shows the detection rate of a rule per malware sample.
- **malware.json:** Stores each piece of malware by hash and signature.

&nbsp;
&nbsp;
## Evaluation
In the **evaluation/** folder of this repository, you'll find the procedure
detailing how the collected data has been evaluated. This section contains all
necessary algorithms used to extract insights from the data and generate
statistical graphics for analysis.
