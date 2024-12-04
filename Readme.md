# Log File Analyzer

This Python script analyzes server log files to extract valuable insights about server activity, including IP request counts, the most accessed endpoint, and suspicious activity detection based on failed login attempts.

## Features

- **Counts Requests per IP**: Tracks how many requests each IP address has made.
- **Identifies the Most Accessed Endpoint**: Finds the most frequently accessed endpoint in the logs.
- **Detects Suspicious Activity**: Detects IP addresses with a high number of failed login attempts (default threshold: 10).
- **Outputs Results to Terminal**: Displays the results of the analysis in the terminal.
- **Saves Results to CSV**: Saves the analysis results to a CSV file (`log_analysis_results.csv`).

## Prerequisites

- Python 3.x (preferably 3.6+)
- Basic knowledge of Python and log file format

## Setup and Installation

1. **Clone this repository** or **download** the Python script to your local machine.

```bash
git clone <repository_url>
cd <directory_name>
```

2. **Install required dependencies** (if any). If not already installed, you may need to install the required libraries (like `re` and `csv`, which are part of Python's standard library).  
No external dependencies are required for this script.

## Running the Script

1. Place your log file (e.g., `sample.log`) in the same directory as the script.
2. Run the script using the following command:

```bash
python log_analysis.py
```

3. The script will:
   - Parse the log file.
   - Print the results in the terminal:
     - IP addresses and their request counts.
     - Most frequently accessed endpoint.
     - Suspicious IP addresses based on failed login attempts.
   - Save the results to a CSV file named `log_analysis_results.csv`.

## Example Output (Terminal)

```bash
IP Address           Request Count
203.0.113.5          8
198.51.100.23        8
192.168.1.1          7
10.0.0.2             6
192.168.1.100        5

Most Frequently Accessed Endpoint: /login (Accessed 13 times)
No suspicious activity detected.
```

The results will also be saved in `log_analysis_results.csv` as follows:

```csv
IP Address,Request Count
192.168.1.1,7
203.0.113.5,8
10.0.0.2,6
198.51.100.23,8
192.168.1.100,5
Most Frequently Accessed Endpoint,/login (Accessed 13 times)
Suspicious Activity Detected,Failed Login Count

```